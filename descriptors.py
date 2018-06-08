import json

import single_hop
import consensus

def consume_descriptors(descriptors, flavor='microdesc', sanity=True):
    if flavor not in ['microdesc']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    whitelist = [b'onion-key', b'ntor-onion-key', b'p', b'p6', b'id']
    aliases = {'p': 'exit-policy', 'p6': 'exit-policy-ipv6', 'id': 'identity'}

    def end_of_field(line):
        if b'onion-key' == line:
            return False
        if b' ' not in line:
            return True
        keyword, _ = line.split(b' ', 1)
        return keyword not in whitelist

    fields = []
    valid = False
    while True:
        descriptors, entry = consensus.scrap(descriptors, end_of_field)
        if entry is None:
            if not valid:
                return descriptors, None
            break

        if b'onion-key' == entry:
            entry += b' '

        valid = True
        if b' ' not in entry:
            continue

        try:
            entry = str(entry, 'utf8')
        except:
            continue

        keyword, content = entry.split(' ', 1)
        if keyword == 'onion-key':
            if sanity:
                assert content == ''

            descriptors, pubkey = consensus.scrap_signature(descriptors,
                fix=b'RSA PUBLIC KEY')
            if pubkey is not None:
                content = consensus.parse_base64(str(pubkey, 'utf8'))

        if keyword == 'ntor-onion-key':
            content = consensus.parse_base64(content)

        if keyword in ['p', 'p6']:
            policy_type, portlist = content.split(' ')
            if sanity:
                assert policy_type in ['accept', 'reject']

            portlist = consensus.parse_range_once(portlist, expand=False)
            content = {'type': policy_type, 'PortList': portlist}

        if keyword == 'id':
            id_type, data = content.split(' ')
            if sanity:
                assert id_type in ['rsa1024', 'ed25519']

            content = {'type': id_type, 'data': consensus.parse_base64(data)}

        if keyword in aliases:
            keyword = aliases[keyword]

        if len(fields) == 0 or keyword in fields[-1]:
            fields.append(dict())

        fields[-1][keyword] = content
    return descriptors, fields

def jsonify(descriptors, flavor='microdesc', encode=True, sanity=True):
    fields = dict(flavor=flavor)
    if sanity:
        nbdesc = descriptors.count(b'onion-key\n-----BEGIN')

    descriptors, http = consensus.consume_http(descriptors)
    if http is not None:
        fields['http'] = http

    descriptors, entries = consume_descriptors(descriptors, flavor, sanity)
    if entries is not None:
        fields['descriptors'] = entries

    if sanity:
        assert 'descriptors' in fields
        assert len(fields['descriptors']) == nbdesc

    if encode:
        return json.dumps(fields), descriptors
    return fields, descriptors

def batch_query(items, prefix, separator='-', fixed_max_length=4096):
    # About batches:
    #    https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L3392

    query = ''
    for item in items:
        if len(item) + len(query) >= fixed_max_length:
            yield query
            query = ''

        if len(query) == 0:
            query += prefix + item
        else:
            query += separator + item

    if len(query) != 0:
        yield query

def download(state, microdesc=None, last_stream_id=0, sanity=True):
    if microdesc is None:
        state, last_stream_id, microdesc = consensus.download(state,
            flavor='microdesc', last_stream_id=last_stream_id, sanity=sanity)

        if microdesc is None:
            return state, last_stream_id, None

    if sanity:
        assert isinstance(microdesc, dict)

    digests = [router['micro-digest'] for router in microdesc['routers']]

    # retrieve descriptors via digests
    descriptors = []
    for query in batch_query(digests, '/tor/micro/d/', '-'):
        state, last_stream_id, answer = single_hop.directory_query(
            state, query, last_stream_id, sanity=sanity)

        if answer is None or len(answer) == 0:
            continue

        new_batch, remaining = jsonify(answer, encode=False)
        if sanity:
            assert new_batch is not None
            assert remaining is not None and len(remaining) == 0

        if new_batch is not None:
            descriptors += new_batch['descriptors']

    return state, last_stream_id, descriptors

if __name__ == '__main__':
    import link_protocol
    import circuit_fast
    import onion_parts
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = link_protocol.handshake(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link[1], link[0]))

    circuit = circuit_fast.create(link)
    print('Circuit {} created – Key hash: {}'.format(circuit[0],
        circuit[1].key_hash.hex()))

    # downloading descriptors
    state = onion_parts.state(link, circuit)
    state, last_stream_id, descriptors = download(state)

    print('Ready to use {} descriptors!'.format(len(descriptors)))
    for d in descriptors:
        print(' - ntor-onion-key: {}'.format(d['ntor-onion-key']))
