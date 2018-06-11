import json
import base64
import hashlib

import single_hop
import consensus

def compute_descriptor_digest(fields, descriptors, entry, flavor, sanity=True):
    """
        (details of the parser – private API)

        Plugs into our consumer to compute extra "digest" fields that expose
        the (micro-)descriptor's (micro-)digest, enabling us to easily fetch
        associated entries within a consensus.

        :param list fields: "fields" accumulator used by the consumer
        :param bytes descriptors: remaining input to be parsed by the consumer
        :param bytes entry: last line being parsed by the consumer
        :param str flavor: flavor used by the consumer
        :param bool sanity: enable extra sanity checks (default: True)

        :returns: updated (or not) fields accumulator
    """

    if flavor == 'unflavored':
        digest_name = 'digest'
        pivot_field = 'router'
        starts_hash = b'router '
        ends_hasher = b'router-signature'
        base_offset = 1
        shalgorithm = hashlib.sha1
        # https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L602
    else:
        digest_name = 'micro-digest'
        pivot_field = 'onion-key'
        starts_hash = b'onion-key'
        ends_hasher = b'id '
        base_offset = 7 + 1 + 43 + 1 # 'ed25519 [identity]\n'
        shalgorithm = hashlib.sha256
        # https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L3202

    # 1. check if we're starting to parse a fresh entry before computing digest
    if digest_name not in fields[-1] or (
        entry.startswith(starts_hash) and pivot_field in fields[-1]):
        if pivot_field in fields[-1]:
            fields.append(dict())

        # 1.5 (extra sanity checks: double-check that we have what we need)
        if sanity:
            assert entry.startswith(starts_hash)
            assert ends_hasher in descriptors

        try:
            # 2. compute the offset to the ends what goes into the hash
            sigoffset = descriptors.index(ends_hasher)
            sigoffset += len(ends_hasher) + base_offset

            # 3. rebuild the original (including its first line being parsed)
            full_desc = entry + b'\n' + descriptors[:sigoffset]

            # 4. compute the base64-encoded hash with the right algorithm
            digest = base64.b64encode(shalgorithm(full_desc).digest())

            # 5. strips the trailing '=' as specified
            fields[-1][digest_name] = str(digest.rstrip(b'='), 'utf8')
        except ValueError:
            pass

        if sanity:
            assert digest_name in fields[-1]

    return fields

def consume_descriptors(descriptors, flavor='microdesc', sanity=True):
    if flavor not in ['microdesc', 'unflavored']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    if flavor == 'microdesc':
        whitelist = [b'onion-key', b'ntor-onion-key', b'p', b'p6', b'id']
    else:
        whitelist = [b'router', b'identity-ed25519', b'master-key-ed25519',
            b'platform', b'proto', b'published', b'fingerprint', b'uptime',
            b'bandwidth', b'extra-info-digest', b'qkk', b'caches-extra-info',
            b'onion-key', b'signing-key', b'onion-key-crosscert',
            b'ntor-onion-key-crosscert', b'hidden-service-dir', b'contact',
            b'ntor-onion-key', b'reject', b'accept', b'tunnelled-dir-server',
            b'router-sig-ed25519', b'router-signature', b'ipv6-policy',
            b'family']
    aliases = {'p': 'policy', 'p6': 'ipv6-policy', 'id': 'identity'}

    def end_of_field(line):
        if b' ' not in line:
            line += b' '
        keyword, _ = line.split(b' ', 1)
        return keyword not in whitelist

    fields = [dict()]
    valid = False
    while True:
        descriptors, entry = consensus.scrap(descriptors, end_of_field)
        if entry is None:
            if not valid:
                return descriptors, None
            break
        fields = compute_descriptor_digest(fields, descriptors, entry, flavor,
            sanity)

        valid = True
        if b' ' not in entry:
            entry += b' '

        try:
            entry = str(entry, 'utf8')
        except:
            continue

        keyword, content = entry.split(' ', 1)
        if keyword == 'router':
            nick, address, orport, socksport, dirport = content.split(' ', 4)
            content = dict(
                nickname=nick,
                address=address,
                orport=int(orport),
                socksport=int(socksport),
                dirport=int(dirport))

        if keyword in ['platform', 'contact']:
            pass # nothing to process

        if keyword in ['reject', 'accept']:
            base = dict(type='exitpattern')
            if 'policy' in fields[-1]:
                base = fields[-1]['policy']
            if sanity:
                assert base['type'] == 'exitpattern'
            if 'rules' not in base:
                base['rules'] = []

            base['rules'].append(dict(type=keyword, pattern=content))
            fields[-1]['policy'] = base
            continue

        if keyword == 'or-address':
            base = []
            if 'or-address' in fields[-1]:
                base = fields[-1]['or-address']

            address, port, guess = consensus.parse_address(content, sanity)
            content = [{'ip': address, 'port': port, 'type': guess}]
            if len(base) > 0:
                content[0]['ignored'] = True

            base += content
            fields[-1]['or-address'] = base
            continue

        if keyword == 'family':
            content = content.split(' ')

        if keyword == 'proto':
            content = consensus.parse_ranges(content)

        if keyword == 'published':
            date, time, when = consensus.parse_time(content)
            content = dict(date=date, time=time, stamp=when.timestamp())

        if keyword == 'fingerprint':
            content = consensus.parse_fingerprint(content, sanity)

        if keyword == 'uptime':
            content = int(content)

        if keyword == 'bandwidth':
            avg, burst, observed = content.split(' ', 2)
            content = dict(
                avg=int(avg), burst=int(burst), observed=int(observed))

        if keyword == 'extra-info-digest':
            if ' ' in content:
                sha1, sha256 = content.split(' ', 1)
                sha256 = consensus.parse_base64(sha256, sanity)
                content = dict(sha1=sha1, sha256=sha256)
            else:
                content = dict(sha1=content)

        if keyword in ['caches-extra-info', 'hidden-service-dir',
            'tunnelled-dir-server']:
            content = True

        if keyword in ['onion-key', 'signing-key']:
            if sanity:
                assert content == ''

            descriptors, pubkey = consensus.scrap_signature(descriptors,
                fix=b'RSA PUBLIC KEY')
            if pubkey is not None:
                content = consensus.parse_base64(str(pubkey, 'utf8'), sanity)

        if keyword == 'onion-key-crosscert':
            if sanity:
                assert content == ''

            descriptors, crosscrt = consensus.scrap_signature(descriptors,
                fix=b'CROSSCERT')
            if crosscrt is not None:
                content = consensus.parse_base64(str(crosscrt, 'utf8'), sanity)

        if keyword == 'ntor-onion-key-crosscert':
            bit = int(content)

            descriptors, edcert = consensus.scrap_signature(descriptors,
                fix=b'ED25519 CERT')
            if edcert is not None:
                content = consensus.parse_base64(str(edcert, 'utf8'), sanity)
            content = dict(bit=bit, cert=content)

        if keyword == 'ntor-onion-key':
            content = consensus.parse_base64(content, sanity)

        if keyword in ['p', 'p6', 'ipv6-policy']:
            policy_type, portlist = content.split(' ')
            if sanity:
                assert policy_type in ['accept', 'reject']

            portlist = consensus.parse_range_once(portlist, expand=False)
            content = {'type': policy_type, 'PortList': portlist}

        if keyword == 'id':
            id_type, data = content.split(' ')
            if sanity:
                assert id_type in ['rsa1024', 'ed25519']

            content = {'type': id_type,
                'master-key': consensus.parse_base64(data, sanity)}

        if keyword in ['router-sig-ed25519', 'router-signature']:
            base = dict()
            if 'router-signatures' in fields[-1]:
                base = fields[-1]['router-signatures']

            if keyword == 'router-sig-ed25519':
                if sanity:
                    assert 'identity' in fields[-1]
                    assert 'cert' in fields[-1]['identity']
                    assert 'router-signatures' not in fields[-1]
                base['ed25519'] = consensus.parse_base64(content, sanity)

            if keyword == 'router-signature':
                descriptors, sig = consensus.scrap_signature(descriptors,
                    fix=b'SIGNATURE')
                if sig is not None:
                    content = consensus.parse_base64(str(sig, 'utf8'), sanity)
                base['rsa'] = content

            fields[-1]['router-signatures'] = base
            continue

        if keyword in ['identity-ed25519', 'master-key-ed25519']:
            base = dict()
            if 'identity' in fields[-1]:
                base = fields[-1]['identity']

            if 'type' not in base:
                base['type'] = 'ed25519'
            elif sanity:
                assert base['type'] == 'ed25519'

            if keyword == 'identity-ed25519':
                if sanity:
                    assert 'cert' not in base

                descriptors, edcert = consensus.scrap_signature(descriptors,
                    fix=b'ED25519 CERT')
                if edcert is not None:
                    base['cert'] = consensus.parse_base64(str(edcert, 'utf8'),
                        sanity)

            if keyword == 'master-key-ed25519':
                if sanity:
                    assert 'master-key' not in base

                base['master-key'] = consensus.parse_base64(content, sanity)

            # TODO: validation if both master-key & identity are present
            fields[-1]['identity'] = base
            continue

        if keyword in aliases:
            keyword = aliases[keyword]

        if keyword in fields[-1]:
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

    if descriptors == b'\n':
        descriptors = b''
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

def download(
        state, cons=None, flavor='microdesc', last_stream_id=0, sanity=True):
    if cons is None:
        state, last_stream_id, cons = consensus.download(state,
            flavor=flavor, last_stream_id=last_stream_id, sanity=sanity)

        if cons is None:
            return state, last_stream_id, None

    if sanity:
        assert isinstance(cons, dict)

    digests = []
    if flavor == 'microdesc':
        digests = [router['micro-digest'] for router in cons['routers']]
        endpoint = '/tor/micro/d/'
        separator = '-'
    else:
        digests = [router['digest'] for router in cons['routers']]
        digests = [base64.b64decode(d + '====').hex() for d in digests]
        endpoint = '/tor/server/d/'
        separator = '+'

    # retrieve descriptors via digests
    descriptors = []
    for query in batch_query(digests, endpoint, separator):
        state, last_stream_id, answer = single_hop.directory_query(
            state, query, last_stream_id, sanity=sanity)

        if answer is None or len(answer) == 0:
            continue

        new_batch, remaining = jsonify(answer, flavor=flavor, encode=False)
        if sanity:
            assert new_batch is not None
            assert remaining is not None and len(remaining) == 0

        if new_batch is not None:
            descriptors += new_batch['descriptors']

    if sanity:
        if flavor == 'microdesc':
            obtained = [d['micro-digest'] for d in descriptors]
        else:
            obtained = [d['digest'] for d in descriptors]
            obtained = [base64.b64decode(d + '====').hex() for d in obtained]
        assert sorted(digests) == sorted(obtained)

    return state, last_stream_id, descriptors

def download_authority(state, last_stream_id=0, sanity=True):
    state, last_stream_id, answer = single_hop.directory_query(state,
        '/tor/server/authority', last_stream_id=last_stream_id, sanity=sanity)
    if answer is None or len(answer) == 0:
        return state, last_stream_id, None

    result, remain = jsonify(
        answer, flavor='unflavored', sanity=sanity, encode=False)
    if sanity:
        assert len(remain) == 0
        assert result is not None
        assert len(result['descriptors']) == 1

    return state, last_stream_id, result['descriptors'][0]

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
    state, last_stream_id, descriptors = download(state) # (microdescriptors)
    state, last_stream_id, undescriptors = download(state, flavor='unflavored')

    # matching fields of microdescriptors against unflavored one
    key_sort = lambda d: d['identity']['master-key']
    descriptors.sort(key=key_sort)
    undescriptors.sort(key=key_sort)
    for desc, udesc in zip(descriptors, undescriptors):
        for key, value in desc.items():
            if key == 'policy' and udesc[key]['type'] == 'exitpattern':
                continue # TODO: match exitpatterns against policy summary

            if key in ['micro-digest', 'digest']:
                continue # TODO: match digests against consensus

            if not isinstance(value, dict):
                assert value == udesc[key]
            else:
                for skey, svalue in value.items():
                    assert udesc[key][skey] == svalue

    print('\nReady to use {} descriptors!'.format(len(descriptors)))
    for d in descriptors:
        print(' - ntor-onion-key: {}'.format(d['ntor-onion-key']))

    # asking politely for our OR's descriptor
    state, last_stream_id, authority = download_authority(
        state, last_stream_id=last_stream_id)

    print('\nWe are connected to the following node:')
    print(' - ntor-onion-key: {}'.format(authority['ntor-onion-key']))
    print(' - identity: {} ({})'.format(
        authority['identity']['master-key'], authority['identity']['type']))
