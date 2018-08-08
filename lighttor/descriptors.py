import base64
import hashlib

import lighttor as ltor
from lighttor import consensus

def compute_descriptor_digest(fields, descriptors, entry, flavor):
    """
        (details of the parser – private API)

        Plugs into our consumer to compute extra "digest" fields that expose
        the (micro-)descriptor's (micro-)digest, enabling us to easily fetch
        associated entries within a consensus.

        :param list fields: "fields" accumulator used by the consumer
        :param bytes descriptors: remaining input to be parsed by the consumer
        :param bytes entry: last line being parsed by the consumer
        :param str flavor: flavor used by the consumer

        :returns: updated (or not) fields accumulator
    """

    if flavor == 'unflavored':
        digest_name = 'digest'
        pivot_field = 'router'
        starts_hash = b'router '
        ends_hasher = b'router-signature'
        base_offset = 1
        base_legacy = 0
        shalgorithm = hashlib.sha1
        # https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L602
    else:
        digest_name = 'micro-digest'
        pivot_field = 'onion-key'
        starts_hash = b'onion-key'
        ends_hasher = b'id '
        base_offset = 7 + 1 + 43 + 1 # 'ed25519 [identity]\n'
        base_legacy = 7 + 1 + 27 + 1 # 'rsa1024 [identity]\n'
        shalgorithm = hashlib.sha256
        # https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L3202

    # 1. check if we're starting to parse a fresh entry before computing digest
    if digest_name not in fields[-1] or (
        entry.startswith(starts_hash) and pivot_field in fields[-1]):
        if pivot_field in fields[-1]:
            fields.append(dict())

        # 1.5 (extra sanity checks: double-check that we have what we need)
        if not entry.startswith(starts_hash):
            raise RuntimeError('Expecting {} to start the payload: {}'.format(
                starts_hash, entry))
        if not ends_hasher in descriptors:
            raise RuntimeError(
                'Expecting {} within: {}'.format(ends_hasher, descriptors))

        try:
            # 2. compute the offset to the ends what goes into the hash
            sigoffset = descriptors.index(ends_hasher)

            # TODO: better support?
            sigoffset += len(ends_hasher) + base_offset
            if b'rsa1024' in descriptors[:sigoffset]:
                sigoffset -= base_offset
                sigoffset += base_legacy

            # 3. rebuild the original (including its first line being parsed)
            full_desc = entry + b'\n' + descriptors[:sigoffset]

            # 4. compute the base64-encoded hash with the right algorithm
            digest = base64.b64encode(shalgorithm(full_desc).digest())

            # 5. strips the trailing '=' as specified
            fields[-1][digest_name] = str(digest.rstrip(b'='), 'utf8')
        except ValueError:
            pass

        if not digest_name in fields[-1]:
            raise RuntimeError('Was unable to generate proper sum.')

    return fields

def consume_descriptors(descriptors, flavor='microdesc'):
    if flavor not in ['microdesc', 'unflavored']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    # TODO: check if family in microdesc are appropriate
    if flavor == 'microdesc':
        whitelist = [b'onion-key', b'ntor-onion-key', b'p', b'p6', b'id',
            b'family']
    else:
        whitelist = [b'router', b'identity-ed25519', b'master-key-ed25519',
            b'platform', b'proto', b'published', b'fingerprint', b'uptime',
            b'bandwidth', b'extra-info-digest', b'qkk', b'caches-extra-info',
            b'onion-key', b'signing-key', b'onion-key-crosscert',
            b'ntor-onion-key-crosscert', b'hidden-service-dir', b'contact',
            b'ntor-onion-key', b'reject', b'accept', b'tunnelled-dir-server',
            b'router-sig-ed25519', b'router-signature', b'ipv6-policy',
            b'family', b'protocols', b'or-address', b'allow-single-hop-exits']
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
        fields = compute_descriptor_digest(fields, descriptors, entry, flavor)

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
            if not base['type'] == 'exitpattern':
                raise RuntimeError('Unknown policy: {}'.format(base))
            if 'rules' not in base:
                base['rules'] = []

            base['rules'].append(dict(type=keyword, pattern=content))
            fields[-1]['policy'] = base
            continue

        if keyword == 'or-address':
            base = []
            if 'or-address' in fields[-1]:
                base = fields[-1]['or-address']

            address, port, guess = consensus.parse_address(content)
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

        # The spec says 'New code should neither […] nor parse this line'
        if keyword == 'protocols':
            pass

        if keyword == 'allow-single-hop-exits':
            content = True

        if keyword == 'published':
            date, time, when = consensus.parse_time(content)
            content = dict(date=date, time=time, stamp=when.timestamp())

        if keyword == 'fingerprint':
            content = consensus.parse_fingerprint(content)

            # Enrich 'router' with 'identity' fingerprint for convenience
            if 'router' in fields[-1]:
                identity = bytes.fromhex(content.replace(' ', ''))
                identity = str(base64.b64encode(identity), 'utf8')
                fields[-1]['router']['identity'] = identity.replace('=', '')

        if keyword == 'uptime':
            content = int(content)

        if keyword == 'bandwidth':
            avg, burst, observed = content.split(' ', 2)
            content = dict(
                avg=int(avg), burst=int(burst), observed=int(observed))

        if keyword == 'extra-info-digest':
            if ' ' in content:
                sha1, sha256 = content.split(' ', 1)
                sha256 = consensus.parse_base64(sha256)
                content = dict(sha1=sha1, sha256=sha256)
            else:
                content = dict(sha1=content)

        if keyword in ['caches-extra-info', 'hidden-service-dir',
            'tunnelled-dir-server']:
            content = True

        if keyword in ['onion-key', 'signing-key']:
            if not content == '':
                raise RuntimeError('Trailing content with {}: {}'.format(
                    keyword, content))

            descriptors, pubkey = consensus.scrap_signature(descriptors,
                fix=b'RSA PUBLIC KEY')
            if pubkey is not None:
                content = consensus.parse_base64(str(pubkey, 'utf8'))

        if keyword == 'onion-key-crosscert':
            if not content == '':
                raise RuntimeError('Trailing content with {}: {}'.format(
                    keyword, content))

            descriptors, crosscrt = consensus.scrap_signature(descriptors,
                fix=b'CROSSCERT')
            if crosscrt is not None:
                content = consensus.parse_base64(str(crosscrt, 'utf8'))

        if keyword == 'ntor-onion-key-crosscert':
            bit = int(content)

            descriptors, edcert = consensus.scrap_signature(descriptors,
                fix=b'ED25519 CERT')
            if edcert is not None:
                content = consensus.parse_base64(str(edcert, 'utf8'))
            content = dict(bit=bit, cert=content)

        if keyword == 'ntor-onion-key':
            content = consensus.parse_base64(content)

        if keyword in ['p', 'p6', 'ipv6-policy']:
            policy_type, portlist = content.split(' ')
            if not policy_type in ['accept', 'reject']:
                raise RuntimeError('Unknown policy: {}'.format(policy_type))

            portlist = consensus.parse_range_once(portlist, expand=False)
            content = {'type': policy_type, 'PortList': portlist}

        if keyword == 'id':
            id_type, data = content.split(' ')
            if not id_type in ['rsa1024', 'ed25519']:
                raise RuntimeError('Unknown id key type: {}'.format(id_type))

            content = {'type': id_type,
                'master-key': consensus.parse_base64(data)}

        if keyword in ['router-sig-ed25519', 'router-signature']:
            base = dict()
            if 'router-signatures' in fields[-1]:
                base = fields[-1]['router-signatures']

            if keyword == 'router-sig-ed25519':
                if 'router-signatures' in fields[-1]:
                    raise RuntimeError('Ed25519 must be first!')
                if not 'identity' in fields[-1]:
                    raise RuntimeError('Need identity with {} here: {}'.format(
                        keyword, fields[-1]))
                if not 'cert' in fields[-1]['identity']:
                    raise RuntimeError('Need cert. in identity: {}'.format(
                        fields[-1]))
                base['ed25519'] = consensus.parse_base64(content)

            if keyword == 'router-signature':
                descriptors, sig = consensus.scrap_signature(descriptors,
                    fix=b'SIGNATURE')
                if sig is not None:
                    content = consensus.parse_base64(str(sig, 'utf8'))
                base['rsa'] = content

            fields[-1]['router-signatures'] = base
            continue

        if keyword in ['identity-ed25519', 'master-key-ed25519']:
            base = dict()
            if 'identity' in fields[-1]:
                base = fields[-1]['identity']

            if 'type' not in base:
                base['type'] = 'ed25519'
            if not base['type'] == 'ed25519':
                raise RuntimeError('Invalid key type {} here:'.format(base))

            if keyword == 'identity-ed25519':
                if 'cert' in base:
                    raise RuntimeError('Extra cert. here: {}'.format(base))

                descriptors, edcert = consensus.scrap_signature(descriptors,
                    fix=b'ED25519 CERT')
                if edcert is not None:
                    base['cert'] = consensus.parse_base64(str(edcert, 'utf8'))

            if keyword == 'master-key-ed25519':
                if 'master-key' in base:
                    raise RuntimeError('Extra master key: {}'.format(base))

                base['master-key'] = consensus.parse_base64(content)

            # TODO: validation if both master-key & identity are present
            fields[-1]['identity'] = base
            continue

        if keyword in aliases:
            keyword = aliases[keyword]

        if keyword in fields[-1]:
            fields.append(dict())

        fields[-1][keyword] = content
    return descriptors, fields

def parse(descriptors, flavor='microdesc'):
    fields = dict(flavor=flavor)
    nbdesc = descriptors.count(b'onion-key\n-----BEGIN')

    descriptors, http = consensus.consume_http(descriptors)
    if http is not None:
        fields['http'] = http

    descriptors, entries = consume_descriptors(descriptors, flavor)
    if entries is not None:
        fields['descriptors'] = entries

    if not 'descriptors' in fields:
        raise RuntimeError('Unable to parse descriptors.')
    if not len(fields['descriptors']) == nbdesc:
        raise RuntimeError(
            'Unexpected or corrupted descriptor? ({}/{} found)'.format(
                len(fields['descriptors']), nbdesc))

    # Add flavor for convenience
    for idx in range(len(fields['descriptors'])):
        fields['descriptors'][idx]['flavor'] = flavor

    if descriptors == b'\n':
        descriptors = b''
    return fields, descriptors

def batch_query(items, prefix, separator='-', fixed_max_length=4096-128):
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

def download(state,
        cons=None, flavor='microdesc', cache=True, fail_on_missing=False):
    if cons is None:
        state, cons = consensus.download(state, flavor=flavor, cache=cache)
        if cons is None:
            return state, None
    elif isinstance(cons, list):
        cons = dict(routers=cons)
    elif isinstance(cons, str):
        digest_name = 'micro-digest' if flavor == 'microdesc' else 'digest'
        cons = dict(routers={digest_name: cons})
    elif 'routers' not in cons and 'identity' in cons:
        cons = dict(routers=[cons])

    if not isinstance(cons, dict):
        raise RuntimeError('Expecting a dict for cons, got: {}'.format(cons))

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

    # retrieve descriptors from cache
    descriptors = []
    partial_digests = digests
    if cache:
        digest_name = 'micro-digest' if flavor == 'microdesc' else 'digest'
        cached_digests = []
        for digest in digests:
            try:
                descriptor = ltor.cache.descriptors.get(flavor, digest)
                descriptors.append(descriptor)
                cached_digests.append(digest)
            except BaseException as e:
                pass
        partial_digests = [d for d in digests if d not in cached_digests]

    # retrieve descriptors via digests
    for query in batch_query(partial_digests, endpoint, separator):
        state, answer = ltor.hop.directory_query(state, query)

        if answer is None or len(answer) == 0:
            continue

        new_batch, remaining = parse(answer, flavor=flavor)
        if new_batch is None or remaining is None or len(remaining) > 0:
            raise RuntimeError('Unable to parse descriptors.')

        if new_batch is not None:
            descriptors += new_batch['descriptors']

    if flavor == 'microdesc':
        obtained = [d['micro-digest'] for d in descriptors]
    else:
        obtained = [d['digest'] for d in descriptors]
        obtained = [base64.b64decode(d + '====').hex() for d in obtained]

    invalid = []
    for digest in digests:
        if digest in obtained:
            obtained.remove(digest)
        else:
            invalid.append(digest)

    if not len(obtained) == 0:
        raise RuntimeError('Mismatched digest afterward! {} vs {}'.format(
            sorted(invalid), sorted(obtained)))

    if fail_on_missing and len(invalid) > 0:
        raise RuntimeError('Missing {} digests in answer: {}'.format(
            len(invalid), invalid))

    if cache:
        for descriptor in descriptors:
            ltor.cache.descriptors.put(descriptor)

    return state, descriptors

def download_authority(state):
    state, answer = ltor.hop.directory_query(state, '/tor/server/authority')
    if answer is None or len(answer) == 0:
        return state, None

    result, remain = parse(answer, flavor='unflavored')
    if not (len(remain) == 0
        and result is not None
        and len(result['descriptors']) == 1):
        raise RuntimeError('Unable to parse authority descriptor.')

    return state, result['descriptors'][0]
