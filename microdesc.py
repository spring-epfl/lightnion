from base64 import b64encode, b64decode
import datetime
import binascii
import time
import json

def scrap(consensus, end_of_field=None):
    if b'\n' not in consensus:
        return consensus, None

    line, remaining = consensus.split(b'\n', 1)
    if end_of_field(line):
        return consensus, None
    return remaining, line

def scrap_signature(consensus):
    if not consensus.startswith(b'-----BEGIN SIGNATURE-----'):
        return consensus, None

    lines = consensus.split(b'\n', 22) # fits 0-1024o (for 256o sig)
    try:
        idx_endsig = lines.index(b'-----END SIGNATURE-----')
    except ValueError:
        return consensus, None

    remaining = b'\n'.join(lines[idx_endsig + 1:])
    content = b''.join(lines[1:idx_endsig])
    return remaining, content

def parse_address(address, sanity=True):
    address = address.split(':')
    address, port = ':'.join(address[:-1]), address[-1]

    guessed_type = 4
    if address.startswith('['):
        address = address[1:]
        guessed_type = 6
    if address.endswith(']') or (sanity and guessed_type == 6):
        if sanity:
            assert address.endswith(']')
        address = address[:-1]
        guessed_type = 6
    if address.count(':') > 3:
        if sanity:
            assert guessed_type == 6
        guessed_type = 6

    return address, port, guessed_type

def parse_range_once(value, expand=True):
    value = value.split(',')
    subvalues = []
    for subvalue in value:
        if '-' in subvalue:
            low, high = [int(v) for v in subvalue.split('-')]
            if expand:
                subvalues += list(range(low, high + 1))
            elif low == high - 1:
                subvalues += [low, high]
            else:
                subvalues += [(low, high)]
        else:
            subvalues += [int(subvalue)]
    return subvalues

def parse_ranges(ranges, expand=True):
    pairs = ranges.split(' ')
    content = {}
    for key, value in [pair.split('=') for pair in pairs if '=' in pair]:
        content[key] = parse_range_once(value, expand)
    return content

def parse_params(params):
    pairs = params.split(' ')
    content = dict()
    for key, value in [pair.split('=') for pair in pairs]:
        content[key] = int(value)
    return content

def parse_base64(payload, sanity=True, level=0):
    if level < 2:
        try:
            value = str(b64encode(b64decode(payload)), 'utf8')
        except binascii.Error:
            value = parse_base64(payload + '=', level + 1)
    else:
        value = str(b64encode(b64decode(payload)), 'utf8')

    if level == 0:
        if not payload[-2:].count('=') == value[-2:].count('='):
            value = value.rstrip('=') + '=' * payload[-2:].count('=')

        if sanity:
            assert value == payload

    return value

def parse_time(timedate):
    date, time = timedate.split(' ', 1)
    when = datetime.datetime.strptime(timedate, '%Y-%m-%d %H:%M:%S')

    # convert to UTC-aware datetime object
    when = datetime.datetime(*when.timetuple()[:6],
        tzinfo=datetime.timezone.utc)
    return (when.strftime('%Y-%m-%d'), when.strftime('%H:%M:%S'), when)

def consume_http(consensus):
    def end_of_field(line):
        return line[-1:] != b'\r'

    fields = dict(headers=dict())
    valid = False
    while True:
        consensus, header = scrap(consensus, end_of_field)
        if header is None:
            return consensus, fields if valid else None

        valid = True
        if b' ' not in header:
            continue

        header = header[:-1]
        try:
            header = str(header, 'utf8')
        except:
            continue

        if header.startswith('HTTP/'):
            version, fields['code'], _ = header.split(' ', 2)
            fields['version'] = float(version.split('/', 1)[1])

        keyword, content = header.split(' ', 1)
        if keyword[-1:] == ':':
            fields['headers'][keyword[:-1]] = content

def consume_headers(consensus, flavor='unflavored', sanity=True):
    if flavor not in ['unflavored', 'microdesc']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    whitelist = [
        b'network-status-version', b'vote-status', b'consensus-method',
        b'valid-after', b'fresh-until', b'valid-until', b'voting-delay',
        b'client-versions', b'server-versions', b'known-flags',
        b'recommended-client-protocols', b'recommended-relay-protocols',
        b'required-client-protocols', b'required-relay-protocols', b'params',
        b'shared-rand-previous-value', b'shared-rand-current-value']
    def end_of_field(line):
        if b' ' not in line:
            return True
        keyword, _ = line.split(b' ', 1)
        return keyword not in whitelist

    fields = dict()
    valid = False
    while True:
        consensus, header = scrap(consensus, end_of_field)
        if header is None:
            return consensus, fields if valid else None

        valid = True
        if b' ' not in header:
            continue

        try:
            header = str(header, 'utf8')
        except:
            continue

        keyword, content = header.split(' ', 1)
        if keyword == 'network-status-version':
            content = content.split(' ', 1)
            if len(content) == 1:
                content.append('unflavored')
            version, variant = content
            content = dict(version=int(version), flavor=variant)

            if sanity:
                assert len(fields) == 0 # first field
                assert content['version'] >= 3
                assert content['flavor'] == flavor

        if keyword == 'consensus-method':
            content = int(content)

            if sanity:
                assert content >= 26

        if keyword in ['valid-after', 'fresh-until', 'valid-until']:
            date, time, when = parse_time(content)
            content = dict(date=date, time=time, stamp=when.timestamp())
            if sanity:
                import time
                if keyword == 'valid-after':
                    assert time.time() > content['stamp'] # valid-after
                if keyword == 'fresh-until':
                    assert content['stamp'] > fields['valid-after']['stamp']
                if keyword == 'valid-until':
                    assert time.time() < content['stamp'] # valid-until

        if keyword == 'voting-delay':
            vote, dist = content.split(' ', 1)
            content = dict(vote=int(vote), dist=int(dist))

        if keyword in ['client-versions', 'server-versions']:
            content = content.split(',')

        if keyword == 'known-flags':
            content = content.split(' ')

        if keyword.startswith(('recommended', 'required')):
            content = parse_ranges(content)

        if keyword == 'params':
            content = parse_params(content)

        if keyword.startswith('shared-rand'):
            reveals, value = content.split(' ')

            value = parse_base64(value, sanity)
            content = {'NumReveals': int(reveals), 'Value': value}

            if sanity:
                assert content['NumReveals'] >= 0

        fields[keyword] = content

def consume_dir_sources(consensus, sanity=True):
    whitelist = [b'dir-source', b'contact', b'vote-digest']
    def end_of_field(line):
        if b' ' not in line:
            return True
        keyword, _ = line.split(b' ', 1)
        return keyword not in whitelist

    fields = []
    valid = False
    while True:
        consensus, header = scrap(consensus, end_of_field)
        if header is None:
            if not valid:
                return consensus, None
            break

        valid = True
        if b' ' not in header:
            continue

        try:
            header = str(header, 'utf8')
        except:
            continue

        keyword, content = header.split(' ', 1)
        if keyword == 'vote-digest':
            value = bytes.fromhex(content).hex()
            if sanity:
                assert value.lower() == content.lower()
            content = value

        if keyword == 'dir-source':
            nickname, identity, hostname, address, dirport, orport = (
                content.split(' ', 5))

            value = bytes.fromhex(identity).hex()
            if sanity:
                assert value.lower() == identity.lower()
            identity = value

            content = dict(nickname=nickname, identity=identity,
                hostname=hostname, address=address, dirport=int(dirport),
                orport=int(orport))

            if sanity:
                assert 0 < content['dirport'] < 65536
                assert 0 < content['orport'] < 65536

        if keyword != 'dir-source' and fields[-1][0] == 'dir-source':
            if sanity:
                assert keyword not in fields[-1][1]
            fields[-1][1][keyword] = content
            continue

        fields.append((keyword, content))

    full_entries_count = len([v for k, v in fields if k == 'dir-source'])
    if sanity:
        assert full_entries_count == len(fields)

    if full_entries_count == len(fields):
        fields = [v for k, v in fields]

    return consensus, fields

def consume_routers(consensus, flavor='unflavored', sanity=True):
    if flavor not in ['unflavored', 'microdesc']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    if flavor == 'unflavored':
        whitelist = [b'r', b'm', b's', b'v', b'pr', b'w', b'p', b'a']
    elif flavor == 'microdesc':
        whitelist = [b'r', b'm', b's', b'v', b'pr', b'w']

    aliases = dict(m='micro-digest', pr='protocols', s='flags', v='version',
        p='exit-policy', a='extra-address')
    def end_of_field(line):
        if b' ' not in line:
            return True
        keyword, _ = line.split(b' ', 1)
        return keyword not in whitelist

    fields = []
    valid = False
    while True:
        consensus, header = scrap(consensus, end_of_field)
        if header is None:
            if not valid:
                return consensus, None
            break

        valid = True
        if b' ' not in header:
            continue

        try:
            header = str(header, 'utf8')
        except:
            continue

        keyword, content = header.split(' ', 1)
        if keyword == 'm':
            content = parse_base64(content, sanity)

        if keyword == 's':
            content = content.split(' ')

        if keyword == 'pr':
            content = parse_ranges(content)

        if keyword == 'w':
            content = parse_params(content)

        if keyword == 'p':
            policy_type, portlist = content.split(' ')
            portlist = parse_range_once(portlist, expand=False)
            content = {'type': policy_type, 'PortList': portlist}

        if keyword == 'a':
            address, port, guessed_type = parse_address(content, sanity)
            content = [{'ip': address, 'port': port, 'guess': guessed_type}]

        if keyword == 'r' and flavor == 'unflavored':
            (nickname, identity, digest, date, time, address, orport,
                dirport) = content.split(' ', 7)

            digest = parse_base64(digest, sanity)
            identity = parse_base64(identity, sanity)
            date, time, when = parse_time(' '.join([date, time]))

            content = dict(nickname=nickname, identity=identity, digest=digest,
                date=date, time=time, stamp=when.timestamp(), address=address,
                dirport=int(dirport), orport=int(orport))

            if sanity:
                assert 0 < content['orport'] < 65536
                assert 0 <= content['dirport'] < 65536

        if keyword == 'r' and flavor == 'microdesc':
            nickname, identity, date, time, address, orport, dirport = (
                content.split(' ', 6))

            identity = parse_base64(identity, sanity)
            date, time, when = parse_time(date + ' ' + time)

            content = dict(nickname=nickname, identity=identity, date=date,
                time=time, stamp=when.timestamp(), address=address,
                dirport=int(dirport), orport=int(orport))

            if sanity:
                assert 0 < content['orport'] < 65536
                assert 0 <= content['dirport'] < 65536

        if keyword != 'r' and fields[-1][0] == 'r':
            if keyword in aliases:
                keyword = aliases[keyword]

            if keyword == 'extra-address' and keyword in fields[-1][1]:
                content[0]['ignored'] = True
                fields[-1][1]['extra-address'] += content
                continue

            if sanity:
                assert keyword not in fields[-1][1]
            fields[-1][1][keyword] = content
            continue

        fields.append((keyword, content))

    full_entries_count = len([v for k, v in fields if k == 'r'])
    if sanity:
        assert full_entries_count == len(fields)

    if full_entries_count == len(fields):
        fields = [v for k, v in fields]

    return consensus, fields

def consume_footer(consensus, flavor='unflavored', sanity=True):
    if flavor not in ['unflavored', 'microdesc']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    whitelist = [
        b'directory-footer', b'bandwidth-weights', b'directory-signature']

    def end_of_field(line):
        if b'directory-footer' == line:
            return False
        if b' ' not in line:
            return True
        keyword, _ = line.split(b' ', 1)
        return keyword not in whitelist

    fields = dict()
    valid = False
    while True:
        consensus, header = scrap(consensus, end_of_field)
        print(consensus, header)
        if header is None:
            return consensus, fields if valid else None

        valid = True
        if b' ' not in header:
            continue

        try:
            header = str(header, 'utf8')
        except:
            continue

        keyword, content = header.split(' ', 1)
        if keyword == 'directory-footer':
            if sanity:
                assert len(fields) == 0 # first field

        if keyword == 'bandwidth-weights':
            content = parse_params(content)

        if keyword == 'directory-signature':
            content = content.split(' ', 2)
            if len(content) == 3:
                algorithm, identity, signing_key_digest = content
            elif len(content) == 2:
                algorithm = 'sha1'
                identity, signing_key_digest = content

            content = {
                'Algorithm': algorithm,
                'identity': identity,
                'signing-key-digest': signing_key_digest}

            consensus, signature = scrap_signature(consensus)
            if signature is not None:
                signature = parse_base64(str(signature, 'utf8'))
                content['signature'] = parse_base64(signature)

            if keyword + 's' not in fields:
                fields[keyword + 's'] = []
            fields[keyword + 's'].append(content)
            continue

        fields[keyword] = content
    return consensus, fields

def jsonify(consensus, flavor='unflavored', encode=True, sanity=True):
    fields = dict()

    consensus, http = consume_http(consensus)
    if http is not None:
        fields['http'] = http

    consensus, headers = consume_headers(consensus, flavor, sanity)
    if headers is not None:
        fields['headers'] = headers

    consensus, dir_sources = consume_dir_sources(consensus, sanity)
    if dir_sources is not None:
        fields['dir-sources'] = dir_sources

    consensus, routers = consume_routers(consensus, flavor, sanity)
    if routers is not None:
        fields['routers'] = routers

    consensus, footer = consume_footer(consensus, flavor, sanity)
    if footer is not None:
        fields['footer'] = footer

    if sanity:
        assert 'headers' in fields
        assert 'dir-sources' in fields
        assert 'routers' in fields
        assert 'footer' in fields

    if encode:
        return json.dumps(fields), consensus
    return fields, consensus

if __name__ == "__main__":
    with open('./descriptors/consensus', 'rb') as f:
        content = f.read()
    ans = jsonify(content)
    print(ans[0], len(ans[1]))

    with open('./descriptors/consensus-microdesc', 'rb') as f:
        content = f.read()
    ans = jsonify(content, flavor='microdesc')
    print(ans[0], len(ans[1]))
