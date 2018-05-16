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

def parse_range_once(value, expand=True):
    value = value.split(',')
    subvalues = []
    for subvalue in value:
        if '-' in subvalue:
            low, high = subvalue.split('-')
            if expand:
                subvalues += list(range(int(low), int(high) + 1))
            else:
                subvalues += [(int(low), int(high))]
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

def parse_base64(payload, level=0):
    if level < 2:
        try:
            return str(b64encode(b64decode(payload)), 'utf8')
        except binascii.Error:
            return parse_base64(payload + '=', level + 1)
    return str(b64encode(b64decode(payload)), 'utf8')

def parse_time(timedate):
    date, time = timedate.split(' ', 1)
    when = datetime.datetime.strptime(timedate, '%Y-%m-%d %H:%M:%S')
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

def consume_headers(consensus, flavor=None, sanity=True):
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
            version, variant = content.split(' ', 2)
            content = dict(version=int(version), flavor=variant)

            if sanity:
                assert len(fields) == 0 # first field
                assert content['version'] >= 3
                assert content['flavor'] == 'microdesc'

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
            pairs = parse_params(content)

        if keyword.startswith('shared-rand'):
            reveals, value = content.split(' ')

            value = parse_base64(value)
            content = {'NumReveals': int(reveals), 'Value': value}

            if sanity:
                assert content['NumReveals'] > 0
                assert value.split('=')[0] == content['Value'].split('=')[0]

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

def consume_routers(consensus, sanity=True):
    whitelist = [b'r', b'm', b's', b'v', b'pr', b'w']
    aliases = dict(m='digest', pr='protocols', s='flags', v='version')
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
            value = parse_base64(content)
            if sanity:
                assert value.split('=')[0] == content.split('=')[0]
            content = value

        if keyword == 's':
            content = content.split(' ')

        if keyword == 'pr':
            content = parse_ranges(content)

        if keyword == 'w':
            content = parse_params(content)

        if keyword == 'r':
            nickname, identity, date, time, address, orport, dirport = (
                content.split(' ', 6))

            value = parse_base64(identity)
            if sanity:
                assert value.split('=')[0] == identity.split('=')[0]
            identity = value

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

def jsonify(consensus, flavor=None, encode=True, sanity=True):
    fields = dict()

    consensus, http = consume_http(consensus)
    if http is not None:
        if sanity:
            assert http['headers']['Content-Type'] == 'text/plain'
            assert http['headers']['Content-Encoding'] == 'identity'
        fields['http'] = http

    consensus, headers = consume_headers(consensus, flavor, sanity)
    if headers is not None:
        fields['headers'] = headers

    if sanity:
        assert 'headers' in fields

    consensus, dir_sources = consume_dir_sources(consensus, sanity)
    if dir_sources is not None:
        fields['dir-sources'] = dir_sources

    if sanity:
        assert 'dir-sources' in fields

    consensus, routers = consume_routers(consensus, sanity)
    if routers is not None:
        fields['routers'] = routers

    if sanity:
        assert 'routers' in fields

    if encode:
        return json.dumps(fields), consensus
    return fields, consensus

if __name__ == "__main__":
    with open('consensus-microdesc', 'rb') as f:
        content = f.read()
    print(jsonify(content))
