from base64 import b64encode, b64decode
import datetime
import binascii
import time
import os

import urllib.request

import lightnion as lnn


# TODO: remove extra (useless) checks/exceptions within this file

def scrap(consensus, end_of_field):
    """
        Consume lines upon matching a criterion.

        Returns (consensus-without-first-line, first-line)
            if end_of_field(first-line) returns True,
            else returns (consensus-with-first-line, None)

        :param bytes consensus: input which first line may be consumed
        :param function end_of_field: passed a line, returns True when no match

        :returns: a tuple (updated-consensus, next-field-or-None)
    """
    if b'\n' not in consensus:
        return consensus, None

    line, remaining = consensus.split(b'\n', 1)
    if end_of_field(line):
        return consensus, None
    return remaining, line


def scrap_signature(consensus, fix=b'SIGNATURE'):
    """
        Consume a signature field if there is one to consume.

        :param bytes consensus: input which may start with a signature.

        :returns: a tuple (updated-consensus, signature-or-None)
    """
    if not consensus.startswith(b'-----BEGIN ' + fix + b'-----'):
        return consensus, None

    lines = consensus.split(b'\n', 22)  # fits 0-1024o (for 256o sig)
    try:
        idx_endsig = lines.index(b'-----END ' + fix + b'-----')
    except ValueError:
        return consensus, None

    remaining = b'\n'.join(lines[idx_endsig + 1:])
    content = b''.join(lines[1:idx_endsig])
    return remaining, content


def parse_address(address):
    """
        Take a Tor-formatted v4 or v6 IP address with a port, returns a
        cleaned-up version.

        :param str address: input address to be processed

        :returns: a tuple (address, port, guessed-type) where port is an
                  integer and guessed-type is 4 or 6 (IPv4 or IPv6).
    """
    address = address.split(':')
    address, port = ':'.join(address[:-1]), address[-1]

    guessed_type = 4
    if address.startswith('['):
        address = address[1:]
        guessed_type = 6
    if address.endswith(']') or guessed_type == 6:
        if not address.endswith(']'):
            raise RuntimeError(
                'Seems like an invalid IPv6: {}'.format(address))
        address = address[:-1]
        guessed_type = 6
    if address.count(':') > 3:
        if not guessed_type == 6:
            raise RuntimeError(
                'Seems like an very odd IPv6: {}'.format(address))
        guessed_type = 6

    return address, int(port), guessed_type


def parse_range_once(value, expand=True):
    """
        Take Tor-formatted ranges, then returns it as a list of integers if
        expanded or a mix of integers and ranges as [low, high] tuples.

        For example, we use it to parse "p" fields:
            https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L2322

        :param str value: input value to be processed
        :param bool expand: do we expand a range as integers? (default: True)

        :returns: a list of integers or a mix of integers and range list/tuples
    """
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
                subvalues += [[low, high]]
        else:
            subvalues += [int(subvalue)]
    return subvalues


def parse_ranges(ranges, expand=True):
    """
        Take Tor-formatted named ranges, then returns a keyword-based
        dictionary of list of integers or mix of integers and range tuples (as
        returned by parse_range_once), expanded or not.

        For example, we use it to parse "recommended-client-protocols" fields:
            https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L780

        :param str ranges: input ranges to be processed
        :param bool expand: do we expand ranges as integers? (default: True)

        :returns: a dictionary with (range-name, range-content) items
    """
    pairs = ranges.split(' ')
    content = {}
    for key, value in [pair.split('=') for pair in pairs if '=' in pair]:
        content[key] = parse_range_once(value, expand)
    return content


def parse_params(params):
    """
        Take Tor-formatted parameters, then returns a keyword-based dictionary
        of integers.

        For example, we use it to parse "params" fields:
            https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L1820

        :param str params: input params to be processed

        :returns: a dictionary with (param-name, param-integer-value) items
    """
    pairs = params.split(' ')
    content = dict()
    for key, value in [pair.split('=') for pair in pairs]:
        content[key] = int(value)
    return content


def parse_fingerprint(payload):
    asbytes = bytes.fromhex(payload)
    fingers = asbytes.hex().upper()
    fingers = ' '.join([fingers[i:i + 4] for i in range(0, len(fingers), 4)])
    if not fingers == payload:
        raise RuntimeError(
            'Fingerprint not conform: {} vs {}'.format(fingers, payload))
    return fingers


def parse_base64(payload, decode=False):
    """
        Take an input base64 string, decode it, re-encode it.

        For example, we use it to parse "shared-rand-current-value" fields:
            https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L2069

        :param str payload: input base64-encoded data
        :param bool decode: return raw bytes (default: False)

        :returns: a base64-encoded string equivalent to the input
    """
    decoded = b64decode(payload + '====')
    value = str(b64encode(decoded), 'utf8')

    if not payload[-2:].count('=') == value[-2:].count('='):
        value = value.rstrip('=') + '=' * payload[-2:].count('=')

    if not value == payload:
        raise RuntimeError('Invalid base64 encoding: {} vs {}'.format(
            value, payload))

    if decode:
        return decoded

    return value


def parse_time(timedate):
    """
        Take a Tor-formatted (Y-m-d H:M:S) time, parse it, then returns the
        corresponding date, time and datetime object. This function assumes
        that the given time uses the UTC timezone – as it's the timezone used
        into Tor consensuses.

        :param str timedate: input time and date to be parsed

        :returns: a tuple (date-str, time-str, datetime-object)
    """
    when = datetime.datetime.strptime(timedate, '%Y-%m-%d %H:%M:%S')

    # convert to UTC-aware datetime object
    when = datetime.datetime(*when.timetuple()[:6],
                             tzinfo=datetime.timezone.utc)
    return (when.strftime('%Y-%m-%d'), when.strftime('%H:%M:%S'), when)


def consume_http(consensus):
    """
        Consume HTTP headers if present, then returns the remaining input to be
        further processed and a set of headers (or None, if none present).

        :param str consensus: input to be processed

        :returns: a tuple (remaining-input, headers-or-None)
    """

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


def consume_headers(consensus, flavor='unflavored'):
    """
        Consume consensus headers if present, then returns the remaining input
        to be further processed and a set of headers (or None, if none
        present).

        Will consume the following fields:
            - network-status-version
            - vote-status
            - consensus-method
            - valid-after
            - fresh-until
            - valid-until
            - voting-delay
            - client-versions
            - server-versions
            - known-flags
            - recommended-client-protocols
            - recommended-relay-protocols
            - required-client-protocols
            - required-relay-protocols
            - params
            - shared-rand-previous-value
            - shared-rand-current-value

        :param str consensus: input to be processed
        :param str flavor: consensus flavor ('unflavored' or 'microdesc')

        :returns: a tuple (remaining-input, headers-or-None)
    """
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

            if not len(fields) == 0:
                raise RuntimeError('Expecting {} as first field: {}'.format(
                    keyword, content))
            if not content['version'] >= 3:
                raise RuntimeError('Expecting {} version >= 3 here: {}'.format(
                    keyword, content))
            if not content['flavor'] == flavor:
                raise RuntimeError('Unmatched {} flavor {} here: {}'.format(
                    keyword, flavor, content))

        if keyword == 'consensus-method':
            content = int(content)

            if not content >= 26:
                raise RuntimeError(
                    'Consensus version >= 26 required: {}'.format(content))

        if keyword in ['valid-after', 'fresh-until', 'valid-until']:
            date, time, when = parse_time(content)
            content = dict(date=date, time=time, stamp=when.timestamp())

            import time
            if keyword == 'valid-after':
                if not time.time() > content['stamp']:
                    raise RuntimeError('{} not yet valid! {}'.format(
                        keyword, content))  # valid-after

            if keyword == 'fresh-until':
                if not content['stamp'] > fields['valid-after']['stamp']:
                    raise RuntimeError('{} not fresh! {}'.format(
                        keyword, content))  # fresh-until

            if keyword == 'valid-until':
                if not time.time() < content['stamp']:
                    raise RuntimeError('{} no more valid! {}'.format(
                        keyword, content))  # valid-until

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

            value = parse_base64(value)
            content = {'NumReveals': int(reveals), 'Value': value}

            if not content['NumReveals'] >= 0:
                raise RuntimeError('{} must be >= 0 here:'.format(
                    keyword, content))

        fields[keyword] = content


def consume_dir_sources(consensus):
    """
        Consume directory source listing if present, then returns the remaining
        input to be further processed and a set of directory sources (or None,
        if none present).

        Will consume the following fields:
            - dir-source
            - contact
            - vote-digest

        :param str consensus: input to be processed

        :returns: a tuple (remaining-input, headers-or-None)
    """
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
            if not value.lower() == content.lower():
                raise RuntimeError('Unmatched {} here: {} {}'.format(
                    keyword, value, content))
            content = value

        if keyword == 'dir-source':
            nickname, identity, hostname, address, dirport, orport = (
                content.split(' ', 5))

            value = bytes.fromhex(identity).hex()
            if not value.lower() == identity.lower():
                raise RuntimeError('Unmatched {} here: {} {}'.format(
                    keyword, value, content))
            identity = value

            content = dict(nickname=nickname, identity=identity,
                           hostname=hostname, address=address, dirport=int(dirport),
                           orport=int(orport))

            if not 0 < content['dirport'] < 65536:
                raise RuntimeError('Invalid dirport here: {}'.format(content))
            if not 0 < content['orport'] < 65536:
                raise RuntimeError('Invalid orport here: {}'.format(content))

        if keyword != 'dir-source' and fields[-1][0] == 'dir-source':
            if not (keyword not in fields[-1][1]):
                raise RuntimeError(
                    'Unexpected {} with: {}'.format(keyword, fields[-1]))
            assert keyword not in fields[-1][1]
            fields[-1][1][keyword] = content
            continue

        fields.append((keyword, content))

    full_entries_count = len([v for k, v in fields if k == 'dir-source'])

    if not full_entries_count == len(fields):
        raise RuntimeError('Incomplete entry or corrupted?')

    if full_entries_count == len(fields):
        fields = [v for k, v in fields]

    return consensus, fields


def consume_routers(consensus, flavor='unflavored'):
    """
        Consume router listing if present, then returns the remaining input to
        be further processed and a set of routers (or None, if none present).

        Will consume the following fields:
            - r
            - m
            - s
            - v
            - pr
            - w
            - p (unflavored only)
            - a (unflavored only)

        :param str consensus: input to be processed
        :param str flavor: consensus flavor ('unflavored' or 'microdesc')

        :returns: a tuple (remaining-input, headers-or-None)
    """
    if flavor not in ['unflavored', 'microdesc']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    # TODO: check if 'a' fields in microdesc consensus are still a thing
    if flavor == 'unflavored':
        whitelist = [b'r', b'm', b's', b'v', b'pr', b'w', b'p', b'a']
    elif flavor == 'microdesc':
        whitelist = [b'r', b'm', b's', b'v', b'pr', b'w', b'a']

    aliases = dict(m='micro-digest', pr='protocols', s='flags', v='version',
                   p='exit-policy', a='or-address')

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
            content = parse_base64(content)

        if keyword == 's':
            content = content.split(' ')

        if keyword == 'pr':
            content = parse_ranges(content)

        if keyword == 'w':
            content = parse_params(content)

        if keyword == 'p':
            policy_type, portlist = content.split(' ')
            if not policy_type in ['accept', 'reject']:
                raise RuntimeError('Unknown policy: {}'.format(policy_type))

            portlist = parse_range_once(portlist, expand=False)
            content = {'type': policy_type, 'PortList': portlist}

        if keyword == 'a':
            address, port, guessed_type = parse_address(content)
            content = [{'ip': address, 'port': port, 'type': guessed_type}]

        if keyword == 'r' and flavor == 'unflavored':
            (nickname, identity, digest, date, time, address, orport,
             dirport) = content.split(' ', 7)

            digest = parse_base64(digest)
            identity = parse_base64(identity)
            date, time, when = parse_time(' '.join([date, time]))

            content = dict(nickname=nickname, identity=identity, digest=digest,
                           date=date, time=time, stamp=when.timestamp(), address=address,
                           dirport=int(dirport), orport=int(orport))

            if not 0 <= content['dirport'] < 65536:
                raise RuntimeError('Invalid dirport here: {}'.format(content))
            if not 0 < content['orport'] < 65536:
                raise RuntimeError('Invalid orport here: {}'.format(content))

        if keyword == 'r' and flavor == 'microdesc':
            nickname, identity, date, time, address, orport, dirport = (
                content.split(' ', 6))

            identity = parse_base64(identity)
            date, time, when = parse_time(date + ' ' + time)

            content = dict(nickname=nickname, identity=identity, date=date,
                           time=time, stamp=when.timestamp(), address=address,
                           dirport=int(dirport), orport=int(orport))

            if not 0 <= content['dirport'] < 65536:
                raise RuntimeError('Invalid dirport here: {}'.format(content))
            if not 0 < content['orport'] < 65536:
                raise RuntimeError('Invalid orport here: {}'.format(content))

        if keyword != 'r' and fields[-1][0] == 'r':
            if keyword in aliases:
                keyword = aliases[keyword]

            if keyword == 'or-address' and keyword in fields[-1][1]:
                content[0]['ignored'] = True
                fields[-1][1]['or-address'] += content
                continue

            if not (keyword not in fields[-1][1]):
                raise RuntimeError('Unexpected {} with: {}'.format(keyword,
                                                                   fields[-1]))

            fields[-1][1][keyword] = content
            continue

        fields.append((keyword, content))

    full_entries_count = len([v for k, v in fields if k == 'r'])
    if not full_entries_count == len(fields):
        raise RuntimeError('Invalid or corrupted entry?')

    if full_entries_count == len(fields):
        fields = [v for k, v in fields]

    return consensus, fields


def consume_footer(consensus, flavor='unflavored'):
    """
        Consume consensus footer if present, then returns the remaining input
        to be further processed and a set of footers (or None, if none
        present).

        Will consume the following fields:
            - directory-footer
            - bandwidth-weights
            - directory-signature

        :param str consensus: input to be processed
        :param str flavor: consensus flavor ('unflavored' or 'microdesc')

        :returns: a tuple (remaining-input, headers-or-None)
    """
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
        if keyword == 'directory-footer' and not len(fields) == 0:
            raise RuntimeError('Expect {} as first field!'.format(keyword))

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
                content['signature'] = signature

            if keyword + 's' not in fields:
                fields[keyword + 's'] = []
            fields[keyword + 's'].append(content)
            continue

        fields[keyword] = content
    return consensus, fields


def parse(consensus, flavor='unflavored'):
    """
        Parse a raw consensus with the given flavor, then returns sanitized
        entries as a python dictionary.

        :param str consensus: input to be processed
        :param str flavor: consensus flavor ('unflavored' or 'microdesc')

        :returns: a python dictionary
    """
    fields = dict(flavor=flavor)

    consensus, http = consume_http(consensus)
    if http is not None:
        fields['http'] = http

    consensus, headers = consume_headers(consensus, flavor)
    if headers is not None:
        fields['headers'] = headers

    consensus, dir_sources = consume_dir_sources(consensus)
    if dir_sources is not None:
        fields['dir-sources'] = dir_sources

    consensus, routers = consume_routers(consensus, flavor)
    if routers is not None:
        fields['routers'] = routers

    consensus, footer = consume_footer(consensus, flavor)
    if footer is not None:
        fields['footer'] = footer

    if not ('headers' in fields
            and 'dir-sources' in fields
            and 'routers' in fields
            and 'footer' in fields):
        raise RuntimeError('Missing entry: {}'.format(list(fields)))

    return fields, consensus


def download(state, flavor='microdesc', cache=True):
    if flavor not in ['unflavored', 'microdesc']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    if cache:
        try:
            return state, lnn.cache.consensus.get(flavor)
        except BaseException:
            pass

    endpoint = '/tor/status-vote/current/consensus'
    if flavor == 'microdesc':
        endpoint += '-microdesc'

    state, answer = lnn.hop.directory_query(state, endpoint)

    consensus, remaining = parse(answer, flavor=flavor)

    if consensus is None or remaining is None or not len(remaining) == 0:
        raise RuntimeError('Unable to parse downloaded consensus!')

    if cache:
        lnn.cache.consensus.put(consensus)

    return state, consensus


def download_direct(ip, port, flavor='microdesc', cache=True):
    """Retrieve consensus via a direct HTTP connection.
    :param ip: IP address of the node from which to retrieve the consensus.
    :param port: port of the node from which to retrieve the consensus.
    :param flavor: flavour of the consensus to retrieve.
    :param cache: if the retrieved consensus should put in the cache.
    """

    if flavor not in ['unflavored', 'microdesc']:
        raise NotImplementedError(
            'Consensus flavor "{}" not supported.'.format(flavor))

    endpoint = 'consensus-microdesc' if flavor == 'microdesc' else 'consensus'
    uri = 'http://%s:%d/tor/status-vote/current/%s' % (ip, port, endpoint)

    res = urllib.request.urlopen(uri)

    consensus, remaining = parse(res.read(), flavor=flavor)

    if consensus is None or remaining is None or not len(remaining) == 0:
        raise RuntimeError('Unable to parse downloaded consensus!')

    if cache:
        lnn.cache.consensus.put(consensus)

    return consensus



def load(file_name, cache=True):
    """Load the consensus from a file
    :param file_name: the name of the file in consensus_file
    :param cache: if we cache the newly downloaded consensus
    :return: the parsed consensus"""

    abs_path = "/vagrant/consensus_files/"+file_name

    if not os.path.exists(abs_path):
        raise FileNotFoundError()

    if cache:
        try:
            return lnn.cache.consensus.get("unflavored")
        except BaseException:
            pass

    with open(abs_path, "r") as file:
        answer = file.read()

    consensus, remaining = consume_routers(answer)

    if consensus is None or remaining is None or not len(remaining) == 0:
        raise RuntimeError('Unable to parse downloaded consensus!')

    if cache:
        lnn.cache.consensus.put(consensus)

    return consensus
