import random
import requests

# Those are the IP's addresses of the 9 authorities
ips = ['171.25.193.9:443', '86.59.21.38', '199.58.81.140', '194.109.206.212', '204.13.164.118',
       '131.188.40.189', '128.31.0.34:9131', '193.23.244.244', '154.35.175.225']


def download_signing_keys():
    """Download the signing keys from the one of the authorities, parse the file and returns a dictionary
    of identity digest and keys
    :return: dictionary or none if there is a problem during the request"""
    ip = random.choice(ips)
    # TODO: should be all.z to get a compressed version of the file
    url = "http://{}/tor/keys/all".format(ip)
    rq = requests.get(url)

    if rq.status_code == 200:
        return parse_signing_keys(rq.text)
    else:
        return None


def parse_signing_keys(raw):
    """Parse a raw file into a dictionary of fingerprint and signature
    :param raw: the raw file
    :return: dictionary"""

    assert raw is not None

    lines = raw.split('\n')
    count = 0
    keys = {}
    next_fingerprint = None

    while count < len(lines):
        if lines[count].startswith('fingerprint'):
            if next_fingerprint is not None:
                raise ValueError("File has not the expected format")
            else:
                next_fingerprint = lines[count].split(" ")[1]

        elif lines[count] == 'dir-signing-key':
            count += 1
            key = lines[count] + '\n'
            count += 1
            while lines[count] != '-----END RSA PUBLIC KEY-----':
                key += lines[count] + '\n'
                count += 1
            key += '-----END RSA PUBLIC KEY-----'

            keys[next_fingerprint] = key
            next_fingerprint = None

        count += 1

    return keys
