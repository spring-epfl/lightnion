import random
import requests
from Crypto.PublicKey import RSA
import json as js

# Those are the IP's addresses of the 9 authorities
ips = ['171.25.193.9:443', '86.59.21.38', '199.58.81.140', '194.109.206.212', '204.13.164.118',
       '131.188.40.189', '128.31.0.34:9131', '193.23.244.244', '154.35.175.225']


def download_signing_keys():
    """Download the signing keys from the one of the authorities, parse the file and returns a dictionary
    of identity digest and keys
    :return: dictionary or none if there is a problem during the request"""
    ip = random.choice(ips)
    # TODO: should be all.z to get a compressed version of the file + cached them if not expired?
    url = "http://{}/tor/keys/all".format(ip)
    rq = requests.get(url)

    if rq.status_code == 200:
        return parse_signing_keys(rq.text)
    else:
        return None


def parse_signing_keys(raw):
    """Parse a raw file into a dictionary of fingerprint and keys
    :param raw: the raw file
    :return: dictionary mapping the fingerprints to a RSA key in pem format"""

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


def get_signing_keys_info(path="authority_signing_keys.json"):
    """
    Get the information of the authority router keys and save it to a json file.
    Each key is saved as:

    fingerprint:{
        pem: key_pem            //the key in pem format
        modulus: modulus        //the modulus of the key
        exponent: exponent      //the exponent of the key
    }

    :param path: where we want to save the json
    """
    keys_dict = download_signing_keys()
    info = {}

    if keys_dict is None:
        raise ValueError("Error occurred during download of the keys")

    for fingerprint in keys_dict.keys():
        key_pem = keys_dict[fingerprint]
        key = RSA.importKey(key_pem)
        modulus = key.n
        exponent = key.e

        sub_dict = {
            "pem": key_pem,
            "modulus": modulus,
            "exponent": exponent
        }

        info[fingerprint] = sub_dict

    info_json = js.dumps(info)

    with open(path, "w") as file:
        file.write(info_json)

    print("{} keys have been saved to {}".format(len(keys_dict.keys()), path))
