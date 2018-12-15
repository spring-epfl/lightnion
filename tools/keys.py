import os
import random
import requests
from Crypto.PublicKey import RSA
import json as js
import re

# Those are the IP's addresses of the 9 authorities
ips = ['171.25.193.9:443', '86.59.21.38', '199.58.81.140', '194.109.206.212', '204.13.164.118',
       '131.188.40.189', '128.31.0.34:9131', '193.23.244.244', '154.35.175.225']
fingerprints = ['14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
                '23D15D965BC35114467363C165C4F724B64B4F66',
                '27102BC123E7AF1D4741AE047E160C91ADC76B21',
                '49015F787433103580E3B66A1707A00E60F2D15B',
                'D586D18309DED4CD6D57C18FDB97EFA96D330566',
                'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
                'ED03BB616EB2F60BEC80151114BB25CEF515B226',
                'EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97',
                '0232AF901C31A04EE9848595AF9BB7620D4C5B2E']


def download_signing_keys():
    """Download the signing keys from the one of the authorities, parse the file and returns a dictionary
    of identity digest and keys
    :return: dictionary or none if there is a problem during the request"""
    ip = random.choice(ips)
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

            if next_fingerprint in fingerprints:
                keys[next_fingerprint] = key
            next_fingerprint = None

        count += 1

    return keys


def get_signing_keys_info(path="tools/authority_signing_keys.json"):
    """
    Get the information of the authority router keys and save it to a json file.


    :param path: where we want to save the json
    """
    keys_dict = download_signing_keys()
    if keys_dict is None:
        raise ValueError("Error occurred during download of the keys")

    to_json(keys_dict, path)


def get_chutney_keys_info(saving_path="tools/chutney_authority_signing_keys.json"):
    """
    This function scrap the chutney's authority keys
    :param saving_path: where we want to save the json
    """
    rootdir = "/home/vagrant/chutney/net/nodes"
    keys = {}
    for d in os.listdir(rootdir):
        pattern = re.compile('\d*a')
        if pattern.match(d) is not None:
            subdir = rootdir + "/" + d
            with open(subdir + "/fingerprint", "r") as file1:
                fingerprint = file1.read().split(" ")[1][:-1]
            with open(subdir + "/keys/authority_signing_key", "r") as file2:
                key = file2.read()[:-1]

            keys[fingerprint] = key
    to_json(keys, saving_path)


def to_json(keys_dict, path):
    """
    This function saves a mapping from fingerprint to PEM format keys on disk as a json where each key is saved as:
    fingerprint:{
        pem: key_pem            //the key in pem format
        modulus: modulus        //the modulus of the key
        exponent: exponent      //the exponent of the key
    }

    :param keys_dict:
    :param path:
    :return:
    """
    info = {}
    for fingerprint in keys_dict.keys():
        key_pem = keys_dict[fingerprint]
        key = RSA.importKey(key_pem)
        modulus = key.n
        exponent = key.e

        sub_dict = {
            "pem": key_pem,
            "modulus": str(modulus),
            "exponent": str(exponent)
        }

        info[fingerprint] = sub_dict

    info_json = js.dumps(info)
    with open(path, "w") as file:
        file.write(info_json)

    print("{} keys have been saved to {}".format(len(keys_dict.keys()), path))
