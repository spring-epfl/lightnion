import os
import random
import requests
from Crypto.PublicKey import RSA
import json as js
import re

# Those are the IP's addresses of the 9 authorities
ips = ['171.25.193.9:443', '86.59.21.38', '199.58.81.140',  '204.13.164.118',
       '131.188.40.189', '128.31.0.34:9131',  '154.35.175.225']


def download_signing_keys(ip):
    """Download the signing keys from the one of the authorities, parse the file and returns a dictionary
    of identity digest and keys
    :return: dictionary or none if there is a problem during the request"""
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


def get_signing_keys_info(ip = random.choice(ips), path = "./tools/authority_signing_keys.json"):
    """
    Get the information of the authority router keys and save it to a json file.


    :param path: where we want to save the json
    """
    keys_dict = download_signing_keys(ip)
    if keys_dict is None:
        raise ValueError("Error occurred during download of the keys")

    return to_json(keys_dict, path)


def get_chutney_keys_info(saving_path="./tools/chutney_authority_signing_keys.json"):
    """
    This function scrap the chutney's authority keys
    :param saving_path: where we want to save the json
    """
    #change to your chutney dir. 
    rootdir = "/home/vagrant/chutney/net/nodes"
    keys = ""
    for d in os.listdir(rootdir):
        pattern = re.compile('\d*a')
        if pattern.match(d) is not None:
            subdir = rootdir + "/" + d
            with open(subdir + "/keys/authority_certificate", "r") as file2:
                keys += file2.read()
    keys = parse_signing_keys(keys)
    return to_json(keys, saving_path)


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

    return info
