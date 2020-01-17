from tools import keys
import os
import random
import requests
from Crypto.PublicKey import RSA
import json as js
import re


all_keys = {}
def get_root_keys(raw):
    """Parse a raw file into a dictionary of fingerprint and keys
    :param raw: the raw file
    :return: dictionary mapping the fingerprints to a RSA key in pem format"""

    assert raw is not None

    lines = raw.split('\n')
    count = 0
    next_fingerprint = None

    while count < len(lines):
        if lines[count].startswith('fingerprint'):
            if next_fingerprint is not None:
                raise ValueError("File has not the expected format")
            else:
                next_fingerprint = lines[count].split(" ")[1]

        elif lines[count] == 'dir-identity-key':
            count += 1
            key = lines[count] + '\n'
            count += 1
            while lines[count] != '-----END RSA PUBLIC KEY-----':
                key += lines[count] + '\n'
                count += 1
            key += '-----END RSA PUBLIC KEY-----'

            
            all_keys[next_fingerprint] = key

            next_fingerprint = None

        count += 1

for ip in keys.ips:
	url = "http://{}/tor/keys/all".format(ip)
	rq = requests.get(url)

	if rq.status_code != 200:
		continue

	get_root_keys(rq.text)
	print("+++++keys so far : " + str(len(all_keys)))

keys.to_json(all_keys,"./js-client/demo/root_keys.json")