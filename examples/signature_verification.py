import requests
from tools.keys import get_signing_keys_info
import os
import json
from lightnion import signature

if __name__ == "__main__":
    # The url of one of the TOR's authority node to download a consensus
    url = "http://193.23.244.244/tor/status-vote/current/consensus"

    # HTTP request
    print("Request for consensus")
    request = requests.get(url)

    if request.status_code == 200:
        raw_cons = request.text
    else:
        raise Exception("Consensus could not be downloaded")

    # Get the keys
    print("Get the signing keys")
    path = "./tools/authority_signing_keys.json"
    if not os.path.exists(path):
        print("Download keys")
        get_signing_keys_info(path)

    with open(path, "r") as file:
        print("Get keys from disk")
        keys_json = file.read()
        keys = json.loads(keys_json)

    print("Stat verification")
    # Verify consensus
    if signature.verify(raw_cons, keys):
        print("The consensus has been verified!")
    else:
        print("The consensus has not been verified")
