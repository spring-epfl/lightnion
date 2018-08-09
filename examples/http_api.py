import lighttor as ltor
import lighttor.proxy.forward

import argparse
import requests
import base64
import json

def ntor_get(guard):
    import lighttor.ntor_ref as ntor_ref
    import curve25519

    identity = base64.b64decode(guard['router']['identity'] + '====')
    onion_key = base64.b64decode(guard['ntor-onion-key'] + '====')

    donna_onion_key = curve25519.keys.Public(onion_key)
    ephemeral_key, payload = ntor_ref.client_part1(identity, donna_onion_key)

    payload = str(base64.b64encode(payload), 'utf8')
    return payload, (donna_onion_key, ephemeral_key, identity)

def ntor_finish(payload, material):
    import lighttor.ntor_ref as ntor_ref

    payload = base64.b64decode(payload)
    donna_onion_key, ephemeral_key, identity = material

    material = ntor_ref.client_part2(ephemeral_key, payload,
        identity, donna_onion_key, keyBytes=92)

    return ltor.crypto.ntor.kdf(material)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('host', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=4990)
    sys_argv = parser.parse_args()

    base_url = 'http://{}:{}{}'.format(
        sys_argv.host, sys_argv.port, lighttor.proxy.forward.base_url)

    # retrieve the guard descriptor
    rq = requests.get(base_url + '/guard')

    # parse the guard destriptor
    assert rq.status_code == 200
    answer = json.loads(rq.text)

    # create a new channel
    ntor, material = ntor_get(answer)
    data = json.dumps(dict(ntor=ntor))
    headers = {'Content-Type': 'application/json'}
    rq = requests.post(base_url + '/channels', data=data, headers=headers)

    # parse the id, path and ntor
    assert rq.status_code == 201
    answer = json.loads(rq.text)
    uid, ntor, path = answer['id'], answer['ntor'], answer['path']

    # finish the ntor handshake
    material = ntor_finish(ntor, material)

    # destroy the channel
    rq = requests.delete(base_url + '/channels/{}'.format(uid))
    assert rq.status_code == 202

    import pdb
    pdb.set_trace()
