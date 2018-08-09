import lighttor as ltor
import lighttor.proxy

import argparse
import requests
import json

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('host', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=4990)
    sys_argv = parser.parse_args()

    base_url = 'http://{}:{}{}'.format(
        sys_argv.host, sys_argv.port, ltor.proxy.base_url)

    # retrieve the guard descriptor
    rq = requests.get(base_url + '/guard')

    # parse the guard destriptor
    assert rq.status_code == 200
    answer = json.loads(rq.text)

    # create a new channel
    ntor, material = ltor.proxy.parts.ntor_get(answer)
    data = json.dumps(dict(ntor=ntor))
    headers = {'Content-Type': 'application/json'}
    rq = requests.post(base_url + '/channels', data=data, headers=headers)

    # parse the id, path and ntor
    assert rq.status_code == 201
    answer = json.loads(rq.text)
    uid, ntor, path = answer['id'], answer['ntor'], answer['path']

    # finish the ntor handshake
    material = ltor.proxy.parts.ntor_finish(ntor, material)

    # destroy the channel
    rq = requests.delete(base_url + '/channels/{}'.format(uid))
    assert rq.status_code == 202

    import pdb
    pdb.set_trace()
