import lighttor as ltor
import lighttor.proxy
import lighttor.http

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


    # get the guard descriptor
    rq = requests.get(base_url + '/guard')
    assert rq.status_code == 200
    guard = json.loads(rq.text)
    print('Guard descriptor retrieved through HTTP: {}'.format(
        guard['router']['nickname']))

    # create a new channel
    ntor, material = ltor.http.ntor.hand(guard)
    data = json.dumps(dict(ntor=ntor))
    headers = {'Content-Type': 'application/json'}
    rq = requests.post(base_url + '/channels', data=data, headers=headers)
    print('New channel (with ntor handshake) created:')

    # parse the id, path and ntor
    assert rq.status_code == 201
    answer = json.loads(rq.text)
    uid, ntor, path = answer['id'], answer['ntor'], answer['path']
    print(' - Got following id: {}'.format(uid))

    # finish the ntor handshake
    material = ltor.http.ntor.shake(ntor, material)

    # create fake objects
    io = ltor.http.polling.io(base_url + '/channels/' + uid)
    link = ltor.link.link(io, version='http')
    circuit = ltor.create.circuit(ltor.proxy.fake_circuit_id, material)
    link.register(circuit)
    state = ltor.onion.state(link, circuit)
    print('\nCreated fake link to reuse internal API.')

    # retrieve something
    state, authority = ltor.descriptors.download_authority(state)
    print('Successfully retrieved guard descriptor through HTTP channel.')

    # extend the circuit
    state = ltor.extend.circuit(state, path[0])
    print('Successfully extended circuit to middle node through HTTP channel.')
    state = ltor.extend.circuit(state, path[1])
    print('Successfully extended circuit to exit node through HTTP channel.')

    # retrieve something
    state, authority = ltor.descriptors.download_authority(state)
    print('Successfully retrieved exit node descriptor through HTTP channel.')

    # retrieve something heavier
    state, authority = ltor.consensus.download(state, cache=False)
    print('Successfully retrieved full consensus through HTTP channel.')

    # destroy the channel
    rq = requests.delete(base_url + '/channels/{}'.format(uid))
    assert rq.status_code == 202
    print('Successfully destroyed HTTP channel.')
