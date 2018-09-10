import collections
import requests
import json

headers = {'Content-Type': 'application/json'}

import lighttor as ltor
import lighttor.proxy

from . import polling, websocket, ntor

class channel(collections.namedtuple('channel',
    ['id', 'guard', 'middle', 'exit'])):
    pass

def client(host, port=80, *, io, prefix='http', failures=5, **kwargs):
    base_url = '{}://{}:{}{}'.format(prefix, host, port, ltor.proxy.base_url)

    guard = None
    try:
        code = 503
        fails = 0
        for _ in range(failures):
            rq = requests.get(base_url + '/guard')
            if not rq.status_code in [200, 503]:
                raise RuntimeError('Error code: {}'.format(rq.status_code))

            code = rq.status_code
            if fails > failures or not code == 503:
                break

            fails += 1

        if code == 503:
            raise RuntimeError('Too many failures!')

        guard = json.loads(rq.text)

    except BaseException as e:
        raise RuntimeError(
            'Unable retrieve guard at endpoint {}, reason: {}'.format(
                base_url + '/guard', e))

    handshake, material, uid, path = (None, None, None, None)
    try:
        code = 503
        fails = 0
        for _ in range(failures):
            handshake, material = ntor.hand(guard)
            data = json.dumps(dict(ntor=handshake))

            rq = requests.post(base_url + '/channels',
                data=data, headers=headers)
            if not rq.status_code in [201, 503]:
                raise RuntimeError('Error code: {}'.format(rq.status_code))

            code = rq.status_code
            if fails > failures or not code == 503:
                break

            fails += 1

        if code == 503:
            raise RuntimeError('Too many failures!')

        data = json.loads(rq.text)
        uid, handshake, path = data['id'], data['ntor'], data['path']

    except BaseException as e:
        raise RuntimeError(
            'Unable create channel at endpoint {}, reason: {}'.format(
                base_url + '/channels', e))

    state = None
    try:
        try:
            handshake = ntor.shake(handshake, material)
        except TypeError:
            raise RuntimeError('Invalid ntor cryptographic material?')

        io = io(endpoint=base_url + '/channels/' + uid, **kwargs)
        link = ltor.link.link(io, version='http')

        circuit = ltor.create.circuit(ltor.proxy.fake_circuit_id, handshake)
        link.register(circuit)

        state = ltor.onion.state(link, circuit)

    except BaseException as e:
        raise RuntimeError(
            'Unable craft local state with {}, reason: {}'.format(io, e))

    try:
        state = ltor.extend.circuit(state, path[0])

    except BaseException as e:
        raise RuntimeError(
            'Unable extend the circuit to middle node {}, reason: {}'.format(
                path[0]['router']['nickname'], e))

    try:
        state = ltor.extend.circuit(state, path[1])

    except BaseException as e:
        raise RuntimeError(
            'Unable extend the circuit to exit node {}, reason: {}'.format(
                path[0]['router']['nickname'], e))

    return state, channel(uid, guard, path[0], path[1])
