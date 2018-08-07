import io
import base64
import random

import curve25519

import lighttor as ltor
import lighttor.ntor_ref as ntor_ref

def circuit(state, identity, descriptor):
    # Expect the hash of node's identity as 20 bytes or as some base64
    try:
        if isinstance(identity, str):
            identity = base64.b64decode(identity + '====')
            assert len(identity) == 20 # base64 encoded NODE_ID_LENGTH bytes
    except BaseException:
        pass

    onion_key = base64.b64decode(descriptor['ntor-onion-key'] + '====')
    eidentity = descriptor['identity']['master-key'] # (assuming ed25519 here)
    addr = descriptor['router']['address']
    port = descriptor['router']['orport']

    donna_onion_key = curve25519.keys.Public(onion_key)
    eph_key, hdata = ntor_ref.client_part1(identity, donna_onion_key)

    payload = ltor.cell.relay.extend2.pack(
        hdata, [(addr, port)], [identity, eidentity])

    state = ltor.hop.send(state,
        ltor.cell.relay.cmd.RELAY_EXTEND2, payload.raw, stream_id=0)

    state, cells = ltor.hop.recv(state, once=True)
    if not len(cells) == 1:
        raise RuntimeError('Expected exactly one cell, got: {}'.format(cells))

    if not cells[0].relay.cmd == ltor.cell.relay.cmd.RELAY_EXTENDED2:
        raise RuntimeError('Expected EXTENDED2, got {} here: {}'.format(
            cells[0].relay.cmd, cell.relay.truncated))

    payload = ltor.cell.relay.extended2.payload(cells[0].relay.data)
    if not payload.valid:
        raise RuntimeError('Invalid EXTENDED2 payload: {}'.format(
            payload.truncated))

    raw_material = ntor_ref.client_part2(eph_key, payload.data, identity,
        donna_onion_key, keyBytes=92)

    material = ltor.crypto.ntor.kdf(raw_material)
    extended = ltor.create.circuit(state.circuit.id, material)

    state.wrap(ltor.onion.state(state.link, extended))
    return state
