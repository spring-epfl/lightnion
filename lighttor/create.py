import collections
import base64
import queue

import lighttor as ltor

class circuit(collections.namedtuple('circuit', ['id', 'material'])):
    stream_windows = None # per-stream window (see onion._auto_sendme hack)
    last_stream_id = 0
    destroyed = False
    window = None # per-circuit window (see onion._auto_sendme hack)
    reason = None
    queue = None

    def put(self, payload):
        return self.queue.put(payload)

    def get(self, block=True):
        return self.queue.get(block=block)

def fast(link):
    """Use a CREATE_FAST cell to initiate a one-hop circuit.

    The expected transcript is:

              (... perform a proper link handshake here ...)

           Onion Proxy (client)              Onion Router (server)

               /  [ 7] :------ CREATE_FAST¹ -------> [8]
               |  [10] <------ CREATED_FAST -------: [9]
               |
               |      Shared circuit key (via KDF-TOR²)
               \

    ¹The initiator picks an available circuit ID (CircID) with its most
     significant bit equal to 1 (v4-or-higher links).

    :param link: a link.link object, see: link.initiate

    :returns: a onion.state object, see: onion.state
    """

    # Pick an available ID (link version > 3)
    circuit_id = 0x80000000
    while circuit_id in link.circuits:
        circuit_id += 1

    # Sanity checks
    try:
        packed = ltor.cell.view.uint(4).write(value=circuit_id)
        assert circuit_id == ltor.cell.view.uint(4).value(packed)
    except (OverflowError, AssertionError):
        raise RuntimeError('Erroneous circuit ID: {} ({})'.format(
            circuit_id, packed))

    # Send CREATE_FAST cell (contains OP material)
    op_cell = ltor.cell.create_fast.pack(circuit_id)
    link.send(op_cell)

    # (register a dummy circuit first to reuse the circuit API)
    dummy = circuit(circuit_id, None)
    link.register(dummy)

    # Receive CREATED_FAST cell (contains OR material and key confirmation)
    try:
        or_cell = ltor.cell.created_fast.cell(link.get(dummy))
    except KeyError:
        raise RuntimeError('Got DESTROY cell while creating circuit.')

    # (unregister the dummy circuit before validation/material confirmation)
    link.unregister(dummy)
    if not or_cell.valid:
        raise RuntimeError('Got invalid CREATED cell: {}'.format(or_cell.raw))

    # Compute KDF-TOR on OP+OR materials
    material = ltor.crypto.kdf_tor(
        op_cell.create_fast.material + or_cell.created_fast.material)

    # Confirm shared derived material
    if not material.key_hash == or_cell.created_fast.derivative:
        raise RuntimeError(
            'Invalid CREATE_FAST, invalid KDF-TOR confirmation: '.format(
                (material.key_hash, or_cell.created_fast.derivative)))

    # Register the real circuit
    final = circuit(circuit_id, material)
    link.register(final)

    return ltor.onion.state(link, final)

def ntor(link, descriptor):
    # Late imports (as this function is for testing purposes)
    import curve25519
    import lighttor.ntor_ref as ntor_ref

    identity = base64.b64decode(descriptor['router']['identity'] + '====')
    onion_key = base64.b64decode(descriptor['ntor-onion-key'] + '====')

    # Pick an available ID (link version > 3)
    circuit_id = 0x80000000
    while circuit_id in link.circuits:
        circuit_id += 1

    # Sanity checks
    try:
        packed = ltor.cell.view.uint(4).write(value=circuit_id)
        assert circuit_id == ltor.cell.view.uint(4).value(packed)
    except (OverflowError, AssertionError):
        raise RuntimeError('Erroneous circuit ID: {} ({})'.format(
            circuit_id, packed))

    # Perform the first part of our handshake
    donna_onion_key = curve25519.keys.Public(onion_key)
    ephemeral_key, payload = ntor_ref.client_part1(identity, donna_onion_key)

    # Build a CREATE2 cell containing this first handshake part
    link.send(ltor.cell.create2.pack(circuit_id, payload))

    # (register a dummy circuit first to reuse the circuit API)
    dummy = circuit(circuit_id, None)
    link.register(dummy)

    # Receive answers
    try:
        cell = ltor.cell.created2.cell(link.get(dummy))
    except KeyError:
        raise RuntimeError('Got DESTROY cell while creating circuit.')

    # (unregister the dummy circuit before validation/material confirmation)
    link.unregister(dummy)
    if not cell.valid:
        raise RuntimeError('Got invalid CREATED2 cell: {}'.format(cell.raw))

    # Perform the last part of our handshake
    material = ntor_ref.client_part2(ephemeral_key, cell.created2.data,
        identity, donna_onion_key, keyBytes=92)

    # Register the real circuit
    final = circuit(circuit_id, ltor.crypto.ntor.kdf(material))
    link.register(final)

    return ltor.onion.state(link, final)
