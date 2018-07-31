import collections
import base64

import lighttor as ltor

# import stem
# import stem.client.cell
# import stem.client.datatype
# import curve25519

# import ntor_ref

def ntor_key_material(raw_material, sanity=True):
    if sanity:
        assert len(raw_material) == (20 + 20 + 16 + 16 + 20)

    # Modernized KDF for ntor handshakes, see:
    #   https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1193
    #
    # Order of the fields when deriving material, see:
    #   https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1210
    #
    key_material = stem.client.datatype.KDF(
        raw_material[72:],      # KH or key_hash / {DIGEST,HASH}_LEN (20) bytes
        raw_material[:20],      # Df or forward_digest / HASH_LEN (20) bytes
        raw_material[20:40],    # Db or backward_digest / HASH_LEN (20) bytes
        raw_material[40:56],    # Kf or forward_key / KEY_LEN (16) bytes
        raw_material[56:72])    # Kb or backward_key / KEY_LEN (16) bytes

    return key_material

class circuit(collections.namedtuple('circuit', ['id', 'material'])):
    pass

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

    :returns: a tuple (circuit id, shared key material)

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

    # Receive CREATED_FAST cell (contains OR material and key confirmation)
    link.register(circuit_id)

    or_cell = ltor.cell.created_fast.cell(link.get(circuit_id))
    if not or_cell.valid:
        link.unregister(circuit_id)
        raise RuntimeError('Got invalid CREATED_CELL: {}'.format(or_cell.raw))

    # Compute KDF-TOR on OP+OR materials
    material = ltor.crypto.kdf_tor(
        op_cell.create_fast.material + or_cell.created_fast.material)

    # Confirm shared derived material
    if not material.key_hash == or_cell.created_fast.derivative:
        raise RuntimeError(
            'Invalid CREATE_FAST, invalid KDF-TOR confirmation: '.format(
                (material.key_hash, or_cell.created_fast.derivative)))

    return circuit(circuit_id, material)

def ntor(link, identity, onion_key, circuits=[], sanity=True):

    # Expect the hash of node's identity as 20 bytes or as some base64
    try:
        if isinstance(identity, str):
            identity = base64.b64decode(identity + '====')
            assert len(identity) == 20 # base64 encoded NODE_ID_LENGTH bytes
    except BaseException:
        pass

    # Expect the node's ed25519 ntor-onion-key as 32 bytes or as some base64
    try:
        if isinstance(onion_key, str):
            onion_key = base64.b64decode(onion_key + '====')
            assert len(onion_key) == 32 # base64 encoded KEYID_LENGTH bytes
    except BaseException:
        pass

    # ¹(see create.fast for details on redundant parts)
    link_socket, link_version = link

    # (pick an available circuit_id)¹
    circuit_id = 0x80000000 if link_version > 3 else 0x0001
    while circuit_id in circuits:
        circuit_id += 1

    # (extra useless checks)¹
    if sanity:
        if link_version > 3 and not (0x100000000 > circuit_id > 0):
            return None, None
        if link_version < 4 and not (0x10000 > circuit_id > 0):
            return None, None

    # Perform the first part of our handshake
    donna_onion_key = curve25519.keys.Public(onion_key)
    ephemeral_key, payload = ntor_ref.client_part1(identity, donna_onion_key)

    # Build a CREATE2 cell containing this first handshake part
    create_scell = stem.client.cell.Create2Cell(circuit_id, hdata=payload)
    link_socket.send(create_scell.pack(link_version))

    # Receive answers
    answer = link_socket.recv()
    if not answer:
        return None, None
    created_rcell = None

    # (retrieve the cell)¹
    if sanity:
        created_rcell, _ = stem.client.cell.Cell.pop(answer, link_version)
        if created_rcell.circ_id != circuit_id:
            return None, None
        if not isinstance(created_rcell, stem.client.cell.Created2Cell):
            return None, None
    else:
        received_cells = stem.client.cell.Cell.unpack(answer, link_version)
        circuit_rcells = [c for c in received_cells if c.circ_id != circuit_id]
        created_rcells = [c for c in circuit_rcells if isinstance(c,
            stem.client.cell.Created2Cell)]

        if len(created_rcells) < 1:
            return None, None
        created_rcell = created_rcells[0] # (expecting only one CREATED2)

    # After receiving the 2nd part of the handshake, finish it on our side...
    #   ...enabling us to retrieve shared (derived) key material.
    #
    raw_material = ntor_ref.client_part2(ephemeral_key, created_rcell.data,
        identity, donna_onion_key, keyBytes=92)

    key_material = ntor_key_material(raw_material, sanity)
    return (circuit_id, key_material)

if __name__ == "__main__":
    import link
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('flavor', choices={'both', 'fast', 'ntor'})
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    # (import extra pieces if we're going to test more than CREATE_FAST)
    if sys_argv.flavor in ['both', 'ntor']:
        import consensus    # (to download the consensus)
        import descriptors  # (to download some descriptors)
        import onion        # (to handle cryptographic statefulness)

    # First establish a link where we'll build circuits.
    #
    link = link.handshake(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link[1], link[0]))

    # Simple creation of one-hop circuits with CREATE_FAST cells:
    #   - no public keys involved (only exchanging randomness through TLS).
    #   - used in Tor to connects to the guard (the first hop) to reduce load.
    #
    circuits = []
    if sys_argv.flavor in ['both', 'fast']:
        print('\nCreating 10 one-hop circuits with CREATE_FAST cells:')
        for i in range(10):
            circuit = fast(link, [c[0] for c in circuits])
            print(' {:2}. Circuit {} created – Key hash: {}'.format(i + 1,
                circuit[0], circuit[1].key_hash.hex()))

            circuits.append(circuit)

    # Creation of one-hop circuits with CREATE2 cells & ntor (ECDH) handshakes:
    #   - we retrieve public keys in consensus & descriptors.
    #   - we use a one-hop CREATE_FAST circuit to do so (for showcase).
    #   - Tor clients rarely (never) connects to guard with ntor handshakes.
    #
    state = (0, None)
    if sys_argv.flavor in ['both', 'ntor']:
        print('\nCreating 10 one-hop circuits with CREATE2 cells:')

        # (create a fast circuit if none available from the previous step)
        if len(circuits) == 0:
            circuits.append(fast(link))
            print(' - (created one circuit with a CREATE_FAST cell'
                + 'to retrieve descriptors)')

        # Download our OR's descriptor
        state = onion.state(link, circuits[-1])
        state, lsid, authority = descriptors.download_authority(state)

        # Download an unflavored consensus
        state, lsid, unconsensus = consensus.download(state,
            flavor='unflavored', last_stream_id=lsid)

        # Find our OR into the consensus – TODO: validate consensus signatures
        for router in unconsensus['routers']:
            if router['digest'] == authority['digest']:
                break

        # Create some ntor-ish circuits with CREATE2 cells (only for showcase)
        for i in range(10):
            #                      (don't forget to provide public keys!)
            circuit = ntor(link, #  v
                router['identity'], authority['ntor-onion-key'],
                [c[0] for c in circuits])

            circuits.append(circuit)
            print(' {:2}. Circuit {} created – Key hash: {}'.format(i + 1,
                circuit[0], circuit[1].key_hash.hex()))

    if sys_argv.flavor in ['both', 'ntor']:
        digest = None
        print('\nChecking if all {} circuits works:'.format(len(circuits)))
        for c in circuits:
            if c[0] != state.circuit[0]:
                s = onion.state(link, c)
            else:
                s = state
            #   ^
            # (don't create a second state for an already-used circuit...

            #  ...and do not reuse a stream_id on such already-used circuit)
            #  v
            s, lsid, authority = descriptors.download_authority(s,
                last_stream_id=(0 if c[0] != state.circuit[0] else 1))

            if authority is None:
                print(" - Circuit {} doesn't work.".format(c[0]))
                continue
            print(" - Circuit {} works!".format(c[0]))

            if digest is not None and authority['digest'] != digest:
                print('!! Mismatched digest: {}\n'.format(authority['digest']))

