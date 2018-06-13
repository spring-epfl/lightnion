import base64

import stem
import stem.client.cell
import stem.client.datatype
import curve25519

import ntor_ref
import consensus

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

def create(link, identity, onion_key, circuits=[], sanity=True):

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

    # ¹(see create_fast.py for details on redundant parts)
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

if __name__ == '__main__':
    import link_protocol
    import circuit_fast
    import onion_parts
    import argparse

    import descriptors

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = link_protocol.handshake(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link[1], link[0]))

    # Create a single-hop fast circuit to access the directory through it
    circuit = circuit_fast.create(link)
    print('Circuit {} created – Key hash: {}'.format(circuit[0],
        circuit[1].key_hash.hex()))

    # Download our OR's descriptor
    state = onion_parts.state(link, circuit)
    state, last_stream_id, authority = descriptors.download_authority(state)

    # Download an unflavored consensus
    state, last_stream_id, cons = consensus.download(state,
        flavor='unflavored', last_stream_id=last_stream_id)

    # Find our OR into the consensus – TODO: validate all the signatures
    for router in cons['routers']:
        if router['digest'] == authority['digest']:
            break

    # Create a ntor-ish circuit (single-hop, only to showcase the API)
    circuit_ntor = create(link,
        router['identity'], authority['ntor-onion-key'],
        [circuit[0]])

    # It's working?
    print('Circuit {} created – Key hash: {}'.format(circuit_ntor[0],
        circuit_ntor[1].key_hash.hex()))

    # Retrieve again first hop's descriptor to check if the circuit works
    state_ntor = onion_parts.state(link, circuit_ntor)
    state_ntor, lsid, authority = descriptors.download(state_ntor,
        cons=router, flavor='unflavored') # (retrieve only one entry this time)

    # It is working!
    assert authority[0]['digest'] == router['digest']
    print(('\nDirectory successfully reached through ntor-created circuit {}!'
        ).format(circuit_ntor[0]))
