import link_protocol

import stem
import stem.client.cell
import stem.client.datatype

def create_fast(link, circuits=[], sanity=True):
    """
    We replicate here a one-hop circuit creation with CREATE_FAST:
     - https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1129

    The expected transcript from the point of view of a "client" is:

                   (... perform a proper link handshake here ...)

               Onion Proxy (client)              Onion Router (server)


               /   [7] :------ CREATE_FAST¹ -------> [ 8]
               |   [9] <------ CREATED_FAST -------: [10]
               |
               |      Shared circuit key (via KDF-TOR²)
               |
               \\

    ¹The initiator picks an available circuit ID (also called CircID) with its
     most significant bit equal to:
        - for v3-or-lower links, 1 iff the initiator has the "lower" key, or
          else any value iff the initiator has no key.
        - for v4-or-higher links, 1 iff the node is the initiator.

     Note that in practice, "dumb" clients with no public key can always do the
     v4-or-higher behavior – setting the most significant bit to 1:
        https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L931

     Note that we still need to take into account the different sizes of IDs:
        https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L915

     Note that zero is a reserved CircID for off-circuit cells:
        https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L935


    ²The KDF-TOR derivation function is only to be used in CREATE_FAST, the
     legacy "Tor Authentication Protocol" handshakes & hidden services. Its
     successor (KDF-RFC5869) is to be used elsewhere.

     About TAP (Tor Authentication Protocol), see:
        https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1015

     About KDF-TOR, see:
        https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1164


    After establishing a circuit via a CREATE_FAST "handshake", we can extend
    the circuit with a EXTEND(2) "handshake" encapsulated in RELAY_EARLY cells.

    Note that CREATE_FAST may be disabled in published consensus OR status:
     - https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L1905

    :param tuple link: a tuple (link socket, link version). See: link.establish
    :param list circuits: a list of pre-existing circuit ID (default: []).
    :param bool sanity: performs extra sanity checks (default: False).

    :returns: a tuple (circuit ID, circuit shared keys)

    """

    link_socket, link_version = link
    circuit_id = 0x80000000 if link_version > 3 else 0x0001 # handle MSB (see¹)

    # [8] Pick an available ID
    while circuit_id in circuits:
        circuit_id += 1

    # [8] Extra sanity checks – bound checks on unlikely invalid values.
    if sanity:
        if link_version > 3 and not (0x100000000 > circuit_id > 0):
            return None, None
        if link_version < 4 and not (0x10000 > circuit_id > 0):
            return None, None

    # [8:9] Send CREATE_FAST cell – contains OP's randomness (key material).
    create_scell = stem.client.cell.CreateFastCell(circuit_id)
    link_socket.send(create_scell.pack(link_version))

    # [9:10] Retrieve the 2nd part of the handshake – contains OR's randomness.
    answer = link_socket.recv()
    if not answer:
        return None, None
    created_rcell = None

    # [9:10] We're being strict here – we don't handle concurrent circuits:
    #   1. Receive one pending cell.
    #   2. Aborts if this cell do not belong to our circuit.
    #   3. Aborts if this cell is not a CREATED_FAST cell.
    #
    if sanity:
        created_rcell, _ = stem.client.cell.Cell.pop(answer, link_version)
        if created_rcell.circ_id != circuit_id:
            return None, None
        if not isinstance(created_rcell, stem.client.cell.CreatedFastCell):
            return None, None
    #
    # [9:10] We're sticking to stem's client behavior here:
    #   1. Receive all pending cells.
    #   2. Filter out cells that are not in our circuit (extra check here).
    #   3. Filter out cells that are not a CREATED_FAST cell.
    #   4. Picks the first listed candidate.
    #
    else:
        received_cells = stem.client.cell.Cell.unpack(answer, link_version)
        circuit_rcells = [c for c in received_cells if c.circ_id != circuit_id]
        created_rcells = [c for c in circuit_rcells if isinstance(c,
            stem.client.cell.CreatedFastCell)]

        if len(created_rcells) < 1:
            return None, None
        created_rcell = created_rcells[0] # (expecting only one CREATED_FAST)

    # [10] Here we're using stem's client to do the heavy lifting.
    key_material = stem.client.datatype.KDF.from_value(
        create_scell.key_material + created_rcell.key_material)

    # [10] Confirm that key hashes match between us & the OR.
    if key_material.key_hash != created_rcell.derivative_key:
        return None, None

    return (circuit_id, key_material)

if __name__ == "__main__":
    link = link_protocol.establish()
    print('Link v{} established – {}'.format(link[1], link[0]))

    print('\nCreating 10 one-hop circuits with CREATED_FAST cells:')
    circuits = []
    for i in range(10):
        circuit = create_fast(link, [c[0] for c in circuits])
        print(' {:2}. Circuit {} created – Key hash: {}'.format(i + 1,
            circuit[0], circuit[1].key_hash.hex()))

        circuits.append(circuit)
