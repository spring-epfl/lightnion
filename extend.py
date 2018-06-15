import io
import base64
import random

import stem
import stem.client.datatype
import curve25519

import hop
import ntor_ref
import create

def build_extend2_hshake(handshake_data):
    from stem.client.datatype import Size

    payload = io.BytesIO()
    payload.write(Size.SHORT.pack(0x0002)) # (ntor handshake only!)
    payload.write(Size.SHORT.pack(len(handshake_data)))
    payload.write(handshake_data)
    return payload.getvalue()

def build_extend2_header(link_specifiers=([], []), sanity=True):
    from stem.client.datatype import Size

    addresses, identities = link_specifiers
    nb_specifiers = len(addresses) + len(identities)

    payload = io.BytesIO()
    payload.write(Size.CHAR.pack(nb_specifiers))
    for address in addresses:
        ip, port = address

        field = io.BytesIO()
        field.write(Size.CHAR.pack(0x00 if ip.type_int == 4 else 0x01))
        field.write(Size.CHAR.pack(0x06 if ip.type_int == 4 else 0x12))
        field.write(ip.value_bin)
        field.write(Size.SHORT.pack(port))
        field = field.getvalue()

        if sanity:
            assert len(field) == (1 + 1 + (4 if ip.type_int == 4 else 16) + 2)

        payload.write(field)

    for identity in identities:
        is_ed25519 = (len(identity) == 32)

        field = io.BytesIO()
        field.write(Size.CHAR.pack(0x02 if not is_ed25519 else 0x03))
        field.write(Size.CHAR.pack(0x14 if not is_ed25519 else 0x20))
        field.write(identity)
        field = field.getvalue()

        if sanity:
            assert len(field) == (1 + 1 + (20 if not is_ed25519 else 32))

        payload.write(field)

    return payload.getvalue()

def build_extend2_payload(handshake, addresses=[], identities=[], sanity=True):
    for idx, address in enumerate(addresses):
        if isinstance(address, str):
            address = tuple(address.split(':', 1))

        ip, port = address
        if not isinstance(ip, stem.client.datatype.Address):
            ip = stem.client.datatype.Address(ip)
        if not isinstance(port, int):
            port = int(port)

        if sanity:
            assert 0 < port < 2**16

        addresses[idx] = (ip, port)

    if sanity:
        assert 0 <= len(identities) <= 2 # at most one legacy and one ed25519

    for idx, identity in enumerate(identities):
        try:
            if isinstance(identity, str):
                identities[idx] = base64.b64decode(identity + '====')
        except BaseException:
            pass

    if sanity:
        assert all([len(i) in [20, 32] for i in identities]) # legacy|ed25519
        assert any([len(i) == 32 for i in identities]) # at least one ed25519

    header = build_extend2_header((addresses, identities), sanity)
    hshake = build_extend2_hshake(handshake)
    return header + hshake

def circuit(state, identity, descriptor, sanity=True):
    link_socket, link_version = state.link
    circuit_id, _ = state.circuit
    rollback = state.clone()

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

    payload = build_extend2_payload(hdata,
        [(addr, port)], [identity, eidentity], sanity)
    rollback, nbytes = hop.send(rollback, 'RELAY_EXTEND2', payload, 0)

    if nbytes is None:
        return state, None

    rollback, answer = hop.recv(rollback)
    if not answer:
        return state, None

    if sanity:
        assert len(answer) == 1
        assert isinstance(answer[0], stem.client.cell.RelayCell)
        assert answer[0].command == 'RELAY_EXTENDED2'

    created = stem.client.cell.Created2Cell._unpack(
        answer[0].data, circuit_id, link_version)

    raw_material = ntor_ref.client_part2(eph_key, created.data, identity,
        donna_onion_key, keyBytes=92)

    key_material = create.ntor_key_material(raw_material, sanity)
    rollback.wrap(onion.state(state.link, (circuit_id, key_material)))

    return rollback, rollback.depth()

if __name__ == '__main__':
    import link
    import create
    import onion
    import argparse

    import descriptors
    import consensus

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = link.handshake(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link[1], link[0]))

    # Create a single-hop fast circuit to access the directory through it
    circ = create.fast(link)
    print('Circuit {} created – Key hash: {}'.format(circ[0],
        circ[1].key_hash.hex()))

    # Download our first hop's descriptor
    state = onion.state(link, circ)
    state, lsid, authority = descriptors.download_authority(state)

    # Download a consensus
    state, lsid, cons = consensus.download(state, flavor='unflavored',
        last_stream_id=lsid)

    # Randomly pick few nodes (!! NOT a sane behavior, only to showcase API !!)
    further_hops = []
    circuit_length = random.randint(2, 7) # (random circuit length to showcase)
    random.shuffle(cons['routers'])
    for router in cons['routers']:
        if len(further_hops) == circuit_length:
            break
        if router['digest'] == authority['digest']: # don't pick our first hop
            continue

        # Retrieve its descriptor
        state, lsid, nhop = descriptors.download(state, cons=router,
            flavor='unflavored', last_stream_id=lsid)
        nhop = nhop[0] # (expect only one entry with a matching digest)

        # Skip the entry if digests do not match (note: already sanity checked)
        if router['digest'] != nhop['digest']:
            continue

        # Skip if not ed25519 identity key available
        if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
            continue

        # Keep the identity fingerprint for later (ntor) and the descriptor
        further_hops.append((router['identity'], nhop))

    # Create a brand new circuit (to have spare RELAY_EARLY to extend it)
    ext_circ = create.fast(link, circuits=[circ[0]])
    print('Circuit {} created – Key hash: {}\n'.format(ext_circ[0],
        ext_circ[1].key_hash.hex()))

    ext_state = onion.state(link, ext_circ)
    for identity, nhop in further_hops:
        print('Extending to {}:'.format(nhop['router']['nickname']))
        print(' - remaining RELAY_EARLY cells: {}'.format(ext_state.early))

        ext_state, depth = circuit(ext_state, identity, nhop)
        print(' - circuit extended, new depth: {}'.format(depth))

    print('\nChecking...')
    ext_state, lsid, nauth = descriptors.download_authority(ext_state)
    print("- endpoint's descriptor ({}) retrieved at depth {}!".format(
        nauth['router']['nickname'], ext_state.depth()))

    ext_state, lsid, ncons = consensus.download(ext_state, last_stream_id=lsid)
    print("- micro-consensus (with {} nodes) retrieved at depth {}!".format(
        len(ncons['routers']), ext_state.depth()))

