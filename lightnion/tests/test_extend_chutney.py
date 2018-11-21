import lightnion as lnn


def test_circuit():
    import random

    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # Download our first hop's descriptor
    endpoint, authority = lnn.descriptors.download_authority(endpoint)

    # Download a consensus
    endpoint, cons = lnn.consensus.download(endpoint, flavor='unflavored')

    # Randomly pick few nodes (!! NOT a sane behavior, only to showcase API !!)
    further_hops = []
    circuit_length = random.randint(2, 7)  # (random circuit length to showcase)

    random.shuffle(cons['routers'])
    for router in cons['routers']:
        if len(further_hops) == circuit_length:
            break

        # Skip our first node & already picked ones (no loop)
        if router['digest'] == authority['digest']:
            continue
        if router['digest'] in [h['digest'] for h in further_hops]:
            continue

        # Skip nodes that are not 'Fast' and 'Stable'
        if 'Fast' not in router['flags'] or 'Stable' not in router['flags']:
            continue

        # Skip nodes with old Tor versions
        if not router['version'].startswith('Tor 0.3.'):
            continue

        # Retrieve its descriptor
        endpoint, nhop = lnn.descriptors.download(
            endpoint, cons=router, flavor='unflavored')
        nhop = nhop[0]  # (expect only one entry with a matching digest)

        # Skip the entry if digests do not match (note: double-check here)
        if router['digest'] != nhop['digest']:
            continue

        # Skip if no ed25519 identity key available
        if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
            continue

        # Keep the descriptor for later (to build the circuit)
        further_hops.append(nhop)

    # Create a brand new circuit (to have spare RELAY_EARLY to extend it)
    endpoint = lnn.create.fast(link)

    for nhop in further_hops:
        # Extending to nhop['router']['nickname']:
        # - remaining RELAY_EARLY: endpoint.early_count
        endpoint = lnn.extend.circuit(endpoint, nhop)

    endpoint, authority = lnn.descriptors.download_authority(endpoint)
    endpoint, ncons = lnn.consensus.download(endpoint, cache=False)

    assert True
