import lighttor as ltor

import argparse
import random

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = ltor.link.initiate(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link.version, link.io))

    endpoint = ltor.create.fast(link)
    print('Circuit {} created – Key hash: {}'.format(endpoint.circuit.id,
        endpoint.circuit.material.key_hash.hex()))

    # Download our first hop's descriptor
    endpoint, authority = ltor.descriptors.download_authority(endpoint)

    # Download a consensus
    endpoint, cons = ltor.consensus.download(endpoint, flavor='unflavored')

    # Randomly pick few nodes (!! NOT a sane behavior, only to showcase API !!)
    further_hops = []
    circuit_length = random.randint(2, 7) # (random circuit length to showcase)

    print('Building {}-hop circuit (out of {} nodes):'.format(
        circuit_length, len(cons['routers'])))

    random.shuffle(cons['routers'])
    for router in cons['routers']:
        if len(further_hops) == circuit_length:
            break
        if router['digest'] == authority['digest']: # don't pick our first hop
            continue

        # Retrieve its descriptor
        endpoint, nhop = ltor.descriptors.download(
            endpoint, cons=router, flavor='unflavored')
        nhop = nhop[0] # (expect only one entry with a matching digest)

        # Skip the entry if digests do not match (note: already sanity checked)
        if router['digest'] != nhop['digest']:
            continue

        # Skip if not ed25519 identity key available
        if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
            continue

        # Keep the descriptor for later (to build the circuit)
        further_hops.append(nhop)
        print(' - Picked node named {} for {}th hop!'.format(
            nhop['router']['nickname'], len(further_hops)))

    # Create a brand new circuit (to have spare RELAY_EARLY to extend it)
    endpoint = ltor.create.fast(link)
    print('Circuit {} created – Key hash: {}'.format(endpoint.circuit.id,
        endpoint.circuit.material.key_hash.hex()))

    for nhop in further_hops:
        print('Extending to {}:'.format(nhop['router']['nickname']))
        print(' - remaining RELAY_EARLY: {}'.format(endpoint.early_count))

        endpoint = ltor.extend.circuit(endpoint, nhop)
        print(' - circuit extended, new depth: {}'.format(endpoint.depth))

    print('\nChecking...')
    endpoint, authority = ltor.descriptors.download_authority(endpoint)
    print("- endpoint's descriptor ({}) retrieved at depth {}!".format(
        authority['router']['nickname'], endpoint.depth))

    endpoint, ncons = ltor.consensus.download(endpoint)
    print("- micro-consensus (with {} nodes) retrieved at depth {}!".format(
        len(ncons['routers']), endpoint.depth))
