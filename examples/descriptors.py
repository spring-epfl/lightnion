import lightnion as lnn

import argparse
import pdb

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = lnn.link.initiate(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link.version, link.io))

    endpoint = lnn.create.fast(link)
    print('Circuit {} created – Key hash: {}'.format(endpoint.circuit.id,
        endpoint.circuit.material.key_hash.hex()))

    # downloading descriptors
    endpoint, descriptors = lnn.descriptors.download(endpoint)
    endpoint, undescriptors = lnn.descriptors.download(endpoint,
        flavor='unflavored')

    # matching fields of microdescriptors against unflavored one
    by_key = {d['ntor-onion-key']: d for d in descriptors}
    skipped = []
    for udesc in undescriptors:
        if udesc['ntor-onion-key'] not in by_key:
            print('Missing {} (skipped)'.format(udesc['ntor-onion-key']))
            skipped.append(udesc)
            continue

        desc = by_key[udesc['ntor-onion-key']]
        for key, value in desc.items():
            if key == 'policy' and udesc[key]['type'] == 'exitpattern':
                continue # TODO: match exitpatterns against policy summary

            if key in ['micro-digest', 'digest', 'flavor']:
                continue # TODO: match digests against consensus

            if key not in udesc and key == 'identity':
                continue # TODO: check if missing 'identity' key here is sound

            if not isinstance(value, dict):
                if not value == udesc[key]:
                    pdb.set_trace()
            else:
                for skey, svalue in value.items():
                    if not udesc[key][skey] == svalue:
                        pdb.set_trace()

    print('\nReady to use {} descriptors!'.format(len(descriptors)))
    for idx, d in enumerate(descriptors):
        if idx > 10 and idx < len(descriptors) - 10:
            if idx == 11:
                print(' - [...]')
            continue
        print(' - ntor-onion-key: {}'.format(d['ntor-onion-key']))

    # asking politely for our OR's descriptor
    endpoint, authority = lnn.descriptors.download_authority(endpoint)

    print('\nWe are connected to the following node:')
    print(' - ntor-onion-key: {}'.format(authority['ntor-onion-key']))
    print(' - identity: {} ({})'.format(
        authority['identity']['master-key'], authority['identity']['type']))

    print('\nSummary:')
    print(' - {} unflavored descriptors'.format(len(descriptors)))
    print(' - {} micro-descriptors'.format(len(undescriptors)))
    print(' - {} orphaned ntor-onion-key'.format(len(skipped)))
