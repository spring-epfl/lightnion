import lightnion as lnn

import argparse

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = lnn.link.initiate(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link.version, link.io))

    endpoint = lnn.create.fast(link)
    print('Fast circuit {} created – Key hash: {}'.format(
            endpoint.circuit.id, endpoint.circuit.material.key_hash.hex()))

    print('\nRetrieve cryptographic material through fast circuit...')
    endpoint, authority = lnn.descriptors.download_authority(endpoint)

    print('Perform "ntor" handshake with {}:'.format(
        authority['router']['nickname']))
    endpoint = lnn.create.ntor(link, authority)
    print(' - Success! (circuit_id: {}, key_hash: {})'.format(
        endpoint.circuit.id, endpoint.circuit.material.key_hash.hex()))

    print('Attempt to use the "ntor" circuit...')
    endpoint, descriptor = lnn.descriptors.download_authority(endpoint)
    if descriptor['digest'] == authority['digest']:
        print(' - Success!')
