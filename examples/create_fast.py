import lightnion as lnn

import argparse

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = lnn.link.initiate(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link.version, link.io))

    # Simple creation of one-hop circuits with CREATE_FAST cells:
    #   - no public keys involved (only exchanging randomness through TLS).
    #   - used in Tor to connects to the guard (the first hop) to reduce load.
    #
    print('\nCreating 10 one-hop circuits with CREATE_FAST cells:')
    for i in range(10):
        state = lnn.create.fast(link)
        print(' {:2}. Circuit {} created – Key hash: {}'.format(i + 1,
            state.circuit.id, state.circuit.material.key_hash.hex()))
