import lightnion as lnn

import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = lnn.link.initiate(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link.version, link.io))

    endpoint = lnn.create.fast(link)
    print('Circuit {} created – Key hash: {}'.format(endpoint.circuit.id,
        endpoint.circuit.material.key_hash.hex()))

    def pretty_print(consensus):
        print('Summary for "{}" consensus:'.format(consensus['flavor']))
        print(' - {} http headers'.format(len(consensus['http']['headers'])))
        print(' - {} dir. sources'.format(len(consensus['dir-sources'])))
        print(' - {} nodes listed'.format(len(consensus['routers'])))
        print(' - {} signatures'.format(
            len(consensus['footer']['directory-signatures'])), end='\n')

    # downloading unflavored consensus
    endpoint, unflavored = lnn.consensus.download(endpoint,
        flavor='unflavored')
    pretty_print(unflavored)

    # downloading microdesc consensus
    endpoint, microdesc = lnn.consensus.download(endpoint, flavor='microdesc')
    pretty_print(microdesc)
