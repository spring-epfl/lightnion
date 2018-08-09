import lighttor as ltor
import lighttor.auto

import multiprocessing
import argparse
import queue

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    parser.add_argument('target', nargs='?', type=int, default=32)
    parser.add_argument('tor_local', nargs='?', type=int, default=1)
    parser.add_argument('control_port', nargs='?', type=int, default=9051)
    sys_argv = parser.parse_args()

    link = ltor.link.initiate(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link.version, link.io))

    endpoint = ltor.create.fast(link)
    print('Circuit {} created – Key hash: {}'.format(endpoint.circuit.id,
        endpoint.circuit.material.key_hash.hex()))

    print('Downloading a consensus for later use.')
    endpoint, consensus = ltor.consensus.download(endpoint,
        flavor='unflavored')

    print('Closing the link now.')
    link.close()

    if sys_argv.tor_local == 1:

        # here, we do it manually to pass a nice debug print
        print('\nCreating a local, ephemeral Tor node (via stem)...')
        tor = ltor.auto.path.get_tor(
            msg_handler=lambda line: print(' ' * 4, line))

        print('\nFetching paths now...'.format(sys_argv.target))
        producer = ltor.auto.path.fetch(tor_process=tor)
    else:
        print('\nFetching at least {} paths now.'.format(sys_argv.target))
        producer = ltor.auto.path.fetch(sys_argv.target, tor_process=False,
            control_port=sys_argv.control_port)

    # retrieve the required number of paths
    paths = []
    while not producer.dead and len(paths) < sys_argv.target:
        paths.append(producer.get())
        print(' - {}/{} paths'.format(len(paths), sys_argv.target), end='\r')

    print('\n(now closing the path producer)\n')
    producer.close()

    # convert (fingerprint, nickname) into a full consensus entry
    guard = producer.guard
    guard, paths = ltor.auto.path.convert(guard, paths, consensus=consensus)

    print('With guard {}: {}'.format(guard['nickname'], guard['digest']))
    for middle, exit in paths:
        print(' - {} -> {}'.format(middle['nickname'], exit['nickname']))
        print('     - mid. node digest:', middle['digest'])
        print('     - exit node digest:', exit['digest'])
