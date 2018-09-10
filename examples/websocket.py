import lightnion as lnn
import lightnion.proxy
import lightnion.http

import argparse
import time

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('method', nargs='?', default='websocket')
    parser.add_argument('nb_downloads', nargs='?', type=int, default=3)
    parser.add_argument('host', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=4990)
    parser.add_argument('padding', nargs='?', type=int, default=100)
    sys_argv = parser.parse_args()

    io_used = dict(
        polling=lnn.http.polling.io,
        websocket=lnn.http.websocket.io)[sys_argv.method] # or 'polling'

    print('Building a HTTP channel powered by {}...'.format(sys_argv.method))
    endpoint = sys_argv.host, sys_argv.port
    state, channel = lnn.http.client(*endpoint, io=io_used)

    print('Success!\n\nChannel {} opened with:'.format(channel.id))
    print(' - Guard is {}'.format(channel.guard['router']['nickname']))
    print(' - Middle is {}'.format(channel.middle['router']['nickname']))
    print(' - Exit is {}\n'.format(channel.exit['router']['nickname']))

    # send bunch of padding
    for i in range(sys_argv.padding):
        print('Send padding: {}/{}'.format(i+1, sys_argv.padding), end='\r')
        state = lnn.hop.send(state, lnn.cell.relay.cmd.RELAY_DROP)
    print('')

    start = time.time()
    for _ in range(sys_argv.nb_downloads):
        # retrieve something
        state, authority = lnn.descriptors.download_authority(state)
        print('\nSuccessfully retrieved exit node descriptor through channel.')

        # retrieve something heavier
        state, _ = lnn.hop.directory_query(state,
            '/tor/status-vote/current/consensus',
            compression='identity') # (no cache nor parsing nor compression)
        print('Successfully retrieved full consensus through channel.')

    # destroy the channel
    state.link.close()
    print('Successfully destroyed HTTP channel.')

    print('\nTotal interactive time: {:.2f}s'.format(time.time() - start))
