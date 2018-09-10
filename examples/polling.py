import lightnion as lnn
import lightnion.proxy
import lightnion.http

import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('host', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=4990)
    parser.add_argument('padding', nargs='?', type=int, default=100)
    sys_argv = parser.parse_args()

    print('Building a HTTP channel powered by polling...')
    endpoint = sys_argv.host, sys_argv.port
    state, channel = lnn.http.client(*endpoint, io=lnn.http.polling.io)

    print('Success!\n\nChannel {} opened with:'.format(channel.id))
    print(' - Guard is {}'.format(channel.guard['router']['nickname']))
    print(' - Middle is {}'.format(channel.middle['router']['nickname']))
    print(' - Exit is {}\n'.format(channel.exit['router']['nickname']))

    # send bunch of padding
    for i in range(sys_argv.padding):
        print('Send padding: {}/{}'.format(i+1, sys_argv.padding), end='\r')
        state = lnn.hop.send(state, lnn.cell.relay.cmd.RELAY_DROP)
    print('')

    # retrieve something
    state, authority = lnn.descriptors.download_authority(state)
    print('\nSuccessfully retrieved exit node descriptor through channel.')

    # retrieve something heavier
    state, authority = lnn.consensus.download(state, cache=False)
    print('Successfully retrieved full consensus through channel.')

    # destroy the channel
    state.link.close()
    print('Successfully destroyed HTTP channel.')
