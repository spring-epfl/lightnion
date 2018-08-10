import lighttor as ltor
import lighttor.proxy
import lighttor.http

import argparse
import requests
import json

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('host', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=4990)
    sys_argv = parser.parse_args()

    print('Building a HTTP channel using polling API...')
    endpoint = sys_argv.host, sys_argv.port
    state, channel = ltor.http.client(*endpoint, io=ltor.http.polling.io)

    print('Success!\n\nChannel {} opened with:'.format(channel.id))
    print(' - Guard is {}'.format(channel.guard['router']['nickname']))
    print(' - Middle is {}'.format(channel.middle['router']['nickname']))
    print(' - Exit is {}'.format(channel.exit['router']['nickname']))

    # retrieve something
    state, authority = ltor.descriptors.download_authority(state)
    print('\nSuccessfully retrieved exit node descriptor through channel.')

    # retrieve something heavier
    state, authority = ltor.consensus.download(state, cache=False)
    print('Successfully retrieved full consensus through channel.')

    # destroy the channel
    state.link.close()
    print('Successfully destroyed HTTP channel.')
