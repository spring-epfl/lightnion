import lighttor as ltor

import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = ltor.link.initiate(sys_argv.addr, sys_argv.port)
    print('Link v{} established – {}'.format(link.version, link.io))
    link.close()
