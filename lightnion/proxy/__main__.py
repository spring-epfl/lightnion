import lightnion.proxy.forward

import ipaddress
import argparse
import logging
import os

default_auth = '.lightnion-auth.d'

log_format = "%(levelname)s: %(message)s"
log_levels = {None: logging.ERROR, 1: logging.WARNING, 2: logging.INFO}

def _validate_port(port_s):
    try:
        port = int(port_s)
    except Exception:
        raise RuntimeError('Invalid port (%s).' % port_s)

    if port < 1 or port > 65536:
        raise RuntimeError('Invalid port (%d).' % port)

    return port


def _validate_host(addr):
    if not (addr.count(':') == 1):
        raise RuntimeError('Invalid [ip:port] format: {}'.format(addr))

    addr, port = addr.split(':')
    if not str(ipaddress.IPv4Address(addr)) == addr:
        raise RuntimeError('Invalid format for IPv4 address: {}'.format(addr))

    if not str(int(port)) == port:
        raise RuntimeError('Invalid format for port: {}'.format(port))

    return addr, int(port)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=int, required=False, default=4990,
        metavar='port', help='Listen to port for HTTP requests.'
        + ' (default: 4990)')
    parser.add_argument('-s', required=False, default='127.0.0.1:5000',
        metavar='ip:or_port', help='Tor node used as slave.'
        + ' (default: 127.0.0.1:5000)')
    parser.add_argument('-c', required=False, default='8000',
        metavar='control_port', help='Control port for path selection.'
        + ' (default: 8000)')
    parser.add_argument('-d', required=False, default='7000',
        metavar='dir_port', help='Dir port for consensus retrieval.'
        + ' (default: 7000)')
    parser.add_argument('-v', action='count',
                        help='Verbose output (up to -vvv)')
    parser.add_argument('--compute-path', action='store_true',
        help="Compute the path for the client.")
    parser.add_argument('--purge-cache', action='store_true',
        help='If specified, purge cache before starting.')
    parser.add_argument('--auth-enabled', action='store_true',
        help='Enable proxy authentication.')
    parser.add_argument('--auth-dirpkey', required=False, default=default_auth,
        metavar='path', help='Fetch auth. material here (default: {})'.format(
        default_auth))

    argv = parser.parse_args()
    logging.basicConfig(
        format=log_format, level=log_levels.get(argv.v, logging.DEBUG))

    # For now, we rely on having a trusted local Tor node that checks
    # signatures for us & everything else.
    #
    argv.s = _validate_host(argv.s)

    if argv.s[0] != '127.0.0.1':
        logging.error(
            'No authentication for slave, using {} is unsafe!'.format(argv.s))
    _, argv.c = _validate_host('{}:{}'.format(argv.s[0], argv.c))

    argv.d = _validate_port(argv.d)

    lightnion.proxy.forward.main(
        port=argv.p,
        slave_node=argv.s,
        dir_port=argv.d,
        control_port=argv.c,
        compute_path=argv.compute_path,
        auth_dir=argv.auth_dirpkey if argv.auth_enabled else None)
