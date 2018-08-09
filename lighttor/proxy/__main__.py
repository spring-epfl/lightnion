import lighttor.proxy.forward
import argparse
import ipaddress

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
    parser.add_argument('-b', required=False, default='127.0.0.1:5000',
        metavar='ip:or_port', help='Tor node for first consensus.'
        + ' (default: 127.0.0.1:5000)')
    parser.add_argument('-s', required=False, default='127.0.0.1:8000',
        metavar='ip:control_port', help='Slave node for path selection.'
        + ' (default: 127.0.0.1:8000)')
    parser.add_argument('--purge-cache', action='store_true',
        help='If specified, purge cache before starting.')
    parser.add_argument('--spawn-slave', action='store_true',
        help='If specified, ignore -s and spawn local slave.')

    argv = parser.parse_args()
    argv.b = _validate_host(argv.b)
    argv.s = _validate_host(argv.s)

    lighttor.proxy.forward.main(
        port=argv.p,
        slave_node=argv.s if not argv.spawn_slave else None,
        bootstrap_node=argv.b,
        purge_cache=argv.purge_cache)
