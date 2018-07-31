import socket
import ssl

import lighttor as ltor

class link:
    """An established Tor link, send and receive messages in separate threads.

    :param io: cell.socket.io instance that wraps the TLS/SSLv3 connection
    :param int version: link version

    Usage::

      >>> import lighttor as ltor
      >>> link = ltor.link.initiate('127.0.0.1', 5000)
      >>> link.version
      5
      >>> link.send(ltor.cell.padding.pack())
      >>> ltor.cell.padding.cell(link.recv()).valid
      True
      >>> link.close()
    """
    def __init__(self, io, version, circuits=[0]):
        self.version = version
        self.io = io

        self.circuits = set()
        for circuit in circuits:
            self.register(circuit)

    def register(self, circuit_id):
        if circuit_id in self.circuits:
            raise RuntimeError('Circuit {} already registered.'.format(
                circuit_id))

        self.circuits.add(circuit_id)

    def unregister(self, circuit_id):
        self.circuit_id.remove(circuit_id)

    def recv(self):
        return self.io.recv()

    def send(self, cell):
        self.io.send(cell)

    def close(self):
        self.io.close()

def negotiate_version(peer, versions, *, as_initiator):
    """Performs a VERSIONS negotiation

    :param peer: ssl.socket instance.
    :param list versions: target link versions.
    :param bool as_initiator: send VERSIONS cell first.
    """
    if as_initiator:
        ltor.cell.versions.send(peer, ltor.cell.versions.pack(versions))
    vercell = ltor.cell.versions.recv(peer)

    common_versions = list(set(vercell.versions).intersection(versions))
    if len(common_versions) < 1:
        raise RuntimeError('No common supported versions: {} and {}'.format(
            list(vercell.versions), versions))

    version = max(common_versions)
    if version < 4:
        raise RuntimeError('No support for version 3 or lower, got {}').format(
            version)

    if not as_initiator:
        ltor.cell.versions.send(peer, ltor.cell.versions.pack(versions))
    return version

def initiate(address='127.0.0.1', port=9050, versions=[4, 5]):
    """Establish a link with the "in-protocol" (v3) handshake as initiator

    The expected transcript is:

           Onion Proxy (client)              Onion Router (server)

               /   [1] :-------- VERSIONS ---------> [2]
               |   [4] <-------- VERSIONS ---------: [3]
               |
               |           Negotiated Version
               |
               |   [4] <--------- CERTS -----------: [3]
               |       <----- AUTH_CHALLENGE ------:
               |       <-------- NETINFO ----------:
               |
               |             OP don't need to
        Link   |               authenticate
      Protocol |
        >= 3   |   [5] :-------- NETINFO ----------> [6]
               |
               | Alternative:
               | (          We (OR) authenticate         )
               | (                                       )
               | ( [5] :--------- CERTS -----------> [6] )
               | (     :------ AUTHENTICATE ------->     )
               | (             ^                         )
               | (            (answers AUTH_CHALLENGE)   )
               | (                                       )
               \

    :param str address: remote relay address (default: 127.0.0.1).
    :param int port: remote relay ORPort (default: 9050).
    :param list versions: target link versions (default: [4, 5]).

    :returns: a tuple (link socket, link version)

    """

    # Establish connection
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.connect((address, port))
    peer = ssl.wrap_socket(peer)

    # VERSIONS handshake
    version = negotiate_version(peer, versions, as_initiator=True)

    # Wraps with cell.socket.io
    peer = ltor.cell.socket.io(peer)

    # Get CERTS, AUTH_CHALLENGE and NETINFO cells afterwards
    certs_cell = ltor.cell.certs.cell(peer.recv())
    auth_cell = ltor.cell.challenge.cell(peer.recv())
    netinfo_cell = ltor.cell.netinfo.cell(peer.recv())

    # Sanity checks
    if not certs_cell.valid:
        raise RuntimeError('Invalid CERTS cell: {}'.format(certs_cell.raw))
    if not auth_cell.valid:
        raise RuntimeError('Invalid AUTH_CHALLENGE cell:{}'.format(
            auth_cell.raw))
    if not netinfo_cell.valid:
        raise RuntimeError('Invalid NETINFO cell: {}'.format(netinfo_cell.raw))

    # Send our NETINFO to say "we don't want to authenticate"
    peer.send(ltor.cell.netinfo.pack(address))
    return link(peer, version, [0])
