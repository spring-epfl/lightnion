import socket
import queue
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
      >>> link.send(ltor.cell.create_fast.pack(2**31))
      >>> ltor.cell.created_fast.cell(link.get(circuit_id=2**31)).valid
      True
      >>> link.close()
    """
    def __init__(self, io, version, circuits=[0], max_pool=2048):
        self.max_pool = 2048
        self.version = version
        self.io = io

        self.pool = dict()
        self.circuits = set()
        for circuit in circuits:
            self.register(circuit)

    def pull(self):
        payload = self.io.recv()

        # We know that receiver.get() will give you a cell with a well-formed
        # header, thus we directly access to its circid with validation.
        #
        # We doesn't handle VERSIONS cells with shorter circid.
        #
        circuit_id = ltor.cell.view.uint(4).value(payload)
        self.put(circuit_id, payload)

    def put(self, circuit_id, payload):
        pool_size = sum([q.qsize() for _, q in self.pool.items()])
        if pool_size > self.max_pool:
            raise RuntimeError(
                'Link circuit pool is full: {}'.format(pool_size))

        if circuit_id not in self.circuits:
            raise RuntimeError('Got circid {} outside {}, cell: {}'.format(
                circuit_id, self.circuits, payload))

        try:
            payload = payload.raw
        except AttributeError:
            pass

        self.pool[circuit_id].put(payload)

    def get(self, circuit_id, block=True):
        while block:
            try:
                return self.pool[circuit_id].get_nowait()
            except queue.Empty:
                self.pull()
        else:
            return self.pool[circuit_id].get_nowait()

    def register(self, circuit_id):
        if circuit_id in self.circuits:
            raise RuntimeError('Circuit {} already registered.'.format(
                circuit_id))

        self.pool[circuit_id] = queue.Queue(maxsize=self.max_pool)
        self.circuits.add(circuit_id)

    def unregister(self, circuit_id):
        self.circuit_id.remove(circuit_id)
        del self.pool[circuit_id]

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

    :returns: a link.link object

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
