import socket
import queue
import ssl

import lighttor as ltor

class link:
    """An established Tor link, send and receive messages in separate threads.

    :param io: socket.io instance that wraps the TLS/SSLv3 connection
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
    def __init__(self, io, version, circuits=[0], max_queue=2048):
        self.max_queue = 2048
        self.version = version
        self.io = io

        self.circuits = dict()
        self.register(ltor.create.circuit(0, None))

    def pull(self, block=True):
        try:
            payload = self.io.recv(block=block)
        except queue.Empty:
            return False

        # We know that receiver.get() will give you a cell with a well-formed
        # header, thus we do not validate it one more time.
        #
        # We doesn't handle VERSIONS cells with shorter circuit_id.
        #
        header = ltor.cell.header(payload)
        if not header.circuit_id in self.circuits:
            raise RuntimeError('Got circuit {} outside {}, cell: {}'.format(
                header.circuit_id, list(self.circuits), payload))

        # TODO: property handle DESTROY cells
        circuit = self.circuits[header.circuit_id]
        if header.cmd is ltor.cell.cmd.DESTROY:
            cell = ltor.cell.destroy.cell(payload)
            if not cell.valid:
                raise RuntimeError('Got invalid DESTROY cell: {}'.format(
                    cell.truncated))

            self.put(circuit, payload)
            circuit.destroyed = True
            circuit.reason = cell.reason
            self.unregister(circuit)
            return False

        self.put(circuit, payload)
        return True

    def put(self, circuit, payload):
        circuits_size = sum([c.queue.qsize() for _, c in self.circuits.items()])
        if circuits_size > self.max_queue:
            raise RuntimeError(
                'Link circuit queues are full: {}'.format(circuits_size))

        if circuit.id not in self.circuits:
            raise RuntimeError('Got circuit_id {} outside {}, cell: {}'.format(
                circuit.id, list(self.circuits), payload))

        try:
            payload = payload.raw
        except AttributeError:
            pass

        self.circuits[circuit.id].put(payload)

    def get(self, circuit, block=True):
        while block and not self.io.dead:
            try:
                return self.circuits[circuit.id].get(block=False)
            except queue.Empty:
                pass
            self.pull()
        else:
            self.pull(block=False)
            return self.circuits[circuit.id].get(block=False)

    def register(self, circuit):
        if circuit.id in self.circuits:
            raise RuntimeError('Circuit {} already registered.'.format(
                circuit.id))

        circuit.queue = queue.Queue(maxsize=self.max_queue)
        self.circuits[circuit.id] = circuit

    def unregister(self, circuit):
        del self.circuits[circuit.id]

    def recv(self, block=True):
        return self.io.recv(block=block)

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

    # Wraps with socket.io
    peer = ltor.socket.io(peer)

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
    return link(peer, version)
