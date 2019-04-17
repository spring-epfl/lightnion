import logging
import socket
import ssl
import asyncio

import lightnion as lnn
import lightnion.cell
import lightnion.utils
from lightnion.proxy import fake_circuit_id


class InvalidCellHeaderException(Exception):
    pass

class InvalidAuthCellException(Exception):
    pass

class InvalidCertsCellException(Exception):
    pass

class InvalidDestroyCellException(Exception):
    pass

class InvalidNetInfoCellException(Exception):
    pass

class InvalidVersionCellException(Exception):
    pass

class NoSupportedVersionException(Exception):
    pass

class Link:
    def __init__(self, guard, versions=(4,5)):
        """
        Handler for communications between the proxy and a guard relay.
        :param guard: guard tor relay with with to establish a link.
        :param versions: versions supported by the proxy
        """

        host = guard['router']['address']
        port = guard['router']['orport']

        # Queue containing cells to be send to the tor relay.
        self.to_send = asyncio.Queue(16384)

        # Buffer containing beginning of potential imcomplete cell.
        self.buffer = b''

        # The link is bound to a specific guard node.
        self.guard = guard

        # The first bit of the circuit id must be 1.
        self.circuit_id = 0x80000000

        ctxt = ssl.SSLContext(ssl.PROTOCOL_TLS)

        # TLS 1.3 disabled for compatibility issues.
        # https://trac.torproject.org/projects/tor/ticket/28616
        ctxt.options |= ssl.OP_NO_TLSv1_3

        # channel manager set later.
        self.channel_manager = None

        # The connection to the tor relay.
        self.connection = self._handler(host, port, ctxt, versions)

        logging.debug('Link: Link prepared ({} : {})'.format(host, port))


    def set_channel_manager(self, channel_manager):
        """
        Set the channel manager to which the traffic should be send.
        :param channel_manager: channel manager to use.
        """

        self.channel_manager = channel_manager

        logging.debug('Link: Channel manager set.')


    def gen_cid(self):
        """
        Generate a new circuit id.
        :return: new circuit id
        """
        self.circuit_id += 1

        logging.debug('Link: New circuit id generated {}'.format(self.circuit_id))

        return self.circuit_id


    async def schedule_to_send(self, cell, channel):
        """
        Coroutine
        Order some data to be sent to the tor relay.
        :param cell: cell to be sent.
        :param channel: channel from which the cell is sent.
        """

        logging.debug('Link: Begin adding data to sending queue from channel {}.'.format(channel.cid))

        # Set correct circuit id.
        cell = lnn.cell.header_view.write(cell, circuit_id=channel.cid)

        header = lnn.cell.header(cell)
        if header.cmd is lnn.cell.cmd.DESTROY:
            cell = lnn.cell.destroy.cell(cell)
            if not cell.valid:
                logging.debug('Link: Cancelled adding data to sending queue from channel {}, invalid cell.'.format(channel.cid))
                #raise InvalidDestroyCellException()
                raise Exception()

            # Mark the channel as destroyed and remove it from the manager.
            channel.destroyed = True
            self.channel_manager.delete_channel(channel)

        cell_padded = lnn.cell.pad(cell)

        await self.to_send.put(cell_padded)
        logging.debug('Link: Finish adding data to sending queue from channel {}.'.format(channel.cid))


    async def _handle_tor_mgmt_cell(self, cell):
        logging.debug('Link: Handle management cell from tor relay.')
        pass


    async def _recv(self, reader):
        """
        Recieve data from the tor relay and give it to the channel manager.
        :param reader: asyncio StreamReader
        """
        data = await reader.read(65536)

        data = self.buffer + data
        # Let the channel manager do the multiplexing.
        logging.debug('Link: Received data\n{}'.format(data))

        (cell, data) = lnn.utils.cell_slice(data)

        while cell is not None:
            logging.debug('Link: Spliced a cell.\n{}'.format(cell))
            # Analyse header to select correct channel.
            header = lnn.cell.header(cell)
            cid = header.circuit_id

            if cid == 0:
                await self._handle_tor_mgmt_cell(cell)
            else:
                # Replace the real circuit id by a dummy one.
                logging.debug('Link: Prepare replacement of circuit id.')
                cell = lnn.cell.header_view.write(cell, circuit_id=fake_circuit_id)
                logging.debug('Link: Replaced circuit id.')
                await self.channel_manager.schedule_to_send(cell, cid)

            (cell, data) = lnn.utils.cell_slice(data)

        # At the end we keep the beginning of the next cell.
        self.buffer = data


    async def _send(self, writer):
        """
        Send data to the tor relay.
        :param reader: asyncio StreamWriter
        """
        data = await self.to_send.get()
        writer.write(data)
        await writer.drain()
        logging.debug('Link: Sent data:\n{}'.format(data))


    async def _negociate_version(self, reader, writer, versions):
        """
        Negociate tor version with the relay.
        :param reader: asyncio.StreamReader
        :param writer: asyncio.StreamWriter
        :param versions: collection of versions supported by the proxy
        :return: negociated version
        """

        logging.debug('Link: Begin version negociation.')

        # Ask the relay which versions it supports.
        payload = lnn.cell.versions.pack(versions)

        #await lnn.cell.versions.send_async(writer, payload)
        # Code from this method inlined here:

        payload = payload.raw

        vercell = lnn.cell.versions.cell(payload)
        if not vercell.valid:
            raise InvalidVersionCellException()

        writer.write(payload)
        await writer.drain()

        logging.debug('Link: Sent version cell:\n{}'.format(payload))

        #vercell = await lnn.cell.versions.recv_async(reader)
        # Code from this method inlined here:
        
        answer = await reader.read(lnn.cell.header_legacy_view.width())

        logging.debug('Link: Received version cell:\n{}'.format(answer))

        header = lnn.cell.header_legacy(answer)
        if not header.valid:
            raise InvalidCellHeaderException()
        if not header.cmd == lnn.cell.cmd.VERSIONS:
            raise InvalidVersionCellException()

        length = header.length
        if length > lnn.constants.max_payload_len:
            raise InvalidVersionCellException()

        answer += await reader.read(length)
        if not lnn.cell.versions.view.valid(answer):
            raise InvalidVersionCellException()

        vercell = lnn.cell.versions.cell(answer)

        # Versions validation
        common_versions = set(vercell.versions).intersection(versions)
        if len(common_versions) < 1:
            raise NoSupportedVersionException()

        max_version = max(common_versions)
        if max_version < 4:
            raise NoSupportedVersionException()

        # The latest version is selected.

        logging.debug('Link: Select version {}.'.format(max_version))
        logging.debug('Link: End version negociation.')

        return max_version


    async def _handler(self, host, port, ctxt, versions):
        """
        Establish a connection with the tor relay and handle all
        communications between it and the proxy.
        :param host: ip address of the relay
        :param port: port of the relay
        :param ctxt: TLS context
        :param versions: collection of versions supported by the proxy
        """

        # The expected transcript is:
        #
        #    Onion Proxy (client)                Onion Router (server)
        #
        #            /   [1] :-------- VERSIONS ---------> [2]
        #            |   [4] <-------- VERSIONS ---------: [3]
        #            |
        #            |           Negotiated Version
        #            |
        #            |   [4] <--------- CERTS -----------: [3]
        #            |       <----- AUTH_CHALLENGE ------:
        #            |       <-------- NETINFO ----------:
        #            |
        #            |             OP don't need to
        #     Link   |               authenticate
        #   Protocol |
        #     >= 3   |   [5] :-------- NETINFO ----------> [6]
        #            |
        #            | Alternative:
        #            | (          We (OR) authenticate         )
        #            | (                                       )
        #            | ( [5] :--------- CERTS -----------> [6] )
        #            | (     :------ AUTHENTICATE ------->     )
        #            | (             ^                         )
        #            | (            (answers AUTH_CHALLENGE)   )
        #            | (                                       )
        #            \

        logging.debug('Link: Opening connection.')

        reader, writer = await asyncio.open_connection(host, port, ssl=ctxt)

        logging.debug('Link: Connection open.')

        self.version = await self._negociate_version(reader, writer, versions)

        # Tor handshake
        cells_raw = await reader.read(65536)

        #logging.debug('Link: Received handshake cells:\n{}'.format(cells_raw))

        (cell, cells_raw) = lnn.utils.cell_slice(cells_raw)
        certs_cell = lnn.cell.certs.cell(cell)
        logging.debug('Link: Certs cell:\n{}'.format(certs_cell.raw))

        (cell, cells_raw) = lnn.utils.cell_slice(cells_raw)
        auth_cell = lnn.cell.challenge.cell(cell)
        logging.debug('Link: Auth cell:\n{}'.format(auth_cell.raw))

        (cell, cells_raw) = lnn.utils.cell_slice(cells_raw)
        netinfo_cell = lnn.cell.netinfo.cell(cell)
        logging.debug('Link: Netinfo cell:\n{}'.format(netinfo_cell.raw))

        # Validation of handshake cells given by the relay.
        if not certs_cell.valid:
            raise InvalidCertsCellException()

        if not auth_cell.valid:
            raise InvalidAuthCellException()

        if not netinfo_cell.valid:
            raise InvalidNetInfoCellException()

        # Send the NETINFO without doing any further authentication.
        netinfo_cell = lnn.cell.pad(lnn.cell.netinfo.pack(host))
        writer.write(netinfo_cell)
        await writer.drain()

        logging.debug('Link: Sent netinfo cell:\n{}'.format(netinfo_cell))

        # Handle all communication from now on.
        tasks = [
            asyncio.create_task(self._recv(reader)),
            asyncio.create_task(self._send(writer))
        ]

        while not reader.at_eof():
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            if tasks[0].done() or tasks[0].cancelled():
                tasks[0] = asyncio.create_task(self._recv(reader))
                logging.debug('Link: New recv task created.')
            if tasks[1].done() or tasks[1].cancelled():
                tasks[1] = asyncio.create_task(self._send(writer))
                logging.debug('Link: New send task created.')

        # Proper termination of communications.
        for task in tasks:
            if not task.cancelled():
                task.cancel()

        writer.close()
        await writer.wait_closed()

        logging.debug('Link: Connection closed.')


#async def initiate_async(address='127.0.0.1', port=9050, versions=[4, 5]):
#    """Establish a link with the "in-protocol" (v3) handshake as initiator
#    :param str address: remote relay address (default: 127.0.0.1).
#    :param int port: remote relay ORPort (default: 9050).
#    :param list versions: target link versions (default: [4, 5]).
#
#    :returns: a link.link object
#
#    """
#
#    logging.warning('Setup context')
#    # Setup context
#    ctxt = ssl.SSLContext(ssl.PROTOCOL_TLS)
#    # https://trac.torproject.org/projects/tor/ticket/28616
#    ctxt.options |= ssl.OP_NO_TLSv1_3
#
#    logging.warning('Open connection')
#    reader, writer = await asyncio.open_connection(address, port, ssl=ctxt)
#
#    # VERSIONS handshake
#    logging.warning('Negociate version')
#    version = await negotiate_version_async(reader, writer, versions, as_initiator=True)
#
#    logging.warning(version)
#
#    # Get CERTS, AUTH_CHALLENGE and NETINFO cells afterwards
#    # Number obtained by experimentation with chutney.
#    cell = await fetch_cell(reader)
#    msg = ','.join(str(i) for i in list(cell))
#    logging.warning('cert <<< ' + msg + ' ... length: ' + str(len(cell)))
#    certs_cell = lnn.cell.certs.cell(cell)
#
#    cell = await fetch_cell(reader)
#    msg = ','.join(str(i) for i in list(cell))
#    logging.warning('auth <<< ' + msg + ' ... length: ' + str(len(cell)))
#    auth_cell = lnn.cell.challenge.cell(cell)
#
#    cell = await fetch_cell(reader)
#    msg = ','.join(str(i) for i in list(cell))
#    logging.warning('info <<< ' + msg + ' ... length: ' + str(len(cell)))
#    netinfo_cell = lnn.cell.netinfo.cell(cell)
#
#    # Sanity checks
#    if not certs_cell.valid:
#        raise InvalidCertsCellException('Invalid CERTS cell: {}'.format(certs_cell.raw))
#    if not auth_cell.valid:
#        raise InvalidAuthChallengeCellException('Invalid AUTH_CHALLENGE cell:{}'.format(
#            auth_cell.raw))
#    if not netinfo_cell.valid:
#        raise InvalidNetInfoCellException('Invalid NETINFO cell: {}'.format(netinfo_cell.raw))
#
#    # Send our NETINFO to say "we don't want to authenticate"
#    writer.write(lnn.cell.pad(lnn.cell.netinfo.pack(address)))
#    return Link(reader, writer, version)


