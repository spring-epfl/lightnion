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

        logging.warning('Guard {}'.format(guard['router']['nickname']))

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

        self.cell_sent = 0
        self.cell_recv = 0

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


    async def schedule_to_send(self, cell_raw, channel):
        """
        Coroutine
        Order some data to be sent to the tor relay.
        :param cell: cell to be sent.
        :param channel: channel from which the cell is sent.
        """

        # Set correct circuit id.
        cell = lnn.cell.header_view.write(cell_raw, circuit_id=channel.cid)
        #cell = lnn.utils.cell_set_cid(cell_raw, channel.cid)

        header = lnn.cell.header(cell)
        #cmd = lnn.utils.cell_get_cmd(cell)
        #if cmd == 3:
        #    cell = lnn.utils.cell_pad_rnd(cell)
        #else:
        #    cell = lnn.utils.cell_pad_null(cell)

        #if cmd == 4:
        if header.cmd is lnn.cell.cmd.DESTROY:
            logging.debug('Link: channel {} asks for the circuit to be destroyed.'.format(channel.cid))
            cell_validation = lnn.cell.destroy.cell(cell)
            #if not lnn.utils.cell_is_valid(cell):
            if not cell_validation.valid:
                logging.debug('Link: Channel {} attempted to send an invalid cell.'.format(channel.cid))
                return
                #raise InvalidDestroyCellException()

            # Mark the channel as destroyed
            if not channel.destroyed.is_set():
                channel.destroyed.set()

        cell_padded = lnn.cell.pad(cell)

        await self.to_send.put(cell_padded)
        #await self.to_send.put(cell)
        logging.debug('Link: Scheduled data from channel {} to be send.'.format(channel.cid))


    async def _handle_tor_cmd_cell(self, cell):
        logging.debug('Link: Handle management cell from tor relay.')


    async def _recv(self, reader):
        """
        Recieve data from the tor relay and give it to the channel manager.
        :param reader: asyncio StreamReader
        """

        while not reader.at_eof():
            data = await reader.read(65536)

            data = self.buffer + data

            data_initial = data

            # Let the channel manager do the multiplexing.
            #logging.debug('Link: Received data\n{}'.format(data))

            (cell, data) = lnn.utils.cell_slice_old(data)

            data_cells = b''
            cells = []

            while cell is not None:

                data_cells += cell
                cells.append(cell)

                logging.debug('Link: Spliced a cell. {}... {} bytes.'.format(cell[:20], len(cell)))
                # Analyse header to select correct channel.
                header = lnn.cell.header(cell)
                cid = header.circuit_id
                #cid = lnn.utils.cell_get_cid(cell)

                if cid == 0:
                    await self._handle_tor_cmd_cell(cell)
                else:
                    # Replace the real circuit id by a dummy one.
                    cell_mut = lnn.cell.header_view.write(cell, circuit_id=fake_circuit_id)
                    #cell_mut = lnn.utils.cell_set_cid(cell, fake_circuit_id)

                    self.cell_recv += 1
                    logging.info('cell {} recv by relay: {}'.format(self.cell_recv, cell[:20].hex()))
                    await self.channel_manager.schedule_to_send(cell_mut, cid)

                (cell, data) = lnn.utils.cell_slice_old(data)

            data_cells = data_cells + data

            if data_cells != data_initial:
                logging.warning('CELL SLICING MANGLE THE DATA')
                logging.warning('INITIAL:\n{}'.format(data_initial.hex()))
                logging.warning('CELLS:\n{}'.format(data_cells.hex()))
                logging.warning('PREV BUFFER:\n{}'.format(self.buffer.hex()))
                logging.warning('NEXT BUFFER:\n{}'.format(data.hex()))

            # At the end we keep the beginning of the next cell.
            self.buffer = data


    async def _send(self, writer):
        """
        Send cell to the tor relay.
        :param reader: asyncio StreamWriter
        """
        while not writer.is_closing():
            cell = await self.to_send.get()

            writer.write(cell)
            await writer.drain()
            logging.debug('Link: Sent cell: {}... {} bytes.'.format(cell[:20], len(cell)))

            self.cell_sent += 1
            logging.info('cell {} sent to relay: {}'.format(self.cell_sent, cell[:20].hex()))
            #await asyncio.sleep(0.01)


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
        #payload = lnn.cell.versions.pack(versions)
        payload = lnn.utils.cell_version_build(versions)

        #await lnn.cell.versions.send_async(writer, payload)
        # Code from this method inlined here:

        #payload = payload.raw

        #vercell = lnn.cell.versions.cell(payload)
        #if not vercell.valid:
        #    raise InvalidVersionCellException()

        writer.write(payload)
        await writer.drain()

        logging.debug('Link: Sent version cell: {}.'.format(payload))

        #vercell = await lnn.cell.versions.recv_async(reader)
        # Code from this method inlined here:
        
        #answer = await reader.read(lnn.cell.header_legacy_view.width())
        answer = await reader.read(5)

        #header = lnn.cell.header_legacy(answer)
        #if not header.valid:
        #    raise InvalidCellHeaderException()
        #if not header.cmd == lnn.cell.cmd.VERSIONS:
        #    raise InvalidVersionCellException()

        #length = header.length
        length = lnn.utils.cell_version_get_len(answer)

        if length > lnn.constants.max_payload_len:
            raise InvalidVersionCellException()

        answer += await reader.read(length)
        #if not lnn.cell.versions.view.valid(answer):
        #    raise InvalidVersionCellException()

        logging.debug('Link: Received version cell: {}'.format(answer))

        #vercell = lnn.cell.versions.cell(answer)
        versions_res = lnn.utils.cell_version_get_versions(answer)

        #common_versions = set(vercell.versions).intersection(versions)
        common_versions = set(versions_res).intersection(versions)

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
        #certs_cell = lnn.cell.certs.cell(cell)
        certs_cell = cell
        #logging.debug('Link: Certs cell:\n{}... {} bytes.'.format(certs_cell.raw[:20], len(certs_cell.raw)))
        logging.debug('Link: Certs cell: {}... {} bytes.'.format(certs_cell[:20], len(certs_cell)))

        (cell, cells_raw) = lnn.utils.cell_slice(cells_raw)
        #auth_cell = lnn.cell.challenge.cell(cell)
        auth_cell = cell
        #logging.debug('Link: Auth cell:\n{}... {} bytes.'.format(auth_cell.raw[:20], len(auth_cell.raw)))
        logging.debug('Link: Auth cell: {}... {} bytes.'.format(auth_cell[:20], len(auth_cell)))

        (cell, cells_raw) = lnn.utils.cell_slice(cells_raw)
        #netinfo_cell = lnn.cell.netinfo.cell(cell)
        netinfo_cell = cell
        #logging.debug('Link: Netinfo cell:\n{}... {} bytes.'.format(netinfo_cell.raw[:20], len(netinfo_cell.raw)))
        logging.debug('Link: Netinfo cell: {}... {} bytes.'.format(netinfo_cell[:20], len(netinfo_cell)))

        # Validation of handshake cells given by the relay.
        #if not certs_cell.valid:
        #    raise InvalidCertsCellException()

        #if not auth_cell.valid:
        #    raise InvalidAuthCellException()

        #if not netinfo_cell.valid:
        #    raise InvalidNetInfoCellException()

        # Send the NETINFO without doing any further authentication.
        #netinfo_cell = lnn.cell.pad(lnn.cell.netinfo.pack(host))
        netinfo_cell = lnn.utils.cell_netinfo_build(host)

        writer.write(netinfo_cell)
        await writer.drain()

        logging.debug('Link: Sent netinfo cell: {}'.format(netinfo_cell))

        # Handle all communication from now on.
        tasks = [
            asyncio.create_task(self._recv(reader)),
            asyncio.create_task(self._send(writer))
        ]

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        #while not reader.at_eof():
        #    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        #    if tasks[0].done() or tasks[0].cancelled():
        #        tasks[0] = asyncio.create_task(self._recv(reader))
        #        logging.debug('Link: New recv task created.')
        #    if tasks[1].done() or tasks[1].cancelled():
        #        tasks[1] = asyncio.create_task(self._send(writer))
        #        logging.debug('Link: New send task created.')

        # Proper termination of communications.
        for task in tasks:
            if not task.cancelled():
                task.cancel()

        writer.close()
        await writer.wait_closed()

        logging.debug('Link: Connection closed.')

