import logging
import hashlib
import base64
import time
import websockets
import asyncio

import lightnion as lnn
from . import parts, base_url, fake_circuit_id
import lightnion.path_selection
import lightnion.utils


class InvalidTokenException(Exception):
    def __init__(self, token):
        super().__init__('Value {} is not a valid token.'.format(token))

class CircuitDoesNotExistException(Exception):
    def __init__(self, cid):
        super().__init__('Circuit id {} does not exist.'.format(cid))

class ChannelDoesNotExistException(Exception):
    def __init__(self, channel):
        super().__init__('Channel {} does not exist.'.format(channel))

class LinkNotInitializedException(Exception):
    pass

class LinkAlreadyInitializedException(Exception):
    pass

def dummy_random_gen():
    return b'Dummy random data.'


class Channel:
    """
    Channel
    """
    def __init__(self, token, cid):
        """
        Channel constructor.
        :param token: Token identifyint the channel.
        :param cid: Circuit id corresponding to the channel.
        """
        self.token = token
        self.cid = cid

        self.to_send = asyncio.Queue(2048)

        self.destroyed = False


class ChannelManager:
    """
    Channel manager
    """

    # Cryptographic tools to generate tokens.
    crypto = parts.crypto()

    def __init__(self):
        """
        Channel manager constructor
        """
        # channels identified by a token
        self.channels = dict()

        # link and main token set later
        self.link = None
        self.maintoken = None


    def _cid_from_token(self, token):
        """
        Extract a circuit id from a token.
        :param token: token from which the circuit id is extracted.
        """
        cid = self.crypto.decrypt_token(token, self.maintoken)

        if cid is None:
            logging.debug('ChanMgr: Invalid token: {}'.format(token))
            raise InvalidTokenException()

        return cid


    def gen_token_from_cid(self, cid):
        """
        Produce a token from a circuit id.
        :param cid: circuit id used to generate the token.
        """
        return self.crypto.compute_token(cid, self.maintoken)


    def _gen_main_token(self, rnd_gen):
        """
        Generate the main token used to produce channel tokens.
        :param rnd_gen: method to generate a ransdom number to initialize the token generator.
        :return: main token
        """
        if self.link is None:
            raise LinkNotInitializedException()

        guard_id = self.link.guard['digest'].encode('utf-8')
        secret = rnd_gen()
        maintoken = hashlib.sha256(guard_id + secret).digest()
        logging.debug('ChanMgr: Main token generated: {}'.format(maintoken))
        return maintoken


    def set_link(self, link, rnd_gen=dummy_random_gen):
        """
        Set a link to be used by the channel handler.
        :param link: Link to use.
        :param rnd_gen: Method to generate a ransdom number to initialize the token generator.
        """
        if self.link is not None:
            raise LinkAlreadyInitializedException()

        self.link = link
        logging.debug('ChanMgr: Link set.')
        self.maintoken = self._gen_main_token(rnd_gen)


    async def reset_link(self, link, rnd_gen=dummy_random_gen):
        """
        Reset the link used the channel handler.
        :param link: Link to use.
        :param rnd_gen: Method to generate a ransdom number to initialize the token generator.
        """
        if self.link is not None:
            for channel in self.channels.values():
                await self.destroy_circuit_from_client(channel)
                await self.destroy_circuit_from_link(channel)
            # Deletion per-se of existing channels handled in websocket after the cell was dispatched.

        self.link = link
        logging.debug('ChanMgr: Link resetted.')
        self.maintoken = self._gen_main_token(rnd_gen)


    def create_channel(self, ntor, consensus, descriptors):
        """
        Create a new channel.
        :param ntor: First part of the ntor handshake provided by the client.
        :param consensus: The current consensus.
        :param descriptors: A collection of the current descriptors.
        :return: Response to be send to the client
        """

        # TODO: Currently, the ntor is provided by the client to be packaged
        #       in the proxy and send back to the client to be send again to
        #       the websocket. This need to be simplified.

        if self.link is None:
            raise LinkNotInitializedException()

        ntor_bin = base64.b64decode(ntor)

        (middle, exit) = lnn.path_selection.select_end_path_from_consensus(consensus, descriptors, self.link.guard)

        cid = self.link.gen_cid()
        token = self.gen_token_from_cid(cid)

        cell = lnn.create.ntor_raw2(cid, ntor_bin)
        cell = base64.b64encode(cell).decode('utf-8')

        self.channels[cid] = Channel(token, cid)

        response = {'id': token, 'path': [middle, exit], 'handshake': cell}

        logging.debug('ChanMgr: Channel {} with token {} created.'.format(cid, token))
        return response


    def delete_channel(self, channel):
        """
        Delete a given channel if it is managed by the channel manager, do nothing otherwise.
        :param channel: Channel to be deleted.
        """
        if channel.cid in self.channel_manager.channels.keys():
            del self.channel_manager.channels[channel.cid]
            logging.debug('ChanMgr: Channel {} with token {} deleted.'.format(channel.cid, channel.token))


    async def destroy_circuit_from_client(self, channel):
        """
        Destroy a circuit corresponding to a channel as if the order was comming from the client side.
        :param channel: Channel handling the circuit to be destroyed.
        """

        # Mark the channel as destroyed.
        channel.destroyed = True

        # Send a cell to the link to delete the circuit in the relay.
        cid = channel.cid
        reason = lnn.cell.destroy.reason.REQUESTED

        cell = lnn.cell.destroy.pack(cid, reason)
        cell_padded = lnn.cell.pad(cell)

        await self.link.to_send.put(cell_padded)

        logging.debug('ChanMgr: Prepare to delete circuit {} from client.'.format(cid))


    async def destroy_circuit_from_link(self, channel):
        """
        Destroy a circuit corresponding to a channel as if the order was comming from the link side.
        :param channel: Channel handling the circuit to be destroyed.
        """

        # Mark the channel as destroyed.
        channel.destroyed = True

        cid = fake_circuit_id
        reason = lnn.cell.destroy.reason.FINISHED

        cell = lnn.cell.destroy.pack(cid, reason)
        cell_padded = lnn.cell.pad(cell)

        await channel.to_send.put(cell_padded)

        logging.debug('ChanMgr: Prepare to delete channel {} from link.'.format(channel.cid))


    def get_channel_by_token(self, token):
        """
        Get a channel by its token.
        :param token: Token identifying the channel.
        """

        cid = self._cid_from_token(token)

        if cid not in self.channels.keys():
            raise ChannelDoesNotExistException(token)

        return self.channels[cid]

    async def schedule_to_send(self, cell, cid):
        """
        Scedule the data to be send to the correct channel.
        :param cell: cell to be send.
        """
        logging.debug('ChanMgr: Begin adding data to sending queue of channel {}.'.format(cid))
        
        if cid not in self.channels.keys():
            logging.warning('ChanMgr: Channel {} does not exists.'.format(cid))
            raise CircuitDoesNotExistException(cid)

        channel = self.channels[cid]

        if channel.destroyed:
            logging.warning('ChanMgr: Channel {} was destroyed.'.format(cid))
            raise CircuitDoesNotExistException(cid)

        # If the cell command to delete the circuit,
        # 1/ send a DESTROY command to the client.
        # 2/ schedule the channel for deletion.
        header = lnn.cell.header(cell)
        if header.cmd is lnn.cell.cmd.DESTROY:
            cell = lnn.cell.destroy.cell(cell)
            if not cell.valid:
                raise InvalidDestroyCellException()

            # Mark the channel as destroyed.
            channel.destroyed = True

        cell_padded = lnn.cell.pad(cell)

        await channel.to_send.put(cell_padded)

        logging.debug('ChanMgr: Data added to sending queue of channel {}.'.format(channel.cid))



class WebsocketManager:
    prefix = base_url + '/channels/'
    prefix_len = len(prefix)

    def __init__(self, host='0.0.0.0', port=8765, timeout=600):
        """
        Websocket server
        :param host: host on which the websocket need to run.
        :param port: port on which the websocket is listening.
        :param timeout: timeout before closing the connection.
        """

        # Time witout activity until channel is deleted.
        self.timeout = timeout

        # The channel manager is set later
        self.channel_manager = None

        # The websocket server
        self.host = host
        self.port = port

        logging.debug('WsServ: Websocket server prepared ({}:{})'.format(host, port))


    async def server(self, loop):
        """
        Create and start a websocket server, then wait for it to close.        
        :param host: host on which the websocket need to run.
        :param port: port on which the websocket is listening.
        """
        server = await websockets.serve(self._handler, self.host, self.port, loop=loop, compression=None)
        await server.wait_closed()
        logging.debug('WsServ: Websocket server closed.')


    def set_channel_manager(self, channel_manager):
        """
        Set the channel manager to use for dispatching data.
        :param channel_manager: The channel manager to use.
        """
        self.channel_manager = channel_manager
        logging.debug('WsServ: Channel manager set.')


    async def _recv(self, ws, channel):
        """
        Handler to receive a message from the client via the websocket.
        :param ws: websocket used to communicate with the client.
        :param channel: Channel correspondind to the client from which data is recieved.
        """

        # destroy the channel if it need to be destroyed.
        if channel.destroyed:
            logging.debug('WsServ: Delete channel {} in recv:'.format(channel.cid))
            self.channel_manager.delete_channel(channel)
            # Nothing else to do as the channel is deleted
            return

        cell = await ws.recv()
        logging.debug('WsServ: Recieved data from channel {}:\n{}'.format(channel.cid, cell))

        await self.channel_manager.link.schedule_to_send(cell, channel)


    async def _send(self, ws, channel):
        """
        Handler to send a message to the client via the websocket.
        :param ws: The websocket used to communicate with the client.
        :param channel: Channel from which data is sent.
        """

        # retrieve cell properly
        cell = await channel.to_send.get()

        # Cell analysis to check if the channel need to be scheduled for deletion done in channel handler.

        # destroy the channel if it need to be destroyed.
        if channel.destroyed:
            self.channel_manager.delete_channel(channel)

        # The real circuit ID is kept hidden from the client.
        cell_mut = lnn.cell.header_view.write(cell, circuit_id=fake_circuit_id)
        cell_padded = lnn.cell.pad(cell_mut)
        await ws.send(cell_padded)

        logging.debug('WsServ: Sent data to channel {}:\n{}'.format(channel.cid, cell_padded))


    async def _timeout(self, ws, channel):
        """
        Handler to send termination cells in case of a timeout.
        """
        await asyncio.sleep(self.timeout)

        # mark the channel as destroyed.
        channel.destroyed = True

        # Build a cell to destroy the circuit in the relay.
        cid = channel.cid
        reason = lnn.cell.destroy.reason.REQUESTED

        cell = lnn.cell.destroy.pack(cid, reason)
        cell_padded = lnn.cell.pad(cell)

        await self.channel_manager.link.to_send.put(cell_padded)

        # Channel deleted when cell is send.
        #self.channel_manager.delete_channel(channel)

        logging.debug('WsServ: Channel {} timed out.'.format(channel.cid))


    async def _handler(self, ws, path):
        """
        Handler to process a IO on the websocket or on the link.
        :param ws: The websocket used to communicate with the client.
        :param path: Path used by the client.
        """

        if not path.startswith(WebsocketManager.prefix):
            logging.warning('WsServ: Attempted to connect to websocket with an invalid prefix {}.'.format(path))
            return

        token = path[WebsocketManager.prefix_len:]

        logging.debug('WsServ: Begin handler for channel id by token {}.'.format(token))

        try:
            channel = self.channel_manager.get_channel_by_token(token)
        except Exception:
            logging.warning('WsServ: Attempted to connect to websocket with an invalid token {}.'.format(token))
            return

        tasks = [
            asyncio.create_task(self._recv(ws, channel)),
            asyncio.create_task(self._send(ws, channel)),
            asyncio.create_task(self._timeout(ws, channel))
        ]

        while not ws.closed:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            if tasks[0].done() or tasks[0].cancelled():
                tasks[0] = asyncio.create_task(self._recv(ws, channel))
                logging.debug('WsServ: New recv task created for channel {}.'.format(channel.cid))
            if tasks[1].done() or tasks[1].cancelled():
                tasks[1] = asyncio.create_task(self._send(ws, channel))
                logging.debug('WsServ: New send task created for channel {}.'.format(channel.cid))
            if tasks[2].done():
                logging.debug('WsServ: Ws handler timed out for channel {}.'.format(channel.cid))
                break
            else:
                # Channel has not timed out, so the timeout is resetted.
                task[2].cancel()
                task[2] = asyncio.create_task(self._timeout(ws, channel))
                logging.debug('WsServ: Reset handler timed out for channel {}.'.format(channel.cid))

        # Proper termination of communications.
        for task in tasks:
            if not (task.cancelled() or task.done()):
                task.cancel()

        ws.close()
        await ws.wait_closed()

        logging.debug('WsServ: End handler for channel {}.'.format(channel.cid))
