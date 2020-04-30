import logging
import hashlib
import base64
import time
import websockets
import asyncio

import lightnion as lnn
from . import parts, base_url, fake_circuit_id
import lightnion.path_selection


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

        self.destroyed = asyncio.Event()


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
        :param rnd_gen: Method to generate a random number to initialize the token generator.
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
        :param rnd_gen: Method to generate a random number to initialize the token generator.
        """
        if self.link is not None:
            for channel in self.channels.values():
                await self.destroy_circuit_from_client(channel)
                #await self.destroy_circuit_from_link(channel)
            # Deletion per-se of existing channels handled in websocket after the cell was dispatched.

        self.link = link
        logging.debug('ChanMgr: Link resetted.')
        self.maintoken = self._gen_main_token(rnd_gen)


    def create_channel(self, consensus, descriptors, select_path):
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

        cid = self.link.gen_cid()
        token = self.gen_token_from_cid(cid)

        self.channels[cid] = Channel(token, cid)

        if not select_path:
            (middle, exit) = lnn.path_selection.select_end_path_from_consensus(consensus, descriptors, self.link.guard)
            logging.warning('Middle {}'.format(middle['router']['nickname']))
            logging.warning('Exit {}'.format(exit['router']['nickname']))
            response = {'id': token, 'path': [middle, exit], 'guard': self.link.guard}
            logging.debug('ChanMgr: Channel {} with token {} created.'.format(cid, token))
            return response
        else:
            response = {'id': token, 'guard': self.link.guard}
            logging.debug('ChanMgr: Channel {} with token {} created.'.format(cid, token))
            return response

    def delete_channel(self, channel):
        """
        Delete a given channel if it is managed by the channel manager, do nothing otherwise.
        :param channel: Channel to be deleted.
        """
        if channel.cid in self.channels.keys():
            del self.channels[channel.cid]
            logging.debug('ChanMgr: Channel {} with token {} deleted.'.format(channel.cid, channel.token))


    async def destroy_circuit_from_client(self, channel):
        """
        Destroy a circuit corresponding to a channel as if the order was comming from the client side.
        :param channel: Channel handling the circuit to be destroyed.
        """

        # Send a cell to the link to delete the circuit in the relay.
        cid = channel.cid
        reason = lnn.proxy.cell.DestroyReason.REQUESTED

        cell_padded = lnn.proxy.cell.CellDestroy(cid, reason).to_bytes()

        await self.link.to_send.put(cell_padded)

        # Destroy the channel.
        channel.destroyed.set()

        logging.debug('ChanMgr: Prepare to delete circuit {} from client.'.format(cid))


    async def destroy_circuit_from_link(self, channel):
        """
        Destroy a circuit corresponding to a channel as if the order was comming from the link side.
        :param channel: Channel handling the circuit to be destroyed.
        """

        # Destroy the channel.
        channel.destroyed.set()

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
        logging.info('ChanMgr: Begin adding data to sending queue of channel {}.'.format(cid))
        
        if cid not in self.channels.keys():
            logging.warning('ChanMgr: Channel {} does not exists.'.format(cid))
            return
            #raise CircuitDoesNotExistException(cid)

        channel = self.channels[cid]

        if channel.destroyed.is_set():
            logging.warning('ChanMgr: Channel {} is destroyed.'.format(cid))
            return
            #raise CircuitDoesNotExistException(cid)

        # If the cell command to delete the circuit,
        cmd = lnn.proxy.cell.Cell.command(cell)

        if cmd == lnn.proxy.cell.Command.DESTROY:
            #await self.destroy_circuit_from_link(channel)

            return

        cell_padded = lnn.proxy.cell.Cell.pad(cell)

        await channel.to_send.put(cell_padded)

        logging.debug('ChanMgr: Data added to sending queue of channel {}.'.format(channel.cid))



class WebsocketManager:
    prefix = base_url + '/channel/'
    prefix_len = len(prefix)

    def __init__(self, host='127.0.0.1', port=8765, timeout=60):
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
        self.server = None

        self.cell_sent = 0
        self.cell_recv = 0


        logging.debug('WsServ: Websocket server prepared ({}:{})'.format(host, port))


    async def serve(self, loop):
        """
        Create and start a websocket server, then wait for it to close.        
        :param host: host on which the websocket need to run.
        :param port: port on which the websocket is listening.
        """
        self.server = await websockets.serve(self._handler, self.host, self.port, loop=loop, compression=None)


    async def stop(self):
        if self.server is not None:
            self.server.close()
        await self.server.wait_closed()
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

        while not ws.closed:
            try:
                cell = await ws.recv()

                self.cell_recv += 1
                logging.info('cell {} recv by wbskt: {}'.format(self.cell_recv, cell[:20].hex()))
                logging.debug('WsServ: Recieved cell from channel {}: {}... {} bytes.'.format(channel.cid, cell[:20], len(cell)))

                await self.channel_manager.link.schedule_to_send(cell, channel)

            except websockets.exceptions.ConnectionClosedError:
                logging.exception('Websocket connection closed.')
                return

            except websockets.exceptions.ConnectionClosedOK:
                logging.info('Websocket connection closed.')
                return


    async def _send(self, ws, channel):
        """
        Handler to send a message to the client via the websocket.
        :param ws: The websocket used to communicate with the client.
        :param channel: Channel from which data is sent.
        """

        while not ws.closed:
            try:
                cell = await channel.to_send.get()

                cell = lnn.proxy.cell.Cell.pad(cell)
                await ws.send(cell)

                self.cell_sent += 1
                logging.info('cell {} sent to wbskt: {}'.format(self.cell_sent, cell[:20].hex()))

                logging.debug('WsServ: Sent data to channel {}: {}... {} bytes.'.format(channel.cid, cell[:20], len(cell)))

            except websockets.exceptions.ConnectionClosed as err:
                logging.exception()
                return


    async def _timeout(self, ws, channel):
        """
        Handler to send termination cells in case of a timeout.
        :param ws: The websocket used to communicate with the client.
        :param channel: Channel from which data is sent.
        """
        await asyncio.sleep(self.timeout)

        logging.debug('WsServ: Channel {} timed out.'.format(channel.cid))

        await self.channel_manager.destroy_circuit_from_client(channel)


    async def _destroy(self, ws, channel):
        """
        Handler to destroy the specific circuit.
        :param ws: The websocket used to communicate with the client.
        :param channel: Channel from which data is sent.
        """

        # Just await for the channel to be destroyed.
        await channel.destroyed.wait()


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
            asyncio.create_task(self._destroy(ws, channel)),
            #asyncio.create_task(self._timeout(ws, channel)),
            asyncio.create_task(self._recv(ws, channel)),
            asyncio.create_task(self._send(ws, channel))
        ]

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        #while not ws.closed:
        #    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        #    # Conditions to continue or stop listening.

        #    # Circuit destroyed -> close websocket.
        #    if tasks[0].done():
        #        logging.debug('WsServ: Channel {} destroyed.'.format(channel.cid))
        #        break

        #    # Long timeout -> close websocket.
        #    if tasks[1].done():
        #        logging.debug('WsServ: Ws handler timed out for channel {}.'.format(channel.cid))
        #        break
        #    else:
        #        # Channel has not timed out, so the timeout is resetted.
        #        tasks[1].cancel()
        #        tasks[1] = asyncio.create_task(self._timeout(ws, channel))
        #        logging.debug('WsServ: Reset timeout handler for channel {}.'.format(channel.cid))

        #    # If recv is done, restart it.
        #    if tasks[2].done() or tasks[2].cancelled():
        #        tasks[2] = asyncio.create_task(self._recv(ws, channel))
        #        logging.debug('WsServ: New recv task created for channel {}.'.format(channel.cid))

        #    # If send is done, restart it.
        #    if tasks[3].done() or tasks[3].cancelled():
        #        tasks[3] = asyncio.create_task(self._send(ws, channel))
        #        logging.debug('WsServ: New send task created for channel {}.'.format(channel.cid))

        # The channel is destroyed, and the connection needs to be closed.

        # Cancel tasks which are still pending.
        for task in tasks:
            if not (task.cancelled() or task.done()):
                task.cancel()

        # Delete the channel and close the websocket.
        self.channel_manager.delete_channel(channel)
        await ws.close()

        logging.debug('WsServ: End handler for channel {}.'.format(channel.cid))
