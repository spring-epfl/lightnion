import asyncio
import base64
import logging
import signal
import string
import sys
import threading
import time

from datetime import datetime, timedelta

import quart
import stem
import websockets

from quart_cors import cors
from stem.control import EventType, Controller

import lightnion as lnn
import lightnion.path_selection
import lightnion.proxy

from tools.keys import get_signing_keys_info

#from tools.keys import get_raw_signing_keys

debug = True

formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%H:%M:%S')
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.WARNING)
logger.addHandler(handler)

logger = logging.getLogger("asyncio")
logger.setLevel(logging.WARNING)
logger.addHandler(handler)


class Clerk():
    def __init__(self, slave_node, control_port, dir_port, controller, compute_path, auth_dir=None):
        #super().__init__()
        logging.info('Bootstrapping clerk.')
        self.crypto = lnn.proxy.parts.crypto()

        self.dead = False

        self.auth = None
        self.auth_dir = auth_dir
        if auth_dir is not None:
            try:
                self.auth = lnn.proxy.auth.getpkey(auth_dir)
                logging.debug('Auth dir is set.')
            except FileNotFoundError:
                lnn.proxy.auth.genpkey(auth_dir)
                self.auth = lnn.proxy.auth.getpkey(auth_dir)
                logging.debug('Auth dir got a file not found')
            logging.debug('Note: authentication suffix is {}'.format(self.auth.suffix))
        else:
            logging.debug('Auth dir is None.')

        self.consensus = None
        self.descriptors = None

        self.consensus_raw = None
        self.descriptors_raw = None
        self.mic_consensus_raw = None
        self.mic_descriptors_raw = None

        self.consensus_init = False

        #self.consm = None
        #self.descm = None
        self.signing_keys = None
        #self.signing_keys_raw = None

        self.guard_node = None

        self.control_port = control_port
        self.dir_port = dir_port
        self.slave_node = slave_node
        self.compute_path = compute_path

        self.link = None
        self.channel_manager = None
        self.websocket_manager = None

        self.controller = controller
        self.controller.add_event_listener(self.handle_new_guard, EventType.GUARD)
        self.controller.add_event_listener(self.retrieve_consensus, EventType.NEWCONSENSUS)


    def prepare(self):
        self.retrieve_consensus()
        guard = self.get_guard()

        self.link = lnn.proxy.link.Link(guard)
        self.channel_manager = lnn.proxy.jobs.ChannelManager()
        self.websocket_manager = lnn.proxy.jobs.WebsocketManager()

        self.link.set_channel_manager(self.channel_manager)
        self.channel_manager.set_link(self.link)
        self.websocket_manager.set_channel_manager(self.channel_manager)


    def retrieve_consensus(self, event=None):
        """Retrieve relays data with direct HTTP connection."""

        host = self.slave_node[0]
        port = self.dir_port

        # retrieve consensus and descriptors
        if self.compute_path:
            cons, sg_keys = lnn.consensus.download_direct(host, port, flavor='unflavored')
            desc = lnn.descriptors.download_direct(host, port, cons)
            self.consensus = cons
            self.signing_keys = sg_keys
            self.descriptors = desc

            #self.consm,sg_keysm = lnn.consensus.download_direct(self.slave_node[0], self.dir_port)
            #self.descm = lnn.descriptors.download_direct(self.slave_node[0], self.dir_port, self.consm, flavor='microdesc')

        self.consensus_raw = lnn.consensus.download_raw(host, port, flavor='unflavored')
        digests = lnn.consensus.extract_nodes_digests_unflavored(self.consensus_raw)
        self.descriptors_raw = lnn.descriptors.download_raw_by_digests_unflavored(host, port, digests)

        keys = get_signing_keys_info('{}:{}'.format(host, port))
        self.signing_keys = keys
        #self.signing_keys_raw = get_raw_signing_keys('%s:%d'%(host, port))

        self.mic_consensus_raw = lnn.consensus.download_raw(host, port, flavor='microdesc')
        digests = lnn.consensus.extract_nodes_digests_micro(self.mic_consensus_raw)
        self.mic_descriptors_raw = lnn.descriptors.download_raw_by_digests_micro(host, port, digests)

        self.consensus_init = True


    def wait_for_consensus(self):
        """Ensure a consensus is present in the clerk, and fetch a new one if it is not.
        """

        while not self.consensus_init:
            logging.info('Wait for consensus...')
            time.sleep(1)


    def get_descriptor_unflavoured(self, router):
        """Retrieve a descriptor.
        :param router: Router from which we want the descriptor.
        :return: the descriptor of the given router.
        """

        descriptor = self.descriptors[router['digest']]

        return descriptor


    def handle_new_guard(self, event):
        self.get_guard(renew=True)


    def get_guard(self, renew=False):
        """Generate a guard
        :return: guard node
        """

        if renew or self.guard_node is None:
            # Use local node as the guard.
            #guard = lnn.path_selection.select_guard_from_consensus(self.consensus, self.descriptors)
            host = self.slave_node[0]
            port = self.dir_port

            guard = lnn.descriptors.download_relay_descriptor(host, port)

            #nickname = guard['router']['nickname']
            #fingerprint = guard['fingerprint']
            #entry = [fingerprint, nickname]
            #guard = lnn.proxy.path.convert(entry, consensus=self.consensus, expect='list')[0]

            logging.info('New guard relay selected.')
            logging.debug(guard)
            self.guard_node = guard

        return self.guard_node


app = quart.Quart(__name__)
cors(app, expose_headers='Access-Control-Allow-Origin')
url = lnn.proxy.base_url

@app.route(url + '/descriptors')
def get_descriptors():
    try:
        app.clerk.wait_for_consensus()
        desc = quart.jsonify(app.clerk.descriptors)
        return desc, 200
    except Exception as e:
        logging.exception(e)
        quart.abort(503)

@app.route(url + '/consensus')
async def get_consensus():
    """
    Retrieve consensus.
    """
    try:
        app.clerk.wait_for_consensus()
        cons = quart.jsonify(app.clerk.consensus)
        return cons, 200
    except Exception as e:
        logging.exception(e)
        quart.abort(503)

@app.route(url + '/descriptors-raw/<flavor>')
def get_descriptors_raw(flavor):
    try:
        app.clerk.wait_for_consensus()

        desc = app.clerk.mic_descriptors_raw
        if flavor == 'unflavored':
            desc = app.clerk.descriptors_raw

        return desc, 200
    except Exception as e:
        logging.exception(e)
        quart.abort(503)

@app.route(url + '/consensus-raw/<flavor>')
async def get_consensus_raw(flavor):
    """
    Retrieve raw consensus.
    """
    try:
        app.clerk.wait_for_consensus()
        cons = app.clerk.mic_consensus_raw
        if flavor == 'unflavored':
            cons = app.clerk.consensus_raw

        return cons, 200
    except Exception as e:
        logging.exception(e)
        quart.abort(503)

@app.route(url + '/signing-keys')
async def get_signing_keys():
    """
    Retrieve signing keys to verify consensus.
    """
    try:
        app.clerk.wait_for_consensus()
        keys = app.clerk.signing_keys
        return keys, 200
    except Exception as e:
        logging.exception(e)
        quart.abort(503)

@app.route(url + '/guard')
async def get_guard():
    """
    Retrieve guard descriptor.
    """
    try:
        guard = app.clerk.link.guard
        res = quart.jsonify(guard)
        return res, 200
    except Exception as e:
        logging.exception(e)
        quart.abort(503)


@app.route(url + '/channels', methods=['POST'])
async def create_channel():
    """
    Create a channel.
    """
    payload = await quart.request.get_json()
    #if not payload or not 'ntor' in payload:
    #    quart.abort(400)

    logging.info('Create new channel.')
    #ntor = payload['ntor']

    auth = None
    if 'auth' in payload:
        auth = payload['auth']
        if app.clerk.auth is None:
            quart.abort(400)

    select_path = False
    if 'select_path' in payload:
        if payload['select_path'] == "true":
            select_path = True

    if not select_path:
        app.clerk.wait_for_consensus()

    try:
        #data = app.clerk.create.perform(data)
        ckt_info = app.clerk.channel_manager.create_channel(app.clerk.consensus, app.clerk.descriptors, select_path)
        if auth is not None:
            # TODO the proxy pack the ntor key in a tor cell, this can be done client side.
            ckt_info = app.clerk.auth.perform(auth, ckt_info)

        response = quart.jsonify(ckt_info)
        return response, 201 # Created

    except Exception as e:
        logging.exception(e)
        quart.abort(503)


@app.route(url + '/channels/<uid>', methods=['DELETE'])
async def delete_channel(uid):
    """
    Delete a channel.
    :param uid: channel identifier
    """
    try:
        channel = app.clerk.channel_manager.get_channel_by_token(uid)
    except Exception as e:
        logging.exception(e)
        quart.abort(404)

    try:
        await app.clerk.channel_manager.destroy_circuit_from_client(channel)
        await app.clerk.channel_manager.destroy_circuit_from_link(channel)
    except Exception as e:
        logging.exception(e)
        quart.abort(500)

    return quart.jsonify({}), 202 # Deleted


async def loop_signal_handler(signum, loop):
    """
    Handler to stop coroutines.
    """

    logging.debug('Signal handler called.')
    await app.shutdown()
    await app.clerk.websocket_manager.stop()

    tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

    for task in tasks:
        task.cancel()

    await asyncio.gather(*tasks)

    loop.stop()


def main(port, slave_node, control_port, dir_port, compute_path, auth_dir=None):
    """
    Entry point
    """

    #if static_files is not None:
    #    from werkzeug import SharedDataMiddleware
    #    app.wsgi_app = SharedDataMiddleware(app.wsgi_app, static_files)

    with Controller.from_port(port=control_port) as controller:
        controller.authenticate()

        app.clerk = Clerk(slave_node, control_port, dir_port, controller, compute_path, auth_dir)
        logging.info('Bootstrapping HTTP server.')

        logging.getLogger(websockets.__name__).setLevel(logging.INFO)
        asyncio.set_event_loop(asyncio.new_event_loop())

        app.clerk.prepare()

        loop = asyncio.get_event_loop()
        for s in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(s, lambda s=s: asyncio.create_task(loop_signal_handler(s, loop)))

        loop.set_exception_handler(None)

        try:
            loop.create_task(app.clerk.link.connection)
            loop.create_task(app.clerk.websocket_manager.serve(loop))

            app.run(host='0.0.0.0', port=port, debug=debug, loop=loop, use_reloader=False)
        except Exception:
            pass
        finally:
            loop.close()
