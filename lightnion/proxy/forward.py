import threading
import traceback
import logging
import base64
import quart
from quart_cors import cors
import queue
import string
import time

from datetime import datetime, timedelta

import websockets
import asyncio
import sys
import signal

import lightnion as lnn
import lightnion.proxy
import lightnion.path_selection

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


class clerk():
    def __init__(self, slave_node, control_port, dir_port, auth_dir=None):
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
        self.timer_consensus = None

        self.guard_node = None

        self.control_port = control_port
        self.dir_port = dir_port
        self.slave_node = slave_node

        self.link = None
        self.channel_manager = None
        self.websocket_manager = None

    def prepare(self):
        guard = self.get_guard()

        self.link = lnn.proxy.link.Link(guard)
        self.channel_manager = lnn.proxy.jobs.ChannelManager()
        self.websocket_manager = lnn.proxy.jobs.WebsocketManager()

        self.link.set_channel_manager(self.channel_manager)
        self.channel_manager.set_link(self.link)
        self.websocket_manager.set_channel_manager(self.channel_manager)

    def retrieve_consensus(self):
        """Retrieve relays data with direct HTTP connection and schedule its future retrival."""

        # We tolerate that the system clock can be up to a few seconds too early.
        refresh_tolerance_delay = 2.0

        # retrieve consensus and descriptors
        cons = lnn.consensus.download_direct(self.slave_node[0], self.dir_port, flavor='unflavored')
        desc = lnn.descriptors.download_direct(self.slave_node[0], self.dir_port, cons)

        self.descriptors = desc
        self.consensus = cons

        try:
            # Compute delay until retrival of the next consensus.
            fresh_until = datetime.utcfromtimestamp(self.consensus['headers']['fresh-until']['stamp'])
            now = datetime.utcnow()
            delay = (fresh_until - now).total_seconds() + refresh_tolerance_delay

            self.timer_consensus = threading.Timer(delay, clerk.retrieve_consensus, [self])
            self.timer_consensus.start()

        except Exception as e:
            logging.error(e)
            raise e


    def wait_for_consensus(self):
        """Ensure a consensus is present in the clerk, and fetch a new one if it is not.
        """
        if self.consensus is None:
            if self.timer_consensus is None:
                self.retrieve_consensus()
        while self.consensus is None:
            logging.info('Wait for consensus...')
            time.sleep(1)


    def get_descriptor_unflavoured(self, router):
        """Retrieve a descriptor.
        :param router: Router from which we want the descriptor.
        :return: the descriptor of the given router.
        """

        descriptor = self.descriptors[router['digest']]

        return descriptor


    def get_guard(self):
        """Generate a guard
        :return: guard node
        """

        self.wait_for_consensus()

        if self.guard_node is None:
            guard = lnn.path_selection.select_guard_from_consensus(self.consensus, self.descriptors)
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
        return flask.jsonify(app.clerk.slave.descriptors(app.clerk.slave.consensus())), 200
    except lnn.proxy.jobs.expired:
        flask.abort(503)

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
    if not payload or not 'ntor' in payload:
        quart.abort(400)

    logging.info('Create new channel.')
    ntor = payload['ntor']

    auth = None
    if 'auth' in payload:
        auth = payload['auth']
        if app.clerk.auth is None:
            quart.abort(400)

    app.clerk.wait_for_consensus()

    try:
        #data = app.clerk.create.perform(data)
        ntor_res = app.clerk.channel_manager.create_channel(ntor, app.clerk.consensus, app.clerk.descriptors)
        if auth is not None:
            # TODO the proxy pack the ntor key in a tor cell, this can be done client side.
            ntor_res = app.clerk.auth.perform(auth, ntor_res)

        response = quart.jsonify(ntor_res)
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


def main(port, slave_node, control_port, dir_port, purge_cache, static_files=None, auth_dir=None):
    """
    Entry point
    """

    if purge_cache:
        lnn.cache.purge()

    #if static_files is not None:
    #    from werkzeug import SharedDataMiddleware
    #    app.wsgi_app = SharedDataMiddleware(app.wsgi_app, static_files)

    app.clerk = clerk(slave_node, control_port, dir_port, auth_dir)
    logging.info('Bootstrapping HTTP server.')

    logging.getLogger(websockets.__name__).setLevel(logging.INFO)
    asyncio.set_event_loop(asyncio.new_event_loop())

    app.clerk.prepare()

    loop = asyncio.get_event_loop()
    loop.set_exception_handler(None)

    loop.create_task(app.clerk.link.connection)
    loop.create_task(app.clerk.websocket_manager.serve(loop))

    def signal_handler(signum, frame):
        """
        Handler to stop coroutines.
        """
        logging.debug('Signal handler called.')
        app.clerk.websocket_manager.stop()
        loop.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    app.run(host='0.0.0.0', port=port, debug=debug, loop=loop, use_reloader=False)
