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
import websockets

from quart_cors import cors

import lightnion as lnn
import lightnion.path_selection
import lightnion.proxy

from tools.keys import get_signing_keys_info

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
    def __init__(self, slave_node, control_port, dir_port, compute_path, auth_dir=None):
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

        self.retrieved_consensus = False
        self.consensus = None
        self.descriptors = None

        self.consensus_raw = None
        self.descriptors_raw = None
        self.mic_consensus_raw = None
        self.mic_descriptors_raw = None

        #self.consm = None
        #self.descm = None
        self.signing_keys = None

        self.timer_consensus = None

        self.guard_node = None

        self.control_port = control_port
        self.dir_port = dir_port
        self.slave_node = slave_node
        self.compute_path = compute_path

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
        min_delay = 120.0 # 2 minutes
        max_time_until_invalid = 900.0 # 15 minutes

        host = self.slave_node[0]
        port = self.dir_port

        # retrieve consensus and descriptors
        if self.compute_path:
            cons,sg_keys = lnn.consensus.download_direct(host, port, flavor='unflavored')
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

        self.mic_consensus_raw = lnn.consensus.download_raw(self.slave_node[0], self.dir_port, flavor='microdesc')
        digests = lnn.consensus.extract_nodes_digests_micro(self.mic_consensus_raw)
        self.mic_descriptors_raw = lnn.descriptors.download_raw_by_digests_micro(self.slave_node[0], self.dir_port, digests)

        try:
            # Compute delay until retrival of the next consensus.
            fresh_until = lnn.consensus.extract_date(self.consensus_raw, 'fresh-until')
            now = datetime.utcnow()
            delay = (fresh_until - now).total_seconds() + refresh_tolerance_delay

            if delay < min_delay:
                valid_until = lnn.consensus.extract_date(self.consensus_raw, 'valid-until')
                delay = (valid_until - now).total_seconds() - max_time_until_invalid

            delay = max(delay, min_delay)

            logging.debug('Delay until fetching next concensus: %f', delay)

            self.timer_consensus = threading.Timer(delay, clerk.retrieve_consensus, [self])
            self.timer_consensus.start()
            self.retrieved_consensus = True

        except Exception as e:
            logging.error(e)
            raise e


    def wait_for_consensus(self):
        """Ensure a consensus is present in the clerk, and fetch a new one if it is not.
        """
        if not self.retrieved_consensus:
            if self.timer_consensus is None:
                self.retrieve_consensus()

        while not self.retrieved_consensus:
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
            cons =app.clerk.consensus_raw

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
        keys = quart.jsonify(app.clerk.signing_keys)
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
        ckt_info = app.clerk.channel_manager.create_channel( app.clerk.consensus, app.clerk.descriptors, select_path)
        if auth is not None:
            # TODO the proxy pack the ntor key in a tor cell, this can be done client side.
            ckt_info = app.clerk.auth.perform(auth,ckt_info)

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


def main(port, slave_node, control_port, dir_port, compute_path, auth_dir=None):
    """
    Entry point
    """

    #if static_files is not None:
    #    from werkzeug import SharedDataMiddleware
    #    app.wsgi_app = SharedDataMiddleware(app.wsgi_app, static_files)

    app.clerk = clerk(slave_node, control_port, dir_port, compute_path, auth_dir)
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
