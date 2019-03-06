import threading
import traceback
import logging
import base64
import flask
import queue
import time

from datetime import datetime, timedelta

import websockets
import asyncio

import lightnion as lnn
import lightnion.proxy
import lightnion.path_selection

debug = True
tick_rate = 0.01 # (sleeps when nothing to do)
async_rate = 0.01 # (async.sleep while websocket-ing)

class clerk(threading.Thread):
    def __init__(self, slave_node, control_port, dir_port, auth_dir=None):
        super().__init__()
        logging.info('Bootstrapping clerk.')
        self.crypto = lnn.proxy.parts.crypto()
        self.dead = False

        self.auth = None
        self.auth_dir = auth_dir
        if auth_dir is not None:
            try:
                self.auth = lnn.proxy.auth.getpkey(auth_dir)
            except FileNotFoundError:
                lnn.proxy.auth.genpkey(auth_dir)
                self.auth = lnn.proxy.auth.getpkey(auth_dir)
            logging.debug('Note: authentication suffix is {}'.format(
                self.auth.suffix))

        self.consensus = None
        self.descriptors = None
        self.timer_consensus = None

        self.guard_node = None

        self.control_port = control_port
        self.dir_port = dir_port
        self.slave_node = slave_node

        self.guard    = lnn.proxy.jobs.guard(self)

        self.jobs = [ self.guard ]

        self.channels = dict()


    def get_consensus(self):
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

            self.timer_consensus = threading.Timer(delay, clerk.get_consensus, [self])
            self.timer_consensus.start()

        except Exception as e:
            logging.error(e)
            raise e


    def wait_for_consensus(self):
        if self.consensus is None:
            if self.timer_consensus is None:
                self.get_consensus()
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
            self.guard_node = guard

        return self.guard_node


    def get_end_path(self):
        """Generate a path
        :return: middle and exit nodes
        """

        self.wait_for_consensus()

        if self.guard_node is None:
            self.get_guard()

        (middle, exit) = lnn.path_selection.select_end_path_from_consensus(self.consensus, self.descriptors, self.guard_node)
        return (middle, exit)


    def create_channel(self, data):
        """Create a new channel.
        :param data: Public key of the connecting client encoded in base64.
        """
        # TODO: guard dependance to be removed
        data = base64.b64decode(data)

        if not self.guard.isalive():
            self.guard.reset()
        if not self.guard.isfresh():
            self.guard.refresh()

        # fast channel:
        #   if no identity/onion-key is given within the ntor handshake, the
        #   client doesn't know the guard identity/onion-key and we default to
        #   any guard we want!
        #
        fast = False
        if len(data) == 32:
            fast = True
            identity = base64.b64decode(self.guard.desc['router']['identity'] + '====')
            onion_key = base64.b64decode(self.guard.desc['ntor-onion-key'] + '====')
            data = identity + onion_key + data

        circid, data = lnn.create.ntor_raw(self.guard.link, data, timeout=1)
        circuit = lnn.create.circuit(circid, None)
        data = str(base64.b64encode(data), 'utf8')

        self.wait_for_consensus()

        path_raw = self.get_end_path()
        path = [[p['fingerprint'], p['router']['nickname']] for p in path_raw]

        middle, exit = lnn.proxy.path.convert(*path, consensus=self.consensus, expect='list')

        middle = self.get_descriptor_unflavoured(middle)
        exit = self.get_descriptor_unflavoured(exit)

        token = self.crypto.compute_token(circid, self.maintoken)

        logging.debug('Circuit created with circuit_id: {}'.format(circid))
        logging.debug('Path picked: {} -> {}'.format(middle['router']['nickname'], exit['router']['nickname']))
        logging.debug('Token emitted: {}'.format(token))

        answer = {'id': token, 'path': [middle, exit], 'handshake': data}
        if fast:
            answer['guard'] = self.guard.desc

        self.channels[circuit.id] = lnn.proxy.jobs.channel(self, circuit, self.guard.link)

        now = time.time()
        self.guard.used = now
        circuit.used = now

        return answer


    def delete_channel(self, circuit):
        """Delete an existing channel.
        :param circuit: Circuit associated with the channel.
        """
        # TODO: guard dependance to be removed
        guard = self.get_guard()

        if not self.guard.isalive():
            self.guard.reset()
            logging.warning('Guard was found dead when attempting to destroy a circuit.')
            return

        self.guard.link.unregister(circuit)
        logging.debug('Deleting circuit: {}'.format(circuit.id))

        reason = lnn.cell.destroy.reason.REQUESTED
        self.guard.link.send(lnn.cell.destroy.pack(circuit.id, reason))
        logging.debug('Remaining circuits: {}'.format(list(self.guard.link.circuits)))

        circuit.destroyed = True
        circuit.reason = reason


    def die(self, e):
        if isinstance(e, str):
            logging.error(e)
            e = RuntimeError(e)

        self.dead = True
        raise e

    def channel_from_uid(self, uid):
        circuit_id = self.crypto.decrypt_token(uid, self.maintoken)
        if circuit_id is None:
            logging.debug('Got an invalid token: {}'.format(uid))
            raise RuntimeError('Invalid token.')

        if circuit_id not in self.channels:
            logging.debug('Got an unknown circuit: {}'.format(circuit_id))
            raise RuntimeError('Unknown circuit: {}'.format(circuit_id))

        channel = self.channels[circuit_id]
        channel.used = time.time()
        channel.circuit.used = time.time()
        return channel

    def main(self):
        channels = [channel for _, channel in self.channels.items()]
        for job in self.jobs + channels:
            if not job.isalive():
                job.reset()

        bored = True
        for job in self.jobs + channels:
            if job.isfresh():
                continue

            for _ in range(lnn.proxy.jobs.refresh_batches):
                if job.refresh():
                    bored = False
                    continue
                break

        if bored:
            time.sleep(tick_rate)

    def run(self):
        while not self.dead:
            try:
                self.main()
            except BaseException as e:
                logging.warning(e)
                if debug:
                    traceback.print_exc()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *kargs):
        self.dead = True
        self.join()

async def channel_input(websocket, channel):
    cell = None
    while True:
        try:
            if cell is None:
                cell = await websocket.recv()
            channel.put([cell], timeout=async_rate/2)
            cell = None

            await asyncio.sleep(0)
            continue
        except lnn.proxy.jobs.expired:
            pass

        await asyncio.sleep(async_rate / 2)

async def channel_output(websocket, channel):
    cells = None
    while True:
        try:
            if cells is None:
                try:
                    cells = channel.get(timeout=0)
                except lnn.proxy.jobs.expired:
                    channel.put([], timeout=async_rate/4)
                    cells = channel.get(timeout=async_rate/4)
            for cell in cells:
                await websocket.send(cell)

            channel.used = time.time()
            cells = None

            await asyncio.sleep(0)
            continue
        except lnn.proxy.jobs.expired:
            pass

        await asyncio.sleep(async_rate / 2)

def channel_handler(clerk):
    async def _handler(websocket, path):
        if not path.startswith(url + '/channels/'):
            return

        path = path[len(url + '/channels/'):]
        if len(path) > 50:
            return
        channel = clerk.channel_from_uid(path)

        for task in [channel_input, channel_output]:
            channel.tasks.append(asyncio.ensure_future(task(websocket, channel)))

        done, pending = await asyncio.wait(channel.tasks, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()
    return _handler

class sockets(threading.Thread):
    def __init__(self, clerk):
        super().__init__()
        self.handler = channel_handler(clerk)

    def run(self):
        logging.getLogger(websockets.__name__).setLevel(logging.ERROR)
        asyncio.set_event_loop(asyncio.new_event_loop())

        server = websockets.serve(self.handler, '0.0.0.0', 8765, compression=None)
        asyncio.get_event_loop().run_until_complete(server)
        asyncio.get_event_loop().run_forever()

app = flask.Flask(__name__)
url = lnn.proxy.base_url

@app.route(url + '/descriptors')
def get_descriptors():
    try:
        return flask.jsonify(app.clerk.slave.descriptors(app.clerk.slave.consensus())), 200
    except lnn.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/consensus')
def get_consensus():
    try:
        app.clerk.wait_for_consensus()
        cons = flask.jsonify(app.clerk.consensus)
        logging.debug('GET /consensus')
        logging.debug('consensus:\n%s' % cons.data.decode('utf-8'))
        return cons, 200
    except lnn.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/guard')
def get_guard():
    try:
        guard = flask.jsonify(app.clerk.guard.perform())
        return guard, 200
    except lnn.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/channels', methods=['POST'])
def create_channel():
    if not flask.request.json or not 'ntor' in flask.request.json:
        flask.abort(400)
    data = flask.request.json['ntor']

    auth = None
    if 'auth' in flask.request.json:
        auth = flask.request.json['auth']
        if app.clerk.auth is None:
            flask.abort(400)

    try:
        #data = app.clerk.create.perform(data)
        data = app.clerk.create_channel(data)
        if auth is not None:
            data = app.clerk.auth.perform(auth, data)

        data = flask.jsonify(data)
        return data, 201 # Created
    except lnn.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/channels/<uid>', methods=['POST'])
def write_channel(uid):
    if not flask.request.json or 'cells' not in flask.request.json:
        flask.abort(400)

    try:
        channel = app.clerk.channel_from_uid(uid)
    except RuntimeError:
        flask.abort(404)

    if len(flask.request.json['cells']) > lnn.proxy.jobs.request_max_cells:
        flask.abort(400)

    cells = [base64.b64decode(cell) for cell in flask.request.json['cells']]

    if any([len(cell) > lnn.constants.full_cell_len for cell in cells]):
        flask.abort(400)

    try:
        return flask.jsonify(dict(cells=channel.perform(cells))), 201
    except lnn.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/channels/<uid>', methods=['DELETE'])
def delete_channel(uid):
    try:
        channel = app.clerk.channel_from_uid(uid)
    except RuntimeError:
        flask.abort(404)

    circuit = channel.circuit
    try:
        clerk.delete_channel(circuit)
        return flask.jsonify({}), 202 # Deleted
        #return flask.jsonify(app.clerk.delete.perform(circuit)), 202 # Deleted
    except lnn.proxy.jobs.expired:
        flask.abort(503)

def main(port, slave_node, control_port, dir_port, purge_cache, static_files=None, auth_dir=None):
    if purge_cache:
        lnn.cache.purge()

    if static_files is not None:
        from werkzeug import SharedDataMiddleware
        app.wsgi_app = SharedDataMiddleware(app.wsgi_app, static_files)

    with clerk(slave_node, control_port, dir_port, auth_dir) as app.clerk:
        logging.info('Bootstrapping HTTP server.')
        sockets(app.clerk).start()
        app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False)
