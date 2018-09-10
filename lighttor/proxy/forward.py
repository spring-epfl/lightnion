import threading
import traceback
import logging
import base64
import flask
import queue
import time

import websockets
import asyncio

import lighttor as ltor
import lighttor.proxy

debug = True
tick_rate = 0.01 # (sleeps when nothing to do)
async_rate = 0.01 # (async.sleep while websocket-ing)

class clerk(threading.Thread):
    def __init__(self, slave_node, control_port, auth_dir=None):
        super().__init__()
        logging.info('Bootstrapping clerk.')
        self.crypto = ltor.proxy.parts.crypto()
        self.dead = False

        self.auth = None
        self.auth_dir = auth_dir
        if auth_dir is not None:
            try:
                self.auth = ltor.proxy.auth.getpkey(auth_dir)
            except FileNotFoundError:
                ltor.proxy.auth.genpkey(auth_dir)
                self.auth = ltor.proxy.auth.getpkey(auth_dir)
            logging.debug('Note: authentication suffix is {}'.format(
                self.auth.suffix))

        self.control_port = control_port
        self.slave_node = slave_node

        self.producer           = ltor.proxy.jobs.producer(self)
        self.slave              = ltor.proxy.jobs.slave(self)
        self.consensus_getter   = ltor.proxy.jobs.consensus(self)
        self.guard              = ltor.proxy.jobs.guard(self)
        self.create             = ltor.proxy.jobs.create(self)
        self.delete             = ltor.proxy.jobs.delete(self)

        self.jobs = [
            self.slave,
            self.producer,
            self.consensus_getter,
            self.guard,
            self.create,
            self.delete]

        self.channels = dict()

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

            for _ in range(ltor.proxy.jobs.refresh_batches):
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
                logging.warning('Exception:', e)
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
        except ltor.proxy.jobs.expired:
            pass

        await asyncio.sleep(async_rate / 2)

async def channel_output(websocket, channel):
    cells = None
    while True:
        try:
            if cells is None:
                try:
                    cells = channel.get(timeout=0)
                except ltor.proxy.jobs.expired:
                    channel.put([], timeout=async_rate/4)
                    cells = channel.get(timeout=async_rate/4)
            for cell in cells:
                await websocket.send(cell)

            channel.used = time.time()
            cells = None

            await asyncio.sleep(0)
            continue
        except ltor.proxy.jobs.expired:
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
            channel.tasks.append(
                asyncio.ensure_future(task(websocket, channel)))

        done, pending = await asyncio.wait(channel.tasks,
            return_when=asyncio.FIRST_COMPLETED)

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

        server = websockets.serve(self.handler, 'localhost', 8765,
            compression=None)
        asyncio.get_event_loop().run_until_complete(server)
        asyncio.get_event_loop().run_forever()

app = flask.Flask(__name__)
url = ltor.proxy.base_url

@app.route(url + '/consensus')
def get_consensus():
    try:
        return flask.jsonify(app.clerk.consensus_getter.perform()), 200
    except ltor.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/guard')
def get_guard():
    try:
        return flask.jsonify(app.clerk.guard.perform()), 200
    except ltor.proxy.jobs.expired:
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
        data = app.clerk.create.perform(data)
        if auth is not None:
            data = app.clerk.auth.perform(auth, data)

        return flask.jsonify(data), 201 # Created
    except ltor.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/channels/<uid>', methods=['POST'])
def write_channel(uid):
    if not flask.request.json or 'cells' not in flask.request.json:
        flask.abort(400)

    try:
        channel = app.clerk.channel_from_uid(uid)
    except RuntimeError:
        flask.abort(404)

    if len(flask.request.json['cells']) > ltor.proxy.jobs.request_max_cells:
        flask.abort(400)

    cells = [base64.b64decode(cell) for cell in flask.request.json['cells']]
    if any([len(cell) > ltor.constants.full_cell_len for cell in cells]):
        flask.abort(400)

    try:
        return flask.jsonify(dict(cells=channel.perform(cells))), 201
    except ltor.proxy.jobs.expired:
        flask.abort(503)

@app.route(url + '/channels/<uid>', methods=['DELETE'])
def delete_channel(uid):
    try:
        channel = app.clerk.channel_from_uid(uid)
    except RuntimeError:
        flask.abort(404)

    circuit = channel.circuit
    try:
        return flask.jsonify(app.clerk.delete.perform(circuit)), 202 # Deleted
    except ltor.proxy.jobs.expired:
        flask.abort(503)

def main(port, slave_node, control_port, purge_cache,
    static_files=None, auth_dir=None):
    if purge_cache:
        ltor.cache.purge()

    if static_files is not None:
        from werkzeug import SharedDataMiddleware
        app.wsgi_app = SharedDataMiddleware(app.wsgi_app, static_files)

    with clerk(slave_node, control_port, auth_dir) as app.clerk:
        logging.info('Bootstrapping HTTP server.')
        sockets(app.clerk).start()
        app.run(port=port, debug=debug, use_reloader=False)
