import threading
import traceback
import logging
import base64
import flask
import queue
import time

import lighttor as ltor
import lighttor.proxy

debug = True
tick_rate = 0.1 # (sleeps when nothing to do)

class clerk(threading.Thread):
    def __init__(self, slave_node, control_port):
        super().__init__()
        logging.info('Bootstrapping clerk.')
        self.crypto = ltor.proxy.parts.crypto()
        self.dead = False

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

    try:
        data = flask.request.json['ntor']
        return flask.jsonify(app.clerk.create.perform(data)), 201 # Created
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

def main(port, slave_node, control_port, purge_cache):
    if purge_cache:
        ltor.cache.purge()

    with clerk(slave_node, control_port) as app.clerk:
        logging.info('Bootstrapping HTTP server.')
        app.run(port=port, debug=debug, use_reloader=False)
