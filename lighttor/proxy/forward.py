import threading
import traceback
import secrets
import logging
import base64
import flask
import queue
import time

import lighttor as ltor
import lighttor.proxy

debug = True

per_request_max_cell = 120
send_batch = ltor.proxy.jobs.default_qsize * per_request_max_cell
recv_batch = ltor.proxy.jobs.default_qsize * per_request_max_cell

tick_rate = 0.01 if not debug else 0.1
queue_size = 5
query_time = 6
nonce_size = 12

refresh_timeout = 5
isalive_timeout = 30

class crypto:
    from cryptography.exceptions import InvalidTag

    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as gcm

        self.binding = secrets.token_bytes(32)
        self.gcm = gcm(gcm.generate_key(bit_length=128))

    def compute_token(self, circuit_id, binding):
        circuit_id = ltor.cell.view.uint(4).write(b'', circuit_id)

        nonce = secrets.token_bytes(nonce_size)
        token = self.gcm.encrypt(nonce, circuit_id, self.binding + binding)
        token = base64.urlsafe_b64encode(nonce + token)
        return str(token.replace(b'=', b''), 'utf8')

    def decrypt_token(self, token, binding):
        try:
            if not isinstance(token, str):
                token = str(token, 'utf8')
            token = base64.urlsafe_b64decode(token + '====')
        except BaseException:
            return None

        if len(token) != 32:
            return None

        binding = self.binding + binding
        nonce, token = token[:nonce_size], token[nonce_size:]
        try:
            circuit_id = self.gcm.decrypt(nonce, token, binding)
        except self.InvalidTag:
            return None

        if len(circuit_id) != 4:
            return None

        return int.from_bytes(circuit_id, byteorder='big')

class clerk(threading.Thread):
    def __init__(self, slave_node, control_port):
        super().__init__()
        logging.info('Bootstrapping clerk.')
        self.control_port = control_port
        self.slave_node = slave_node

        self.crypto = crypto()

        self._lock = threading.RLock()
        self.dead = False

        self.nb_actions = 0
        self.tick = 0

        self.producer = ltor.proxy.jobs.producer(self)
        self.slave = ltor.proxy.jobs.slave(self)

        self.consensus_getter = ltor.proxy.jobs.consensus(self)
        self.guard = ltor.proxy.jobs.guard(self)

        self.create = ltor.proxy.jobs.create(self)
        self.delete = ltor.proxy.jobs.delete(self)

        self._send_trigger = queue.Queue(maxsize=send_batch)

        self.jobs = [
            self.slave,
            self.producer,
            self.consensus_getter,
            self.guard,
            self.create,
            self.delete]

    def die(self, e):
        if isinstance(e, str):
            logging.error(e)
            e = RuntimeError(e)

        self.dead = True
        raise e

    def circuit_from_uid(self, uid):
        circuit_id = self.crypto.decrypt_token(uid, self.maintoken)
        if circuit_id is None:
            logging.debug('Got an invalid token: {}'.format(uid))
            raise RuntimeError('Invalid token.')

        if circuit_id not in self.guard.link.circuits:
            logging.debug('Got an unknown circuit: {}'.format(circuit_id))
            raise RuntimeError('Unknown circuit: {}'.format(circuit_id))

        circuit = self.guard.link.circuits[circuit_id]
        circuit.used = time.time()
        return circuit

    def perform_pending_send(self):
        try:
            payload = self._send_trigger.get_nowait()
            self.guard.link.send(payload)
            return True
        except queue.Empty:
            return False

    def main(self):
        for job in self.jobs:
            if not job.isalive():
                job.reset()

        for job in self.jobs:
            if job.isfresh():
                continue

            for _ in range(ltor.proxy.jobs.refresh_batches):
                if job.refresh():
                    continue
                break

        for _ in range(ltor.proxy.jobs.refresh_batches):
            if self.perform_pending_send():
                continue
            break
        time.sleep(tick_rate)

    def run(self):
        while not self.dead:
            try:
                self.main()
            except BaseException as e:
                logging.warning('Exception:', e)
                if debug:
                    traceback.print_exc()

    def send(self, payload, circuit, timeout=1):
        if len(payload) != ltor.constants.full_cell_len:
            logging.debug('Got invalid size for cell.')
            flask.abort(400)
        payload = ltor.cell.header_view.write(payload, circuit_id=circuit.id)

        try:
            self._send_trigger.put(payload, timeout=timeout)
        except queue.Full:
            flask.abort(503)

    def recv(self, circuit, timeout=1):
        timeout = timeout / recv_batch
        received = []
        try:
            for _ in range(recv_batch):
                payload = circuit.queue.get(timeout=timeout)
                payload = ltor.cell.header_view.write(payload,
                    circuit_id=ltor.proxy.fake_circuit_id)

                received.append(str(base64.b64encode(payload), 'utf8'))
        except queue.Empty:
            pass

        return dict(cells=received)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *kargs):
        self.dead = True
        self.join()

app = flask.Flask(__name__)
base_url = ltor.proxy.base_url

@app.route(base_url + '/consensus')
def get_consensus():
    try:
        return flask.jsonify(app.clerk.consensus_getter.perform()), 200
    except ltor.proxy.jobs.expired:
        flask.abort(503)

@app.route(base_url + '/guard')
def get_guard():
    try:
        return flask.jsonify(app.clerk.guard.perform()), 200
    except ltor.proxy.jobs.expired:
        flask.abort(503)

@app.route(base_url + '/channels', methods=['POST'])
def create_channel():
    if not flask.request.json or not 'ntor' in flask.request.json:
        flask.abort(400)

    try:
        data = flask.request.json['ntor']
        return flask.jsonify(app.clerk.create.perform(data)), 201 # Created
    except ltor.proxy.jobs.expired:
        flask.abort(503)

@app.route(base_url + '/channels/<uid>', methods=['POST'])
def write_channel(uid):
    if not flask.request.json or 'cells' not in flask.request.json:
        flask.abort(400)

    try:
        circuit = app.clerk.circuit_from_uid(uid)
    except RuntimeError:
        flask.abort(404)

    if len(flask.request.json['cells']) > per_request_max_cell:
        flask.abort(404)

    for cell in flask.request.json['cells']:
        cell = base64.b64decode(cell)
        app.clerk.send(cell, circuit)

    return flask.jsonify(app.clerk.recv(circuit)), 201 # Created

@app.route(base_url + '/channels/<uid>', methods=['DELETE'])
def delete_channel(uid):
    try:
        circuit = app.clerk.circuit_from_uid(uid)
    except RuntimeError:
        flask.abort(404)

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
