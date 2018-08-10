import threading
import traceback
import secrets
import logging
import hashlib
import base64
import flask
import queue
import time

import lighttor as ltor
import lighttor.proxy

debug = True
tick_rate = 0.1
send_batch = 32
recv_batch = 32
queue_size = 5
query_time = 6

refresh_timeout = 5
isalive_timeout = 30

class _abort_lock:
    def __init__(self, lock):
        self._lock = lock
        self.acquired = False

    def __enter__(self):
        if self._lock.acquire(blocking=False):
            self.acquired = True
            return
        flask.abort(503)

    def __exit__(self, *kargs):
        if self.acquired:
            return self._lock.release()

class crypto:
    from cryptography.exceptions import InvalidTag

    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as gcm

        self.binding = secrets.token_bytes(32)
        self.gcm = gcm(gcm.generate_key(bit_length=128))

    def compute_token(self, circuit_id, binding):
        circuit_id = ltor.cell.view.uint(4).write(b'', circuit_id)

        nonce = secrets.token_bytes(12)
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
        nonce, token = token[:12], token[12:]
        try:
            circuit_id = self.gcm.decrypt(nonce, token, binding)
        except self.InvalidTag:
            return None

        if len(circuit_id) != 4:
            return None

        return int.from_bytes(circuit_id, byteorder='big')

class clerk(threading.Thread):
    def __init__(self, slave_node, bootstrap_node):
        super().__init__()
        logging.info('Bootstrapping clerk.')

        self.crypto = crypto()

        self._lock = threading.RLock()
        self.dead = False

        self.nb_actions = 0
        self.tick = 0

        self.bootstrap_node = bootstrap_node
        self.slave_node = slave_node

        self.producer = ltor.proxy.jobs.producer(self)

        self.bootlink = None
        self.bootnode = None
        self.refresh_bootnode()

        self.consensus = dict(headers=None)
        self.refresh_consensus()

        self.guardlink = None
        self.guardnode = None
        self.maintoken = None
        self.refresh_guardnode()

        self._send_trigger = queue.Queue(maxsize=send_batch)
        self._delete_trigger = queue.Queue(maxsize=queue_size)
        self._create_trigger = queue.Queue(maxsize=queue_size)
        self._created_output = queue.Queue(maxsize=queue_size)

    @property
    def lock(self):
        return _abort_lock(self._lock)

    def die(self, e):
        if isinstance(e, str):
            logging.error(e)
            e = RuntimeError(e)

        self.dead = True
        raise e

    def get_circuit(self, uid, abort=False):
        circuit_id = self.crypto.decrypt_token(uid, self.maintoken)
        if circuit_id is None:
            logging.debug('Got an invalid token: {}'.format(uid))
            if abort:
                flask.abort(404)
            return None

        if circuit_id not in self.guardlink.circuits:
            logging.debug('Got an unknown circuit: {}'.format(circuit_id))
            if abort:
                flask.abort(404)
            return None

        return self.guardlink.circuits[circuit_id]

    def refresh_bootnode(self):
        logging.info('Refreshing bootstrap node link.')

        with self._lock:
            if self.bootlink is not None:
                self.bootlink.close()

                for _ in range(refresh_timeout):
                    if self.bootlink.io.dead:
                        break
                    time.sleep(1)

                if not self.bootlink.io.dead:
                    self.die('Unable to close bootstrap link, abort!')

            addr, port = self.bootstrap_node
            self.bootlink = ltor.link.initiate(address=addr, port=port)
            self.bootcirc = ltor.create.fast(self.bootlink)
            self.bootlast = time.time()

            if not self.isalive_bootnode(force_check=True):
                self.die('Unable to interact w/ bootstrap node, abort!')

    def refresh_consensus(self):
        with self._lock:
            if not self.isalive_bootnode():
                self.refresh_bootnode()

            self.bootcirc, census = ltor.consensus.download(self.bootcirc,
                flavor='unflavored')

            if census['headers']['valid-until']['stamp'] < time.time():
                self.die('Unable to get a fresh consensus, abort!')
            if not census['headers'] == self.consensus['headers']:
                logging.info('Consensus successfully refreshed.')

            self.consensus = census

            # (cache descriptors for later use)
            self.bootcirc, _ = ltor.descriptors.download(self.bootcirc,
                census, flavor='unflavored')

    def refresh_guardnode(self):
        logging.info('Refreshing guard node link.')

        with self._lock:
            if not self.isfresh_consensus():
                self.refresh_consensus()

            if not self.producer.isalive():
                self.producer.reset()

            guardnode = ltor.proxy.path.convert(self.producer.guard,
                consensus=self.consensus, expect='list')[0]

            if not self.guardnode == guardnode:
                logging.info('New guard: {}'.format(guardnode['nickname']))
            self.guardnode = guardnode

            if not self.isalive_bootnode():
                self.refresh_bootnode()

            self.bootcirc, guarddesc = ltor.descriptors.download(self.bootcirc,
                self.guardnode, flavor='unflavored', fail_on_missing=True)

            # TODO: link authentication instead of NTOR handshakes!
            addr, port = self.guardnode['address'], self.guardnode['orport']
            self.guardlink = ltor.link.initiate(address=addr, port=port)
            self.guardcirc = ltor.create.ntor(self.guardlink, guarddesc[0])
            self.guardlast = time.time()
            self.guarddesc = guarddesc[0]

            self.refresh_maintoken()

            self._guard_output = queue.Queue(maxsize=queue_size)
            if not self.isalive_guardnode(force_check=True):
                self.die('Unable to interact w/ guard node, abort!')

    def refresh_maintoken(self):
        logging.info('Refreshing guard node link.')

        with self._lock:
            if not self.isalive_guardnode():
                self.refresh_guardnode()

            token = hashlib.sha256(bytes(self.guardnode['identity'], 'utf8')
                + self.guardlink.io.binding()).digest()

            if not token == self.maintoken:
                logging.info('Shared tokenid updated.')

            self.maintoken = token
            logging.debug('Shared tokenid: {}'.format(token.hex()))

    def isalive_producer(self):
        with self._lock:
            return not self.producer.dead

    def isalive_bootnode(self, force_check=False):
        with self._lock:
            if self.bootlink is None:
                return False

            if self.bootlink.io.dead:
                logging.warning('Bootstrap node link seems dead.')
                return False

            if self.bootcirc.circuit.destroyed:
                logging.warning('Bootstrap node circuit got destroyed.')
                return False

            if force_check or (time.time() - self.bootlast) > isalive_timeout:
                logging.debug('Get bootstrap node descriptor (heath check).')

                circ, node = ltor.descriptors.download_authority(self.bootcirc)
                if self.bootnode not in (None, node['identity']):
                    self.die('Bootstrap node changed its identity, abort!')

                self.bootlast = time.time()
                self.bootcirc, self.bootnode = circ, node['identity']

            return True

    def isfresh_consensus(self):
        with self._lock:
            fresh_until = self.consensus['headers']['fresh-until']['stamp']
            return not (fresh_until < time.time())

    def isalive_guardnode(self, force_check=False):
        with self._lock:
            if self.guardlink is None:
                return False

            if self.guardlink.io.dead:
                logging.warning('Guard node link seems dead.')
                return False

            if self.guardcirc.circuit.destroyed:
                logging.warning('Guard keepalive circuit got destroyed.')
                return False

            if force_check or (time.time() - self.guardlast) > isalive_timeout:
                logging.debug('Get guard node descriptor (health check).')

                circ, guard = ltor.descriptors.download_authority(
                    self.guardcirc)

                if self.guardnode['identity'] != guard['router']['identity']:
                    logging.warning('Guard changed its identity, renew!')

                    self.producer.reset()
                    self.refresh_guardnode()
                    return self.isalive_guardnode()

                for key in ['ntor-onion-key', 'identity', 'router']:
                    if not (self.guarddesc[key] == guard[key]):
                        logging.info('Guard changed its {} field.'.format(key))

                        self.producer.reset()
                        self.refresh_guardnode()
                        return self.isalive_guardnode()

                self.guardlast = time.time()
                self.guardcirc = circ

            return True

    def perform_pending_create(self):
        try:
            rq, data = self._create_trigger.get_nowait()
            logging.info('Got an incoming create channel request.')
        except queue.Empty:
            return False

        try:
            circuit_id, payload = ltor.create.ntor_raw(self.guardlink, data)
            self.guardlink.register(ltor.create.circuit(circuit_id, None))
        except BaseException as e:
            logging.info('Got an invalid handshake, cause: {}'.format(e))
            payload = b''

        middle, exit = ltor.proxy.path.convert(*self.producer.get(),
            consensus=self.consensus, expect='list')

        self.bootcirc, middle = ltor.descriptors.download(self.bootcirc,
            middle, flavor='unflavored', fail_on_missing=True)
        self.bootcirc, exit = ltor.descriptors.download(self.bootcirc,
            exit, flavor='unflavored', fail_on_missing=True)

        token = self.crypto.compute_token(circuit_id, self.maintoken)
        payload = str(base64.b64encode(payload), 'utf8')

        logging.debug('Circuit created with circuit_id: {}'.format(
            circuit_id))
        logging.debug('Path picked: {} -> {}'.format(
            middle[0]['router']['nickname'], exit[0]['router']['nickname']))
        logging.debug('Token emitted: {}'.format(token))

        try:
            self._created_output.put_nowait((rq,
                {'id': token, 'path': [middle[0], exit[0]], 'ntor': payload}))
        except queue.Full:
            logging.warning('Too many create channel requests, dropping.')
            return False

        return True

    def perform_delete(self, circuit):
        self.guardlink.unregister(circuit)
        logging.debug('Deleting circuit: {}'.format(circuit.id))

        reason = ltor.cell.destroy.reason.REQUESTED
        self.guardlink.send(ltor.cell.destroy.pack(circuit.id, reason))
        logging.debug('Remaining circuits: {}'.format(list(
            self.guardlink.circuits)))

        return True

    def perform_pending_delete(self):
        try:
            uid = self._delete_trigger.get_nowait()
            logging.info('Got an incoming delete channel.')
        except queue.Empty:
            return False

        circuit = self.get_circuit(uid)
        if circuit is None:
            return True

        return self.perform_delete(circuit)

    def perform_pending_send(self):
        try:
            payload = self._send_trigger.get_nowait()
            self.guardlink.send(payload)
            return True
        except queue.Empty:
            return False

    def update_guard(self):
        try:
            self._guard_output.put_nowait(self.guarddesc)
            return True
        except queue.Full:
            return False

    def update_link(self):
        try:
            return self.guardlink.pull(block=False)
        except RuntimeError as e:
            if 'queues are full' in str(e): # TODO: do better than this hack
                sizes = [(k, c.queue.qsize())
                     for k, c in self.guardlink.circuits.items()]
                sizes.sort(key=lambda sz: -sz[1])

                # Delete the most overfilled circuit
                self.perform_delete(sizes[0][0])
                return True
            else:
                raise e

    def main(self):
        if not self.isalive_bootnode():
            self.refresh_bootnode()

        if not self.producer.isalive():
            self.producer.reset()

        if not self.isfresh_consensus():
            self.refresh_consensus()

        if not self.isalive_guardnode():
            self.refresh_guardnode()

        with self._lock:
            while (False
                or self.producer.refresh()
                or self.perform_pending_delete()
                or self.perform_pending_create()
                or self.perform_pending_send()
                or self.update_guard()
                or self.update_link()):
                    self.nb_actions += 1
            self.tick += 1
        time.sleep(tick_rate)

    def run(self):
        while not self.dead:
            try:
                self.main()
            except BaseException as e:
                logging.critical(e)
                if debug:
                    traceback.print_exc()

    _create_trigger_cache = None
    _create_trigger_count = 0
    def create(self, data, timeout=3):
        timeout = timeout / (1 + queue_size)

        self._create_trigger_count += 1
        rq = self._create_trigger_count

        try:
            self._create_trigger.put((rq, data), timeout=timeout)
        except queue.Full:
            flask.abort(503)

        for _ in range(queue_size):
            if self._create_trigger_cache is None:
                self._create_trigger_cache = dict()

            try:
                key, data = self._created_output.get(timeout=timeout)
                self._create_trigger_cache[key] = (data, time.time())
            except queue.Empty:
                pass

            to_delete = []
            rq_target = None
            for key, (data, date) in self._create_trigger_cache.items():
                if time.time() - date:
                    to_delete.append(key)
                if key == rq:
                    rq_target = data

            for key in to_delete:
                del self._create_trigger_cache[key]

            if rq_target is not None:
                return rq_target

        flask.abort(503)

    def delete(self, uid, timeout=1):
        try:
            self._delete_trigger.put(uid, timeout=timeout)
        except queue.Full:
            flask.abort(503)

    def get_guard(self, timeout=1):
        try:
            return self._guard_output.get(timeout=timeout)
        except queue.Empty:
            flask.abort(503)

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
    global debug
    if not debug:
        flask.abort(404)

    consensus = None
    with app.clerk.lock:
        consensus = app.clerk.consensus

    return flask.jsonify(consensus)

@app.route(base_url + '/guard')
def get_guard():
    return flask.jsonify(app.clerk.get_guard()), 200

@app.route(base_url + '/channels', methods=['POST'])
def create_channel():
    if not flask.request.json or not 'ntor' in flask.request.json:
        flask.abort(400)

    data = base64.b64decode(flask.request.json['ntor'])
    return flask.jsonify(app.clerk.create(data)), 201 # Created

@app.route(base_url + '/channels/<uid>', methods=['POST'])
def write_channel(uid):
    if not flask.request.json or 'event' not in flask.request.json:
        flask.abort(400)
    if not flask.request.json['event'] in ['send', 'recv']:
        flask.abort(400)

    circuit = app.clerk.get_circuit(uid, abort=True)
    if flask.request.json['event'] == 'send':
        if 'cell' not in flask.request.json:
            flask.abort(400)

        cell = base64.b64decode(flask.request.json['cell'])
        app.clerk.send(cell, circuit)

    return flask.jsonify(app.clerk.recv(circuit)), 201 # Created

@app.route(base_url + '/channels/<uid>', methods=['DELETE'])
def delete_channel(uid):
    app.clerk.delete(uid)
    return flask.jsonify({}), 202 # Deleted

def main(port, slave_node, bootstrap_node, purge_cache):
    if purge_cache:
        ltor.cache.purge()

    with clerk(slave_node, bootstrap_node) as app.clerk:
        logging.info('Bootstrapping HTTP server.')
        app.run(port=port, debug=debug, use_reloader=False)
