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
queue_size = 5
api_version = 0.1

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

        self.nb_create = 0
        self.nb_delete = 0
        self.tick = 0

        self.bootstrap_node = bootstrap_node
        self.slave_node = slave_node

        self.producer = None
        self.refresh_producer()

        self.bootlink = None
        self.bootnode = None
        self.refresh_bootnode()

        self.consensus = dict(headers=None)
        self.refresh_consensus()

        self.guardlink = None
        self.guardnode = None
        self.maintoken = None
        self.refresh_guardnode()

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

    def refresh_producer(self):
        logging.info('Refreshing path emitter.')

        with self._lock:
            if self.producer is not None:
                self.producer.close()

                for _ in range(refresh_timeout):
                    if self.producer.dead:
                        break
                    time.sleep(1)

                if not self.producer.dead:
                    self.die('Unable to kill path emitter, abort!')

                logging.debug('Previous producer successfully terminated.')

            if self.slave_node is None:
                self.producer = ltor.proxy.path.fetch()
            else:
                addr, port = self.slave_node
                self.producer = ltor.proxy.path.fetch(
                    tor_process=False, control_host=addr, control_port=port)

            logging.debug('Producer successfully created.')

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

    def refresh_guardnode(self):
        logging.info('Refreshing guard node link.')

        with self._lock:
            if not self.isfresh_consensus():
                self.refresh_consensus()

            if not self.isalive_producer():
                self.refresh_producer()

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

                    self.refresh_producer()
                    self.refresh_guardnode()
                    return self.isalive_guardnode()

                if not self.guarddesc['digest'] == guard['digest']:
                    logging.info('Guard changed its descriptor.')

                    self.refresh_guardnode()
                    return self.isalive_guardnode()

                self.guardlast = time.time()
                self.guardcirc = circ

            return True

    def perform_pending_create(self):
        try:
            self._create_trigger.get_nowait()
            logging.info('Got an incoming create channel request.')
        except queue.Empty:
            return False

        circ = ltor.create.ntor(self.guardlink, self.guarddesc)
        middle, exit = ltor.proxy.path.convert(*self.producer.get(),
            consensus=self.consensus, expect='list')

        token = self.crypto.compute_token(circ.circuit.id, self.maintoken)

        logging.debug('Circuit created with circuit_id: {}'.format(
            circ.circuit.id))
        logging.debug('Path picked: {} -> {}'.format(
            middle['nickname'], exit['nickname']))
        logging.debug('Token emitted: {}'.format(token))

        try:
            self._created_output.put_nowait(
                {'id': token, 'path': [middle, exit]})
        except queue.Full:
            logging.warning('Too many create channel requests, dropping.')
            return False

        return True

    def perform_pending_delete(self):
        try:
            token = self._delete_trigger.get_nowait()
            logging.info('Got an incoming delete channel.')
        except queue.Empty:
            return False

        circuit_id = self.crypto.decrypt_token(token, self.maintoken)
        if circuit_id is None:
            logging.debug('Got an invalid token: {}'.format(token))
            return True

        if circuit_id not in self.guardlink.circuits:
            logging.debug('Got an unknown circuit: {}'.format(circuit_id))
            return True

        circuit = self.guardlink.circuits[circuit_id]
        self.guardlink.unregister(circuit)
        logging.debug('Deleting circuit: {}'.format(circuit_id))

        reason = ltor.cell.destroy.reason.REQUESTED
        self.guardlink.send(ltor.cell.destroy.pack(circuit.id, reason))
        logging.debug('Remaining circuits: {}'.format(list(
            self.guardlink.circuits)))

    def main(self):
        if not self.isalive_bootnode():
            self.refresh_bootnode()

        if not self.isalive_producer():
            self.refresh_producer()

        if not self.isfresh_consensus():
            self.refresh_consensus()

        if not self.isalive_guardnode():
            self.refresh_guardnode()

        with self._lock:
            while self.perform_pending_create():
                self.nb_create += 1
            while self.perform_pending_delete():
                self.nb_delete += 1
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

    def create(self, timeout=1):
        try:
            self._create_trigger.put([None], timeout=timeout)
            return self._created_output.get(timeout=timeout)
        except (queue.Empty, queue.Full):
            flask.abort(503)

    def delete(self, uid, timeout=1):
        try:
            self._delete_trigger.put(uid, timeout=timeout)
        except queue.Full:
            flask.abort(503)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *kargs):
        self.dead = True
        self.join()

app = flask.Flask(__name__)
base_url = '/lighttor/api/v{}'.format(api_version)

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
    global debug
    if not debug:
        flask.abort(404)

    guard = None
    with app.clerk.lock:
        guard = app.clerk.guarddesc

    return flask.jsonify(guard)

@app.route(base_url + '/channels', methods=['POST'])
def create_channel():
    return flask.jsonify(app.clerk.create()), 201 # Created

@app.route(base_url + '/channels/<uid>', methods=['DELETE'])
def delete_channel(uid):
    app.clerk.delete(uid)
    return flask.jsonify({}), 200

def main(port, slave_node, bootstrap_node, purge_cache):
    if purge_cache:
        ltor.cache.purge()

    with clerk(slave_node, bootstrap_node) as app.clerk:
        logging.info('Bootstrapping HTTP server.')
        app.run(port=port, debug=debug, use_reloader=False)
