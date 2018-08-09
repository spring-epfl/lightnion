import threading
import logging
import flask
import time

import lighttor as ltor
import lighttor.proxy

tick_rate = 0.1

refresh_timeout = 5
isalive_timeout = 30

class clerk(threading.Thread):
    def __init__(self, slave_node, bootstrap_node):
        super().__init__()
        logging.info('Bootstrapping clerk.')

        self.lock = threading.RLock()
        self.dead = False
        self.tick = 0

        self.bootstrap_node = bootstrap_node
        self.slave_node = slave_node
        self.producer = None
        self.bootlink = None
        self.bootnode = None

        self.refresh_producer()
        self.refresh_bootnode()

        self.consensus = dict(headers=None)

        self.refresh_consensus()

    def die(self, e):
        if isinstance(e, str):
            logging.error(e)
            e = RuntimeError(e)

        self.dead = True
        raise e

    def refresh_producer(self):
        logging.info('Refreshing path emitter.')

        with self.lock:
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

        with self.lock:
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
        with self.lock:
            if not self.isalive_bootnode():
                self.refresh_bootnode()

            self.bootcirc, census = ltor.consensus.download(self.bootcirc)
            if census['headers']['valid-until']['stamp'] < time.time():
                self.die('Unable to get a fresh consensus, abort!')

            if not census['headers'] == self.consensus['headers']:
                logging.info('Consensus successfully refreshed.')

            self.consensus = census

    def isalive_bootnode(self, force_check=False):
        with self.lock:
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

    def isalive_producer(self):
        with self.lock:
            return not self.producer.dead

    def isfresh_consensus(self):
        with self.lock:
            fresh_until = self.consensus['headers']['fresh-until']['stamp']
            return (fresh_until < time.time())

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *kargs):
        self.dead = True
        self.join()

    def main(self):
        if not self.isalive_bootnode():
            self.refresh_bootnode()

        if not self.isalive_producer():
            self.refresh_producer()

        if not self.isfresh_consensus():
            self.refresh_consensus()

        with self.lock:
            self.tick += 1

        time.sleep(tick_rate)

    def run(self):
        while not self.dead:
            try:
                self.main()
            except BaseException as e:
                print(e)

app = flask.Flask(__name__)

@app.route('/')
def index():
    with app.clerk.lock:
        path = app.clerk.producer.get()
        return "Hello, World! {} {}".format(app.clerk.tick, path)

def main(port, slave_node, bootstrap_node, purge_cache):
    if purge_cache:
        ltor.cache.purge()

    with clerk(slave_node, bootstrap_node) as app.clerk:
        logging.info('Bootstrapping HTTP server.')
        app.run(port=port, debug=True, use_reloader=False)
