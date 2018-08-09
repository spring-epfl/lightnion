import threading
import flask
import time

import lighttor as ltor
import lighttor.proxy

refresh_timeout = 5

class clerk(threading.Thread):
    def __init__(self, slave_node, bootstrap_node):
        super().__init__()

        self.lock = threading.RLock()
        self.dead = False
        self.tick = 0

        self.bootstrap_node = bootstrap_node
        self.slave_node = slave_node
        self.producer = None
        self.bootlink = None

        self.refresh_producer()
        self.refresh_bootlink()

    def die(self, e):
        self.dead = True
        raise e

    def refresh_producer(self):
        if self.producer is not None:
            self.producer.close()

            for _ in range(refresh_timeout):
                if self.producer.dead:
                    break
                time.sleep(1)

            if not self.producer.dead:
                self.die(
                    RuntimeError('Unable to kill path emitter, aborting!'))

        if self.slave_node is None:
            self.producer = ltor.proxy.path.fetch()
        else:
            addr, port = self.slave_node
            self.producer = ltor.proxy.path.fetch(
                tor_process=False, control_host=addr, control_port=port)

    def refresh_bootlink(self):
        if self.bootlink is not None:
            self.bootlink.close()

            for _ in range(refresh_timeout):
                if self.bootlink.io.dead:
                    break
                time.sleep(1)

            if not self.bootlink.io.dead:
                self.die(
                    RuntimeError('Unable to close bootstrap link, aborting!'))

        addr, port = self.bootstrap_node
        self.bootlink = ltor.link.initiate(address=addr, port=port)

    def __enter__(self):
        with self.lock:
            self.start()
        return self

    def __exit__(self, *kargs):
        with self.lock:
            self.dead = True
        self.join()

    def main(self):
        with self.lock:
            self.tick += 1

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
        app.run(port=port, debug=True)
