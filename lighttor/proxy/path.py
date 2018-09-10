import multiprocessing
import threading
import logging
import atexit
import base64
import queue
import time

import stem
import stem.process
import stem.control

# TODO: replace the whole content of this file with proper stuff!

default_nb_worker = 2

class worker(threading.Thread):
    def __init__(self, host, port, barrier, path_queue, batch_size):
        super().__init__()

        self.mini_batch = batch_size // 8 if batch_size // 8 > 0 else 1
        self.batch_size = batch_size
        self.path_queue = path_queue
        self.barrier = barrier
        self.count = 0
        self.finished = False
        self.dead = False
        self.port = port
        self.host = host

    def run(self):
        ctrl = stem.control.Controller.from_port(self.host, port=self.port)
        ctrl.authenticate()

        first = self.barrier.wait()
        if first == 0:
            ctrl.drop_guards()
            ctrl.signal(stem.Signal.NEWNYM)
        self.barrier.wait()

        circs = []
        while not self.dead:
            if self.count >= self.batch_size and not self.dead:
                for circ in circs:
                    try:
                        ctrl.close_circuit(circ)
                    except (stem.ControllerError, ValueError):
                        pass
                self.finished = True
                self.count = 0

            for _ in range(self.mini_batch):
                if len(circs) > self.batch_size:
                    break

                try:
                    circs.append(ctrl.new_circuit())
                except stem.ControllerError as e:
                    pass

            fails = []
            for circ in circs:
                try:
                    path = ctrl.get_circuit(circ).path
                    if len(path) == 3:
                        ctrl.close_circuit(circ)
                        self.path_queue.put(path)
                        self.count += 1
                    else:
                        fails.append(circ)
                except (stem.ControllerError, ValueError) as e:
                    pass

            circs = fails
            self.barrier.wait()

        ctrl.close()

_cached_tor = None
def get_tor(control_port=9051, socks_port=9050, msg_handler=None):
    global _cached_tor
    if _cached_tor is not None:
        return _cached_tor

    tor = stem.process.launch_tor_with_config(
            config={
                'SocksPort': str(socks_port),
                'ControlPort': str(control_port),
                'PublishServerDescriptor': '0',
            }, init_msg_handler=msg_handler)
    atexit.register(tor.kill)

    _cached_tor = tor

def emitter(
        output_queue,
        kill_queue,
        control_host,
        control_port,
        batch=32,
        target=1024,
        nb_worker=default_nb_worker):

    # (shut up stem)
    logging.getLogger(stem.__name__).setLevel(logging.ERROR)

    barrier = threading.Barrier(nb_worker)
    path_queue = queue.Queue(maxsize=batch)
    batch_size = target // nb_worker + 1

    workers = []
    for _ in range(nb_worker):
        workers.append(
            worker(
                control_host,
                control_port,
                barrier,
                path_queue,
                batch_size))

    for w in workers:
        w.start()

    guard, middle, exit = path_queue.get()
    output_queue.put(guard)
    output_queue.put((middle, exit))

    while any([not w.finished for w in workers]):
        new_guard, middle, exit = path_queue.get()
        if new_guard != guard:
            continue

        output_queue.put((middle, exit))
        if kill_queue.qsize() > 0:
            for w in workers:
                w.finished = True

    # (cleanup is useless as the process will die, but do it nonetheless)
    barrier.abort()
    for w in workers:
        w.dead = True

    try:
        for i in range(path_queue.qsize()):
            path_queue.get_nowait()
    except queue.Empty:
        pass

    for w in workers:
        w.join(0.1)

class producer:
    def __init__(self, process, path_queue, kill_queue, tor_process):
        self.guard = path_queue.get()
        self.process = process
        self.path_queue = path_queue
        self.kill_queue = kill_queue
        self.tor_process = tor_process

    @property
    def dead(self):
        return not self.process.is_alive()

    @property
    def empty(self):
        return not (self.path_queue.qsize() > 0)

    def get(self):
        return self.path_queue.get()

    def close(self):
        try:
            self.kill_queue.put_nowait([None])
        except queue.Full:
            pass

        try:
            self.path_queue.get_nowait()
        except queue.Empty:
            pass

_default_tor = None
_default_socks_port = None
_default_control_port = None
def fetch(
    batch=32,
    target=1024,
    nb_worker=2,
    tor_process=None,
    socks_port=None,
    control_host='127.0.0.1',
    control_port=None):

    global _default_tor, _default_socks_port, _default_control_port
    if socks_port is None:
        if _default_socks_port is None:
            _default_socks_port = 9050
        socks_port = _default_socks_port

    if control_port is None:
        if _default_control_port is None:
            _default_control_port = 9051
        control_port = _default_control_port

    if tor_process is None:
        if _default_tor is None:
            _default_tor = get_tor(
                socks_port=socks_port,
                control_port=control_port,
                msg_handler=None)
        tor_process = _default_tor

    path_queue = multiprocessing.Queue(maxsize=batch)
    kill_queue = multiprocessing.Queue(maxsize=1)
    process = multiprocessing.Process(target=emitter, args=(
            path_queue,
            kill_queue,
            control_host,
            control_port,
            batch,
            target,
            nb_worker))
    process.start()

    if not tor_process:
        tor_process = None

    return producer(process, path_queue, kill_queue, tor_process)

# TODO: check if this conversion fingerprint->descriptor is safe?
def convert(*entries, consensus, expect='fetch_format'):
    if expect not in ['list', 'fetch_format']:
        raise RuntimeError('Format unknown: {}'.format(expect))

    if expect == 'fetch_format':
        entries = [entries[0]] + [node for pair in entries[1] for node in pair]
        guard, *paths = convert(*entries, consensus=consensus, expect='list')
        paths = list(zip(paths[::2], paths[1::2]))
        return guard, paths

    if expect == 'list':
        pass
    new_entries = []

    by_identity = {r['identity']: r for r in consensus['routers']}
    if len(by_identity) != len(consensus['routers']):
        raise RuntimeError('Unsafe! Duplicates in the consensus!')

    for entry in entries:
        fingerprint, nickname = entry

        as_identity = str(base64.b64encode(bytes.fromhex(fingerprint)), 'utf8')
        as_identity = as_identity.replace('=', '')

        if as_identity not in by_identity:
            raise RuntimeError('Unknown entity within consensus: {}'.format(
                (entry, as_identity)))

        router = by_identity[as_identity]
        if nickname != router['nickname']:
            raise RuntimeError('Mismatched nickname: {} vs {}'.format(nickname,
                router['nickname']))

        new_entries.append(router)
    return new_entries
