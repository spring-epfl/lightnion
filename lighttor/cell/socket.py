import lighttor as ltor

import threading
import socket
import queue

class worker(threading.Thread):
    def __init__(self, peer, max_queue=2048):
        super().__init__()

        self.peer = peer
        self.dead = False
        self.queue = queue.Queue(max_queue)

    def close(self):
        try:
            self.peer.close()
        except BaseException:
            pass
        self.dead = True

    def die(self, e):
        if self.dead:
            return

        self.close()
        raise e

    def put(self, item):
        return self.queue.put(item)

    def get(self, block=True):
        return self.queue.get(block=block)

    @property
    def full(self):
        return self.queue.full()

    @property
    def empty(self):
        return self.queue.empty()

class sender(worker):
    def __init__(self, peer, max_queue=2048, period=0.5):
        super().__init__(peer, max_queue)
        peer.settimeout(period)

    def send(self, payload):
        while not self.dead:
            try:
                ltor.cell.send(self.peer, payload)
                break
            except socket.timeout:
                pass

    def run(self):
        while not self.dead:
            try:
                self.send(self.get())
            except BaseException as e:
                self.die(e)

class receiver(worker):
    def __init__(self, peer, max_queue=2048, period=0.5, buffer_size=8192):
        super().__init__(peer, max_queue)
        self.buffer_size = buffer_size
        peer.settimeout(period)

    def run(self):
        try:
            while not self.dead:
                try:
                    self.put(self.peer.recv(self.buffer_size))
                except socket.timeout:
                    pass

        except BaseException as e:
            self.die(e)

# TODO: check if cellmaker is useful, if not remove it
class cellmaker(worker):
    class _fake_peer:
        def __init__(self, io, buffer_size):
            self.buffer_size = buffer_size
            self.buffer = b''
            self.io = io

        def recv(self, size):
            while len(self.buffer) < size:
                self.buffer += self.io.receiver.get()
            payload, self.buffer = self.buffer[:size], self.buffer[size:]
            return payload

    def __init__(self, io, peer, max_queue=2048, buffer_size=8192):
        super().__init__(peer, max_queue)
        self.fake_peer = cellmaker._fake_peer(io, buffer_size)

    def run(self):
        try:
            while not self.dead:
                self.put(ltor.cell.recv(self.fake_peer))

        except BaseException as e:
            self.die(e)

class io:
    _join_timeout = 3

    def __init__(self, peer, daemon=True, max_queue=2048, buffer_size=8192):
        self.cellmaker = cellmaker(self, peer, max_queue, buffer_size)
        self.receiver = receiver(peer, max_queue, buffer_size)
        self.sender = sender(peer, max_queue)
        self.queue = queue.Queue(max_queue)

        if daemon:
            self.cellmaker.daemon = True
            self.receiver.daemon = True
            self.sender.daemon = True

        self.cellmaker.start()
        self.receiver.start()
        self.sender.start()
        self.peer = peer

    def recv(self, block=True):
        return self.cellmaker.get(block)

    def send(self, payload):
        self.sender.put(payload)

    def close(self):
        self.sender.close()
        self.receiver.close()
        self.cellmaker.close()

        self.sender.join(self._join_timeout)
        self.receiver.join(self._join_timeout)
        self.cellmaker.join(self._join_timeout)
