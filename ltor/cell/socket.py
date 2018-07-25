import threading
import socket
import queue

import cell

class worker(threading.Thread):
    def __init__(self, peer, max_queue=2048, period=0.5):
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

    def get(self):
        return self.queue.get()

    @property
    def full(self):
        return self.queue.full()

    @property
    def empty(self):
        return self.queue.empty()

class sender(worker):
    def __init__(self, peer, max_queue=2048, period=0.5):
        super().__init__(peer, max_queue, period)
        peer.settimeout(period)

    def send(self, payload):
        while not self.dead:
            try:
                cell.send(self.peer, payload)
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
    def __init__(self, peer, max_queue=2048, period=0.5):
        super().__init__(peer, max_queue, period)
        peer.settimeout(period)

    def run(self):
        try:
            while not self.dead:
                try:
                    self.put(cell.recv(self.peer))
                except socket.timeout:
                    pass

        except BaseException as e:
            self.die(e)

class io:
    _join_timeout = 3

    def __init__(self, peer, daemon=True, max_queue=2048):
        self.receiver = receiver(peer, max_queue)
        self.sender = sender(peer, max_queue)

        if daemon:
            self.receiver.daemon = True
            self.sender.daemon = True

        self.receiver.start()
        self.sender.start()
        self.peer = peer

    def recv(self):
        return self.receiver.get()

    def send(self, payload):
        self.sender.put(payload)

    def close(self):
        self.sender.close()
        self.receiver.close()

        self.sender.join(self._join_timeout)
        self.receiver.join(self._join_timeout)
