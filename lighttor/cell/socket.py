import lighttor as ltor

import threading
import socket
import queue
import ssl

# TODO: Remove ugly hacks done here!

class _real_peer:
    # TODO: Properly handle ssl sockets:
    #   https://mail.python.org/pipermail/python-list/2017-January/718926.html
    #
    def __init__(self, peer, max_fails=32):
        self.peer = peer
        self.lock = threading.RLock()
        self.fails = 0
        self.max_fails = max_fails
        self.closed = False

    def recv(self, size):
        if self.fails > self.max_fails:
            self.die()

        with self.lock:
            data = self.peer.recv(size)
            self.fails = self.fails + 1 if len(data) == 0 else 0
            return data

    def send(self, data):
        if self.fails > self.max_fails:
            self.die()

        with self.lock:
            nbytes_send = self.peer.send(data)
            self.fails = self.fails + 1 if nbytes_send == 0 else 0
            return nbytes_send

    def sendall(self, data):
        if self.fails > self.max_fails:
            self.die()

        with self.lock:
            nbytes_send = self.peer.sendall(data)
            self.fails = self.fails + 1 if nbytes_send == 0 else 0
            return nbytes_send

    def die(self):
        raise RuntimeError('Unable to interact with socket (closed?).')

    def close(self):
        with self.lock:
            self.closed = True
            self.close = (lambda: None)
            return self.peer.close()

class _stat_peer(_real_peer):
    def __init__(self, peer):
        super().__init__(peer)
        self._kbout = 0
        self._kbin = 0

    def disp(self):
        print('Traffic: {:.2f} up {:.2f} down {} fails'.format(
            self._kbout, self._kbin, self.fails), end='\r')

    def recv(self, size):
        data = super().recv(size)
        self._kbin += len(data) / 1000
        self.disp()
        return data

    def send(self, data):
        bytes_send = super().send(data)
        self._kbout += bytes_send / 1000
        self.disp()
        return bytes_send

    def sendall(self, data):
        bytes_send = super().sendall(data)
        self._kbout += bytes_send / 1000
        self.disp()
        return bytes_send

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

class worker(threading.Thread):
    def __init__(self, peer, max_queue=2048):
        super().__init__()

        self.peer = peer
        self.dead = False
        self.queue = queue.Queue(max_queue)

    def close(self):
        self.peer.close()
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
    def __init__(self, peer, max_queue=2048):
        super().__init__(peer, max_queue)

    def send(self, peer, data):
        while len(data) > 0 and not self.dead and not self.peer.closed:
            try:
                sended = peer.send(data)
                data = data[sended:]
            except (socket.timeout, ssl.SSLError, BlockingIOError) as e:
                pass # print('send {}'.format(e))

    def run(self):
        try:
            while not self.dead and not self.peer.closed:
                ltor.cell.send(self.peer, self.get(),
                    _sendall=lambda peer, data: self.send(peer, data))
            self.dead = True

        except BaseException as e:
            self.die(e)

class receiver(worker):
    def __init__(self, peer, max_queue=2048, buffer_size=4096):
        super().__init__(peer, max_queue)
        self.buffer_size = buffer_size

    def run(self):
        try:
            while not self.dead and not self.peer.closed:
                try:
                    payload = self.peer.recv(self.buffer_size)
                    self.put(payload)
                except (socket.timeout, ssl.SSLError, BlockingIOError) as e:
                    pass # print('recv {}'.format(e))
            self.dead = True

        except BaseException as e:
            self.die(e)

# TODO: check if cellmaker is useful, if not remove it
class cellmaker(worker):
    def __init__(self, io, peer, max_queue=2048, buffer_size=4096):
        super().__init__(peer, max_queue)
        self.fake_peer = _fake_peer(io, buffer_size)

    def run(self):
        try:
            while not self.dead and not self.peer.closed:
                self.put(ltor.cell.recv(self.fake_peer))
            self.dead = True

        except BaseException as e:
            self.die(e)

class io:
    _join_timeout = 3

    def __init__(self, peer,
            daemon=True, period=0.02, max_queue=2048, buffer_size=4096):
        peer.settimeout(period)
        peer = _real_peer(peer)
        # peer = _stat_peer(peer)

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

    @property
    def dead(self):
        return (self.peer.closed
            or self.cellmaker.dead or self.sender.dead or self.receiver.dead)

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

        self.peer.close()
