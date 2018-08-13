import lighttor as ltor

import threading
import socket
import queue
import ssl

# TODO: Better network handling?

class _stat_peer:
    def __init__(self, peer):
        self.peer = peer

        self._kbout = 0
        self._kbin = 0

    def disp(self):
        print('Traffic: {:.2f} up {:.2f} down'.format(
            self._kbout, self._kbin), end='\r')

    def recv(self, size):
        data = self.peer.recv(size)
        self._kbin += len(data) / 1000
        self.disp()
        return data

    def send(self, data):
        bytes_send = self.peer.send(data)
        self._kbout += bytes_send / 1000
        self.disp()
        return bytes_send

    def sendall(self, data):
        bytes_send = self.peer.sendall(data)
        self._kbout += bytes_send / 1000
        self.disp()
        return bytes_send

    def get_channel_binding(self, *kargs):
        return self.peer.get_channel_binding(*kargs)

    def close(self):
        return self.peer.close()

def cell_slice(payload, once=False):
    cell_header = ltor.cell.header(payload)
    if len(payload) < cell_header.width: # (payload too small, need data)
        return [], payload, True

    if not cell_header.valid:
        raise RuntimeError('Invalid cell header: {}'.format(cell_header.raw))

    length = cell_header.width + ltor.constants.payload_len
    if not cell_header.cmd.is_fixed:
        cell_header = ltor.cell.header_variable(payload)
        if len(payload) < cell_header.width: # (payload too small, need data)
            return [], payload, True

        if not cell_header.valid:
            raise RuntimeError(
                'Invalid variable cell header: {}'.format(cell_header.raw))

        length = cell_header.width + cell_header.length

    if length > ltor.constants.max_payload_len:
        raise RuntimeError('Invalid cell length: {}'.format(length))

    if len(payload) < length:
        return [], payload, True

    cells = [payload[:length]]
    payload = payload[length:]
    celling = False

    if once:
        return cells, payload, celling

    while not celling and len(payload) > 0:
        new_cells, payload, celling = cell_slice(payload, once=True)
        cells += new_cells
    return cells, payload, celling

class worker(threading.Thread):
    def __init__(self, peer, max_fails=32, max_queue=2048, buffer_size=4096):
        super().__init__()

        self.buffer_size = buffer_size
        self.max_queue = max_queue
        self.max_fails = max_fails
        self.peer = peer

        self.cell_queue = queue.Queue(max_queue)
        self.send_queue = queue.Queue(max_queue)
        self.recv_queue = queue.Queue(max_queue)
        self.sending = b''
        self.recving = b''
        self.celling = False
        self.fails = 0
        self.dead = False

    def close(self):
        self.peer.close()
        self.dead = True

    def die(self, e):
        if self.dead:
            return

        self.close()
        raise e

    def send(self, cell, block=True):
        self.send_queue.put(ltor.cell.pad(cell), block=block)

    def recv(self, block=True):
        return self.cell_queue.get(block=block)

    def main(self):
        if self.fails > self.max_fails:
            cells, _, _ = cell_slice(self.recving)
            for cell in cells:
                self.cell_queue.put(cell)
            self.die(RuntimeError('Too many fails, is the socket dead?'))

        try:
            if len(self.sending) < 1:
                self.sending = self.send_queue.get(block=False)
        except queue.Empty:
            pass

        try:
            if len(self.sending) > 0:
                nbytes = self.peer.send(self.sending)
                self.fails = self.fails + 1 if nbytes == 0 else 0
                self.sending = self.sending[nbytes:]
                return
        except (socket.timeout, ssl.SSLError, BlockingIOError):
            pass

        try:
            payload = self.peer.recv(self.buffer_size)
            self.fails = self.fails + 1 if len(payload) == 0 else 0
            self.recv_queue.put(payload)
            if self.recv_queue.qsize() < self.max_queue // 4:
                return
        except (socket.timeout, ssl.SSLError, BlockingIOError):
            pass

        try:
            if ((len(self.recving) < 1 or self.celling)
                and len(self.recving) <= ltor.constants.max_payload_len):
                self.recving += self.recv_queue.get(block=False)
                self.celling = False
        except queue.Empty:
            pass

        if len(self.recving) > 0 and not self.celling:
            cells, self.recving, self.celling = cell_slice(self.recving)
            for cell in cells:
                self.cell_queue.put(cell)

    def run(self):
        try:
            while not self.dead:
                self.main()
            self.dead = True
        except BaseException as e:
            self.die(e)

class io:
    _join_timeout = 3

    def __init__(self,
            peer,
            daemon=True,
            period=0.01,
            max_fails=32,
            max_queue=2048,
            buffer_size=4096):
        peer.settimeout(period)
        # peer = _stat_peer(peer) # uncomment for extra statistics

        self.worker = worker(peer, max_fails, max_queue, buffer_size)
        if daemon:
            self.worker.daemon = True

        self.worker.start()
        self.peer = peer

    @property
    def dead(self):
        return self.worker.dead

    @property
    def pending(self):
        return self.worker.cell_queue.qsize()

    def recv(self, block=True):
        return self.worker.recv(block)

    def send(self, payload, block=True):
        self.worker.send(payload, block=block)

    def binding(self):
        return self.peer.get_channel_binding()

    def close(self):
        self.peer.close()

        self.worker.close()
        self.worker.join(self._join_timeout)
