import websockets
import threading
import logging
import asyncio
import queue

from .. import http
from .. import proxy

async def incoming(websocket, worker):
    cell = None
    while True:
        try:
            if cell is None:
                cell = await websocket.recv()
            worker.recv_queue.put_nowait(cell)
            cell = None

            await asyncio.sleep(0)
            continue
        except (asyncio.QueueEmpty, queue.Full):
            pass

        await asyncio.sleep(worker.period)

async def outcoming(websocket, worker):
    cell = None
    while True:
        try:
            if cell is None:
                cell = worker.send_queue.get_nowait()
            await websocket.send(cell)
            cell = None

            await asyncio.sleep(0)
            continue
        except (asyncio.QueueFull, queue.Empty):
            pass

        await asyncio.sleep(worker.period)

async def channel_handler(websocket, worker):
    for task in [incoming, outcoming]:
        worker.tasks.append(asyncio.ensure_future(task(websocket, worker)))

    done, pending = await asyncio.wait(worker.tasks,
        return_when=asyncio.FIRST_COMPLETED)

    for task in pending:
        task.cancel()
    worker.dead = True

async def client(worker):
    async with websockets.connect(worker.endpoint) as websocket:
        await channel_handler(websocket, worker)

class worker(threading.Thread):
    def __init__(self, endpoint, period, max_queue=2048):
        super().__init__()
        self.endpoint = endpoint
        self.period = period
        max_queue = max_queue // 2

        self.send_queue = queue.Queue(max_queue)
        self.recv_queue = queue.Queue(max_queue)

        self.send_async = asyncio.Queue(max_queue)
        self.recv_async = asyncio.Queue(max_queue)

        self.tasks = []
        self.dead = False

    def close(self):
        for task in self.tasks:
            task.cancel()
        self.dead = True

    def die(self, e):
        if self.dead:
            return

        self.close()
        raise e

    def send(self, cell, block=True):
        try:
            cell = cell.raw
        except AttributeError:
            pass

        self.send_queue.put(cell, block)

    def recv(self, block=True):
        payload = self.recv_queue.get(block=block)
        return payload

    def run(self):
        logging.getLogger(websockets.__name__).setLevel(logging.ERROR)
        asyncio.set_event_loop(asyncio.new_event_loop())

        asyncio.get_event_loop().run_until_complete(client(self))

class io:
    _join_timeout = 3

    def __init__(self, endpoint, period=0.1, daemon=True, max_queue=2048):
        endpoint = endpoint.replace('http', 'ws')
        endpoint = endpoint.replace(':4990/', ':8765/') # TODO: work same port

        self.worker = worker(endpoint, period, max_queue)
        if daemon:
            self.worker.daemon = True

        self.worker.start()

    @property
    def dead(self):
        return self.worker.dead

    def recv(self, block=True):
        return self.worker.recv(block)

    def send(self, payload, block=True):
        self.worker.send(payload, block=block)

    def close(self):
        self.worker.close()
        self.worker.join(self._join_timeout)
