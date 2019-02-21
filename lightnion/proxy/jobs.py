import logging
import hashlib
import queue
import base64
import time

import lightnion as lnn
import lightnion.http
import lightnion.path_selection

# TODO: rewrite everything? (with less complexity? using asyncio only?)

default_qsize = 128
default_expiracy = 10
circuit_expiracy = 60
request_max_cells = 120

isalive_period = 30
refresh_timeout = 3
refresh_batches = 8

class expired(BaseException):
    pass

class basic:
    def __init__(self, clerk, qsize=default_qsize):
        self.clerk = clerk
        self.qsize = qsize

        self.reset()

    def reset(self):
        self._in = queue.Queue(maxsize=self.qsize)
        self._out = queue.Queue(maxsize=self.qsize)

    def get(self, timeout=1):
        try:
            return self._out.get(timeout=timeout)
        except queue.Empty:
            pass
        raise expired

    def put(self, job, timeout=1):
        try:
            return self._in.put(job, timeout=timeout)
        except queue.Full:
            pass
        raise expired

    def get_job(self):
        try:
            return self._in.get_nowait()
        except queue.Empty:
            pass
        raise expired

    def put_job(self, job):
        try:
            return self._out.put_nowait(job)
        except queue.Full:
            pass
        raise expired

    def isfresh(self):
        return True

    def isalive(self):
        return True

    def refresh(self):
        raise NotImplementedError

    def perform(self, timeout=1):
        raise NotImplementedError

    def close(self):
        pass

class ordered(basic):
    def __init__(self, clerk, expiracy=default_expiracy, qsize=default_qsize):
        super().__init__(clerk=clerk, qsize=qsize)
        self.pending_jobs = dict()
        self.expiracy = expiracy
        self.last_job = 0

    def put(self, job, timeout=1):
        self.last_job += 1
        jid = self.last_job

        date = time.time()
        super().put((jid, job, date), timeout=timeout)
        return jid

    def get(self, job_id, timeout=1):
        timeout = timeout / self.qsize

        for _ in range(self.qsize):
            if job_id in self.pending_jobs:
                job, date = self.pending_jobs[job_id]
                if time.time() - date > self.expiracy:
                    raise expired

                self.pending_jobs.pop(job_id, None)
                return job

            try:
                jid, job, date = super().get(timeout=timeout)
                self.pending_jobs[jid] = (job, date)
            except expired:
                continue

            olds = []
            for jid, (_, date) in self.pending_jobs.items():
                if time.time() - date > self.expiracy:
                    olds.append(jid)

            for jid in olds:
                self.pending_jobs.pop(jid, None)
        raise expired

    def get_job(self):
        jid, job, date = super().get_job()

        qsize = self._in.qsize()
        while (False
            or (time.time() - date > self.expiracy)
            or (jid % 2 > 0 and qsize > self.qsize // 2)
            or (jid % 4 > 0 and qsize > 3 * self.qsize // 4)):
            jid, job, date = super().get_job()
        return jid, job

    def put_job(self, job, job_id):
        date = time.time()
        super().put_job((job_id, job, date))


class guard(basic):
    def __init__(self, clerk, qsize=default_qsize):
        self.link = None
        self.circ = None
        self.desc = None
        self.identity = None
        clerk.maintoken = None
        super().__init__(clerk=clerk, qsize=qsize)

    def put(self, job):
        raise NotImplementedError

    def get_job(self):
        raise NotImplementedError

    def router(self, check_alive=True):
        #self.clerk.wait_for_consensus()

        guard = self.clerk.get_guard()
        nickname = guard['router']['nickname']
        fingerprint = guard['fingerprint']
        entry = [fingerprint, nickname]
        guard = lnn.proxy.path.convert(entry, consensus=self.clerk.consensus, expect='list')[0]

        return guard

    def maintoken(self):
        logging.info('Resetting guard node link.')

        token = hashlib.sha256(bytes(self.identity, 'utf8')
            + self.link.io.binding()).digest()

        if not token == self.clerk.maintoken:
            logging.info('Shared tokenid updated.')

        logging.debug('Shared tokenid: {}'.format(token.hex()))
        self.clerk.maintoken = token

    def authority(self, check_alive=True):
        if check_alive and not self.isalive():
            self.reset()
        self.circ, desc = lnn.descriptors.download_authority(self.circ)
        return desc

    def reset(self):
        logging.info('Resetting guard node link.')

        router = self.router()
        if not self.router == router:
            logging.info('New guard: {}'.format(router['nickname']))
        self.identity = router['identity']

        # TODO: link authentication instead of NTOR handshakes!
        addr, port = router['address'], router['orport']
        self.link = lnn.link.initiate(address=addr, port=port)

        self.desc = self.clerk.get_descriptor_unflavoured(router)
        self.circ = lnn.create.ntor(self.link, self.desc)

        self.last = time.time()
        self.used = None
        self.maintoken()

        super().reset()
        if not self.isalive(force_check=True):
            raise RuntimeError('Unable to interact with guard node, abort!')

    def isalive(self, force_check=False):
        if self.link is None:
            return False

        if self.link.io.dead:
            logging.warning('Guard node link seems dead.')
            return False

        if self.circ.circuit.destroyed:
            logging.warning('Guard keepalive circuit got destroyed.')
            return False

        router = self.router()
        if not self.identity == router['identity']:
            logging.warning('Guard may have changed, need reset!')
            return False
        self.identity = router['identity']

        if force_check or (time.time() - self.last) > isalive_period:
            logging.debug('Update guard descriptor (health check).')

            # Disable this check as the guard node will not change.
            #desc = self.authority(check_alive=False)
            #if self.identity != desc['router']['identity']:
            #    logging.warning('Guard changed its identity, need reset!')

            #    self.clerk.producer.reset()
            #    return False

            #for key in ['ntor-onion-key', 'identity', 'router']:
            #    if not (self.desc[key] == desc[key]):
            #        logging.info('Guard changed {}, need reset!.'.format(key))

            #        self.clerk.producer.reset()
            #        return False
            self.last = time.time()

            olds = []
            news = []
            for key, circuit in self.link.circuits.items():
                if not hasattr(circuit, 'used'):
                    continue

                if time.time() - circuit.used > circuit_expiracy:
                    logging.debug('Destroy {} (old age/unused).'.format(key))
                    olds.append(circuit)
                else:
                    news.append(circuit)

            for circuit in olds:
                try:
                    #self.clerk.delete.perform(circuit)
                    self.clerk.delete_circuit(circuit)
                except expired:
                    pass

            if (len(news) < 1
                and self.used is not None
                and time.time() - self.used > isalive_period):
                logging.info('Resetting guard link to clean up.')
                return False

        return True

    def isfresh(self):
        return not (self.link.io.pending > 0 or self._out.qsize() < self.qsize)

    def refresh(self):
        redo = False
        try:
            self.put_job(self.desc)
            redo = True
        except expired:
            pass

        try:
            for _ in range(request_max_cells):
                if not self.link.pull(block=False):
                    return (redo or False)
            return True

        except RuntimeError as e:
            if 'queues are full' in str(e): # TODO: do better than this hack
                sizes = [(c, c.queue.qsize()) for _, c in self.link.circuits.items()]
                sizes.sort(key=lambda sz: -sz[1])

                # Delete the most overfilled circuit
                self.clerk.delete_circuit(sizes[0][0])
                return True
            elif 'Got circuit' in str(e):
                logging.warning(str(e))
                return (redo or False)
            else:
                raise e

    def perform(self, timeout=1):
        return self.get(timeout=timeout)


class channel(basic):
    def __init__(self, clerk, circuit, link,
        expiracy=circuit_expiracy, qsize=default_qsize):
        self.expiracy = expiracy
        self.circuit = circuit
        self.cells = []
        self.packs = []
        self.tasks = []
        self.used = time.time()
        self.link = link
        self.born = False
        super().__init__(clerk=clerk, qsize=qsize)

    def isalive(self):
        return (True
            and self.circuit.id in self.clerk.channels
            and self.circuit.id in self.link.circuits
            and not self.circuit.destroyed
            and not (time.time() - self.used) > self.expiracy)

    def delete(self):
        self.link.unregister(self.circuit)
        logging.debug('Deleting channel: {}'.format(self.circuit.id))

        reason = lnn.cell.destroy.reason.FINISHED
        self.link.send(lnn.cell.destroy.pack(self.circuit.id, reason))

        self.circuit.destroyed = True
        self.circuit.reason = reason

    def reset(self):
        super().reset()
        if self.born:
            if not self.circuit.destroyed:
                self.delete()

            try:
                self.clerk.channels.pop(self.circuit.id, None)
            except ValueError:
                pass

            for task in self.tasks:
                task.cancel()
            return

        logging.info('Channel for circuit {} opened.'.format(self.circuit.id))
        self.link.register(self.circuit)
        self.born = True

    def isfresh(self):
        return not (self._in.qsize() > 0)

    def send(self, cell):
        cell = lnn.cell.header_view.write(cell, circuit_id=self.circuit.id)
        try:
            self.link.send(cell, block=False)
        except queue.Full:
            return False
        return True

    def recv(self):
        try:
            cell = self.circuit.queue.get(block=False)
            cell = lnn.cell.header_view.write(cell,
                circuit_id=lnn.proxy.fake_circuit_id)
            return cell
        except queue.Empty:
            return None

    def refresh(self):
        if not self.isalive():
            return False

        redo = False
        try:
            if len(self.cells) < 1:
                self.cells = self.get_job()
                redo = True
                self.used = time.time()
                self.circuit.used = time.time()
        except expired:
            pass

        while len(self.cells) > 0:
            cell = self.cells.pop(0)
            if not self.send(cell):
                self.cells.insert(cell, 0)
                redo = False
                break

        if len(self.packs) < 1:
            for _ in range(request_max_cells - len(self.packs)):
                cell = self.recv()
                if cell is None:
                    break
                self.packs.append(cell)

        if len(self.packs) > 0:
            try:
                self.put_job(self.packs)
                self.packs = []
                redo = True
            except expired:
                pass
        elif redo:
            try:
                self.put_job([])
            except expired:
                pass

        return redo

    def perform(self, cells, timeout=0.2):
        self.put(cells, timeout=timeout)
        if len(cells) > 0:
            timeout = 0
        timeout = timeout / self.qsize

        packs = []
        for _ in range(self.qsize):
            try:
                packs += self.get(timeout=timeout)
            except expired:
                if len(packs) > 0:
                    break

        return [str(base64.b64encode(cell), 'utf8') for cell in packs]
