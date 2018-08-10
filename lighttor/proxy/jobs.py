import threading
import logging
import queue
import time

import lighttor as ltor

default_qsize = 3
default_expiracy = 3

isalive_period = 30
refresh_timeout = 3

class expired(BaseException):
    pass

class basic:
    def __init__(self, clerk, qsize=default_qsize):
        self.clerk = clerk
        self.qsize = qsize

        self.private_lock = threading.Lock()
        self.public_lock = threading.Lock()
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
        with self.private_lock:
            try:
                return self._in.get_nowait()
            except queue.Empty:
                pass
            raise expired

    def put_job(self, job):
        with self.private_lock:
            try:
                return self._out.put_nowait(job)
            except queue.Full:
                pass
            raise expired

    def isfresh(self):
        raise NotImplementedError

    def isalive(self):
        raise NotImplementedError

    def refresh(self):
        raise NotImplementedError

    def perform(self, timeout=1):
        raise NotImplementedError

    def close(self):
        pass

def ordered(basic):
    def __init__(self, clerk, expiracy=default_expiracy, qsize=default_qsize):
        super().__init__(clerk=clerk, qsize=qsize)
        self.pending_jobs = None
        self.expiracy = expiracy
        self.last_job = 0

    def put(self, job, timeout=1):
        jid = None
        with self.public_lock:
            _last_job += 1
            jid = _last_job

        date = time.time()
        super().put(self, (job, jid, date), timeout=timeout)

    def get(self, job_id, timeout=1):
        timeout = timeout / self.qsize

        for _ in range(self.qsize):
            if job_id in self.pending_jobs:
                job, date = self.pending_jobs[job_id]
                if time.time() - date > self.expiracy:
                    raise expired

                with self.public_lock:
                    self.pending_jobs.pop(job_id, None)
                return job

            try:
                job, jid, date = super().get(self, timeout=timeout)
                with self.public_lock:
                    self.pending_jobs[jid] = (job, date)
            except expired:
                continue

            olds = []
            for jid, (_, date) in self.pending_jobs.items():
                if time.time() - date > self.expiracy:
                    olds.append(jid)

            with self.public_lock:
                for jid in olds:
                    self.pending_jobs.pop(jid, None)

    def get_job(self):
        jid, job, date = super().get_job()
        if time.time() - date > self.expiracy:
            raise expired
        return job, jid

    def put_job(self, job, job_id):
        date = time.time()
        super().put_job((job, job_id, date))

class producer(basic):
    def __init__(self, clerk, qsize=default_qsize):
        self.guard = None
        self.child = None
        self._path = None
        super().__init__(clerk=clerk, qsize=qsize)

    def put(self, job):
        raise NotImplementedError

    def get_job(self):
        raise NotImplementedError

    def reset(self):
        super().reset()

        logging.info('Resetting path emitter.')
        with self.private_lock:
            if self.child is not None:
                self.child.close()

                for _ in range(refresh_timeout):
                    if self.child.dead:
                        break
                    time.sleep(1)

                if not self.child.dead:
                    raise RuntimeError('Unable to kill path emitter, abort!')

                logging.debug('Previous path emitter successfully terminated.')

            addr, port = self.clerk.slave_node[0], self.clerk.control_port
            self.child = ltor.proxy.path.fetch(tor_process=False,
                control_host=addr, control_port=port)
            self.guard = self.child.guard

            logging.debug('Path emitter successfully started.')

    def isalive(self):
        return (not self.child.dead
            and self.guard == self.child.guard)

    def isfresh(self):
        return not (self._out.qsize() < self.qsize)

    def refresh(self):
        path = None
        try:
            with self.private_lock:
                path = self._path
                self._path = None

            if path is not None:
                self.put_job(path)
        except expired:
            if path is not None:
                with self.private_lock:
                    self._path = path
            return False

        try:
            path = self.child.path_queue.get_nowait()
            with self.private_lock:
                self._path = path
        except queue.Empty:
            return False

        return True

    def close(self):
        with self.private_lock:
            self.child.close()

class slave(basic):
    def __init__(self, clerk, qsize=default_qsize):
        self.link = None
        self.circ = None
        self.desc = None
        self.identity = None
        super().__init__(clerk=clerk, qsize=qsize)

    def get(self):
        raise NotImplementedError

    def put(self, job):
        raise NotImplementedError

    def get_job(self):
        raise NotImplementedError

    def put_job(self, job):
        raise NotImplementedError

    def reset(self):
        super().reset()

        logging.info('Resetting slave node link.')
        with self.private_lock:
            if self.link is not None:
                self.link.close()

                for _ in range(refresh_timeout):
                    if self.link.io.dead:
                        break
                    time.sleep(1)

                if not self.link.io.dead:
                    raise RuntimeError('Unable to close slave link, abort!')

                logging.debug('Previous slave link successfully terminated.')

            addr, port = self.clerk.slave_node
            self.link = ltor.link.initiate(addr, port)
            self.circ = ltor.create.fast(self.link)
            self.last = time.time()

        if not self.isalive(force_check=True):
            raise RuntimeError('Unable to interact with slave node, abort!')

    def authority(self, check_alive=True):
        if check_alive and not self.isalive():
            self.reset()
        self.circ, self.desc = ltor.descriptors.download_authority(self.circ)
        return self.desc

    def descriptors(self, query, fail_on_missing=True, check_alive=True):
        if check_alive and not self.isalive():
            self.reset()

        self.circ, descs = ltor.descriptors.download(self.circ, query,
            flavor='unflavored', fail_on_missing=fail_on_missing)
        return descs

    def consensus(self, check_alive=True):
        if check_alive and not self.isalive():
            self.reset()

        self.circ, cons = ltor.consensus.download(self.circ,
            flavor='unflavored')
        return cons

    def isalive(self, force_check=False):
        with self.private_lock:
            if self.link is None:
                return False

            if self.link.io.dead:
                logging.warning('Slave node link seems dead.')
                return False

            if self.circ.circuit.destroyed:
                logging.warning('Bootstrap node circuit got destroyed.')
                return False

            if force_check or (time.time() - self.last) > isalive_period:
                logging.debug('Update slave node descriptor (heath check).')

                desc = self.authority(check_alive=False)
                if self.identity not in (None, desc['identity']):
                    raise RuntimeError('Slave node changed identity, abort!')

                self.last = time.time()
                self.identity = desc['identity']
            return True

    def close(self):
        with self.private_lock:
            self.link.close()

class consensus(basic):
    def __init__(self, clerk, qsize=default_qsize):
        clerk.consensus = dict(headers=None)
        super().__init__(clerk=clerk, qsize=qsize)

    def put(self, job):
        raise NotImplementedError

    def get_job(self):
        raise NotImplementedError

    def reset(self):
        if not self.clerk.slave.isalive():
            self.clerk.slave.reset()

        census = self.clerk.slave.consensus()

        if census['headers']['valid-until']['stamp'] < time.time():
            raise RuntimeError('Unable to get a fresh consensus, abort!')
        if not census['headers'] == self.clerk.consensus['headers']:
            super().reset()
            logging.info('Consensus successfully refreshed.')

        with self.private_lock:
            self.clerk.consensus = census

        # (cache descriptors for later use)
        self.clerk.slave.descriptors(census, fail_on_missing=False)

    def isalive(self):
        fresh_until = self.clerk.consensus['headers']['fresh-until']['stamp']
        return not (fresh_until < time.time())

    def isfresh(self):
        return not (self._out.qsize() < self.qsize)

    def refresh(self):
        try:
            self.put_job(self.clerk.consensus)
            return True
        except expired:
            return False

    def perform(self, timeout=1):
        return self.get(timeout=timeout)
