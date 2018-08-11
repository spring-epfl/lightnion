import logging
import hashlib
import queue
import base64
import time

import lighttor as ltor

default_qsize = 3
default_expiracy = 3

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
        super().put((job, jid, date), timeout=timeout)
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
                job, jid, date = super().get(timeout=timeout)
                self.pending_jobs[jid] = (job, date)
            except expired:
                continue

            olds = []
            for jid, (_, date) in self.pending_jobs.items():
                if time.time() - date > self.expiracy:
                    olds.append(jid)

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
        try:
            if self._path is not None:
                self.put_job(self._path)
                self._path = None
                return True
        except expired:
            pass

        try:
            if self._path is None:
                self._path = self.child.path_queue.get_nowait()
                return True
        except queue.Empty:
            return False

        return False

    def close(self):
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
        if check_alive and not self.clerk.consensus_getter.isalive():
            self.clerk.consensus_getter.reset()

        try:
            guard = ltor.proxy.path.convert(
                self.clerk.producer.guard,
                consensus=self.clerk.consensus,
                expect='list')[0]
        except BaseException:
            self.clerk.producer.reset()

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
        self.circ, desc = ltor.descriptors.download_authority(self.circ)
        return desc

    def reset(self):
        logging.info('Resetting guard node link.')

        router = self.router()
        if not self.router == router:
            logging.info('New guard: {}'.format(router['nickname']))
        self.identity = router['identity']

        # TODO: link authentication instead of NTOR handshakes!
        addr, port = router['address'], router['orport']
        self.link = ltor.link.initiate(address=addr, port=port)

        self.desc = self.clerk.slave.descriptors(router)[0]
        self.circ = ltor.create.ntor(self.link, self.desc)

        self.last = time.time()
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

            desc = self.authority(check_alive=False)
            if self.identity != desc['router']['identity']:
                logging.warning('Guard changed its identity, need reset!')

                self.clerk.producer.reset()
                return False

            for key in ['ntor-onion-key', 'identity', 'router']:
                if not (self.desc[key] == desc[key]):
                    logging.info('Guard changed {}, need reset!.'.format(key))

                    self.clerk.producer.reset()
                    return False

            self.last = time.time()
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
            for _ in range(refresh_batches):
                if not self.link.pull(block=False):
                    return (redo or False)
            return True

        except RuntimeError as e:
            if 'queues are full' in str(e): # TODO: do better than this hack
                sizes = [(k, c.queue.qsize())
                     for k, c in self.link.circuits.items()]
                sizes.sort(key=lambda sz: -sz[1])

                # Delete the most overfilled circuit
                self.perform_delete(sizes[0][0])
                return True
            else:
                raise e

    def perform(self, timeout=1):
        return self.get(timeout=timeout)

class create(ordered):
    def isfresh(self):
        return not (self._in.qsize() > 0)

    def refresh(self):
        try:
            job_id, data = self.get_job()
            logging.info('Got an incoming create channel request.')
        except expired:
            return False

        try:
            circid, data = ltor.create.ntor_raw(self.clerk.guard.link, data)
            data = str(base64.b64encode(data), 'utf8')
        except BaseException as e:
            logging.info('Got an invalid create ntor handshake: {}'.format(e))
            return True

        if not self.clerk.guard.isalive():
            self.clerk.guard.reset()

        self.clerk.guard.link.register(ltor.create.circuit(circid, None))

        if not self.clerk.producer.isalive():
            self.clerk.producer.reset()

        if not self.clerk.consensus_getter.isalive():
            self.clerk.consensus_getter.reset()

        middle, exit = ltor.proxy.path.convert(*self.clerk.producer.get(),
            consensus=self.clerk.consensus, expect='list')

        middle = self.clerk.slave.descriptors(middle)[0]
        exit = self.clerk.slave.descriptors(exit)[0]

        token = self.clerk.crypto.compute_token(circid, self.clerk.maintoken)

        logging.debug('Circuit created with circuit_id: {}'.format(
            circid))
        logging.debug('Path picked: {} -> {}'.format(
            middle['router']['nickname'], exit['router']['nickname']))
        logging.debug('Token emitted: {}'.format(token))

        try:
            self.put_job({'id': token, 'path': [middle, exit], 'ntor': data},
                job_id)
        except expired:
            logging.warning('Too many create channel requests, dropping.')
            return False
        return True

    def perform(self, data, timeout=3):
        timeout = timeout / 2

        data = base64.b64decode(data)
        job_id = self.put(data, timeout=timeout/2)
        return self.get(job_id, timeout=timeout/2)
