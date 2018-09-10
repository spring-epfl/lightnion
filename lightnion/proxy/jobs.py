import logging
import hashlib
import queue
import base64
import time

import lightnion as lnn
import lightnion.http

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
                logging.warning('Enforcing path emitter death.')
                self.child.process.terminate()

                for _ in range(refresh_timeout):
                    if self.child.dead:
                        break
                    self.child.process.terminate()
                    time.sleep(1)

            if not self.child.dead:
                raise RuntimeError('Unable to kill path emitter, abort!')

            logging.debug('Previous path emitter successfully terminated.')

        addr, port = self.clerk.slave_node[0], self.clerk.control_port
        self.child = lnn.proxy.path.fetch(tor_process=False,
            control_host=addr, control_port=port)
        self.guard = self.child.guard

        logging.debug('Path emitter successfully started.')

    def isalive(self):
        return (not self.child.dead
            and self.guard == self.child.guard)

    def isfresh(self):
        return not (self._out.qsize() < self.qsize - 1)

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
        self.link = lnn.link.initiate(addr, port)
        self.circ = lnn.create.fast(self.link)
        self.last = time.time()

        if not self.isalive(force_check=True):
            raise RuntimeError('Unable to interact with slave node, abort!')

    def authority(self, check_alive=True):
        if check_alive and not self.isalive():
            self.reset()
        self.circ, self.desc = lnn.descriptors.download_authority(self.circ)
        return self.desc

    def descriptors(self, query, fail_on_missing=True, check_alive=True):
        if check_alive and not self.isalive():
            self.reset()

        self.circ, descs = lnn.descriptors.download(self.circ, query,
            flavor='unflavored', fail_on_missing=fail_on_missing)
        return descs

    def consensus(self, check_alive=True):
        if check_alive and not self.isalive():
            self.reset()

        self.circ, cons = lnn.consensus.download(self.circ,
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
        valid_until = self.clerk.consensus['headers']['valid-until']['stamp']
        return not (valid_until < time.time())

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
            guard = lnn.proxy.path.convert(
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

        self.desc = self.clerk.slave.descriptors(router)[0]
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
                    self.clerk.delete.perform(circuit)
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
                sizes = [(c, c.queue.qsize())
                     for _, c in self.link.circuits.items()]
                sizes.sort(key=lambda sz: -sz[1])

                # Delete the most overfilled circuit
                self.clerk.delete.perform(sizes[0][0])
                while (not self.clerk.delete.isfresh()
                    and self.clerk.delete.refresh()):
                    pass
                return True
            else:
                raise e

    def perform(self, timeout=1):
        return self.get(timeout=timeout)

class create(ordered):
    def __init__(self, clerk, max_fails=5, qsize=default_qsize):
        self.last = time.time()
        self.fails = 0
        self.max_fails = max_fails
        self.alive_job_id = None
        self.alive_material = None
        super().__init__(clerk, qsize=qsize)

    def isalive(self):
        delta = time.time() - self.last
        if not delta > isalive_period:
            return True

        if self.alive_job_id is None:
            logging.info('Handshaking with guard to check liveness...')
            try:
                data, self.alive_material = lnn.http.ntor.hand(
                    self.clerk.guard.desc, encode=False)
                self.alive_job_id = self.put(data)
            except expired:
                logging.info('Unable to trigger handshaking.')
                return True

        if not delta > isalive_period + default_expiracy / 2:
            return True

        logging.info('Finishing handshake with guard to check liveness...')
        if self.alive_job_id is None:
            logging.info('Ignored handshake.')
            self.last = time.time()
            return True

        try:
            data = self.get(self.alive_job_id)
            some = lnn.http.ntor.shake(data['ntor'], self.alive_material)
            if some is None:
                logging.info('Handshake failed.')
                return False

            channel = self.clerk.channel_from_uid(data['id'])
            channel.delete()
        except expired:
            logging.info('Handshake expired.')
            return False
        except BaseException as e:
            logging.debug('Failed: {}'.format(e))
            logging.info('Handshake failed: guard link died?')
            return False

        self.clerk.guard.used = None
        self.alive_job_id = None
        self.fails = 0
        self.last = time.time()

        logging.info('Handshake success.')
        return True

    def reset(self):
        super().reset()
        if self.alive_job_id is not None:
            logging.info('Handshake failed, increasing failure.')
            self.fails += 1
            if self.fails > self.max_fails:
                logging.error('Unable to create circuits, resetting guard.')
                self.clerk.guard.reset()
                self.fails = 0

            self.alive_job_id = None
            self.last = time.time()

    def isfresh(self):
        return not (self._in.qsize() > 0)

    def refresh(self):
        try:
            job_id, data = self.get_job()
            logging.info('Got an incoming create channel request.')
        except expired:
            return False

        if not self.clerk.guard.isalive():
            self.clerk.guard.reset()

        # fast channel:
        #   if no identity/onion-key is given within the ntor handshake, the
        #   client doesn't know the guard identity/onion-key and we default to
        #   any guard we want!
        #
        fast = False
        if len(data) == 32:
            fast = True
            identity = base64.b64decode(
                self.clerk.guard.desc['router']['identity'] + '====')
            onion_key = base64.b64decode(
                self.clerk.guard.desc['ntor-onion-key'] + '====')
            data = identity + onion_key + data

        try:
            circid, data = lnn.create.ntor_raw(
                self.clerk.guard.link, data, timeout=1)
            circuit = lnn.create.circuit(circid, None)
            data = str(base64.b64encode(data), 'utf8')
        except BaseException as e:
            logging.debug('Got an invalid create ntor handshake: {}'.format(e))
            return True

        if not self.clerk.producer.isalive():
            self.clerk.producer.reset()

        if not self.clerk.consensus_getter.isalive():
            self.clerk.consensus_getter.reset()

        try:
            middle, exit = lnn.proxy.path.convert(*self.clerk.producer.get(),
                consensus=self.clerk.consensus, expect='list')
        except expired:
            logging.debug('Unable to get a path from producer.')
            return False

        middle = self.clerk.slave.descriptors(middle)[0]
        exit = self.clerk.slave.descriptors(exit)[0]

        token = self.clerk.crypto.compute_token(circid, self.clerk.maintoken)

        logging.debug('Circuit created with circuit_id: {}'.format(
            circid))
        logging.debug('Path picked: {} -> {}'.format(
            middle['router']['nickname'], exit['router']['nickname']))
        logging.debug('Token emitted: {}'.format(token))

        try:
            answer = {'id': token, 'path': [middle, exit], 'ntor': data}
            if fast:
                answer['guard'] = self.clerk.guard.desc
            self.put_job((circuit, answer), job_id)
        except expired:
            logging.warning('Too many create channel requests, dropping.')
            return False

        self.clerk.channels[circuit.id] = channel(
                self.clerk, circuit, self.clerk.guard.link)
        return True

    def get(self, job_id, timeout=1):
        circuit, data = super().get(job_id, timeout=timeout)
        self.clerk.guard.used = time.time()
        circuit.used = time.time()
        return data

    def perform(self, data, timeout=(1+2*default_expiracy)):
        timeout = timeout / 2

        data = base64.b64decode(data)
        job_id = self.put(data, timeout=timeout/2)
        return self.get(job_id, timeout=timeout/2)

class delete(basic):
    def isfresh(self):
        return not (self._in.qsize() > 0)

    def refresh(self):
        try:
            circuit = self.get_job()
            logging.info('Got an incoming delete channel request.')
        except expired:
            return False

        if not self.clerk.guard.isalive():
            self.clerk.guard.reset()
            return False

        self.clerk.guard.link.unregister(circuit)
        logging.debug('Deleting circuit: {}'.format(circuit.id))

        reason = lnn.cell.destroy.reason.REQUESTED
        self.clerk.guard.link.send(lnn.cell.destroy.pack(circuit.id, reason))
        logging.debug('Remaining circuits: {}'.format(list(
            self.clerk.guard.link.circuits)))

        circuit.destroyed = True
        circuit.reason = reason
        return True

    def perform(self, circuit, timeout=1):
        self.put(circuit)
        return {}

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
