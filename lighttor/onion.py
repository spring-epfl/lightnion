import cryptography
import hashlib
import copy

import lighttor as ltor

class state:
    '''Handle Tor onion-encryption cryptographic states.

    *For now, only handle cryptography as an initiator (as an OP to an OR).*

    TODO: add support for __init__(link, circuit, initiator={True,False})

                                Status    Condition

        backward  decryptor   provided    initiator=True
                  encryptor     (none)    initiator=False
                     digest   provided
        forward   decryptor     (none)    initiator=False
                  encryptor   provided    initiator=True
                     digest   provided
    '''

    def __init__(self, link, circuit, early_count=8):
        '''Build a new onion-encryption state from a link and circuit.

        :params link: a link object (see link.link)
        :params circuit: a circuit object (see create.circuit)
        :params int early_count: first `early_count` cells will be RELAY_EARLY
        '''
        self.circuit = circuit
        self.link = link

        self._inner = None
        self.early_count = early_count

        self._last_material = None
        self._reset_digest(circuit.material)
        self._reset_encryption(circuit.material)

    @property
    def depth(self):
        '''Number of inner layers in the onion.'''
        if self._inner is None:
            return 0
        return self._inner.depth + 1

    @property
    def early_count(self):
        '''Number of remaining RELAY_EARLY cells before sending RELAY cells.'''

        if self._inner is None:
            return self._early_count
        return self._inner.early_count

    @early_count.setter
    def early_count(self, value):
        '''Setter for self.early_count.'''

        if self._inner is None:
            self._early_count = value
        else:
            raise RuntimeError(
                'Unable to set RELAY_EARLY counter from the outer layers!')

    def _wrap(self, inner):
        '''Wraps an inner state w/ self as outer state (see lighttor.extend).

        Usage:
            1. A one-hop circuit is build with stateA.
            2. A key exchange is made through stateA to get stateB.
            3. Then, call stateA.wrap(stateB) to properly wraps the onion.

        *Note: should not be called explicitly.*
        '''
        if self._inner is None:
            inner._early_count = self._early_count
            self._inner = inner
        else:
            self._inner._wrap(inner)

    def _reset_encryption(self, material):
        '''Initialize stateful stream cipher with cryptographic material.

        :params material: shared material w/ {forward,backward}_key

        *Note: should not be called explicitly.*
        '''
        if self._last_material == material:
            raise RuntimeError('Unsafe! Do NOT reset w/ same material!')
        self._last_material = material

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import (
            algorithms, modes, Cipher
        )

        # Tor uses AES128-CTF with IV=0 as stream cipher
        nonce_size = algorithms.AES.block_size // 8
        zeroed_ctr = modes.CTR(b'\x00' * nonce_size)

        # Initiate forward/backward encryption/decryption (as OP) TODO: add OR
        self.forward_encryptor = Cipher(
                algorithms.AES(material.forward_key),
                zeroed_ctr, default_backend()).encryptor()
        self.backward_decryptor = Cipher(
                algorithms.AES(material.backward_key),
                zeroed_ctr, default_backend()).decryptor()

    def _reset_digest(self, material):
        '''Seed stateful 'running digests' used to authenticate payloads.

        :params material: shared material w/ {forward,backward}_key

        *Note: should not be called explicitly.*
        '''
        self.forward_digest = hashlib.sha1(material.forward_digest)
        self.backward_digest = hashlib.sha1(material.backward_digest)

    def _clone(self):
        '''Non-recursive clone of current cryptographic state.

        Whenever it is required to rollback after an error, you can use this
        function to give yourself a clone of the current state.

        *Note: does not clone inner cryptographic states.*
        '''

        child = state(self.link, self.circuit)

        # Clone digest state (use of hashlib's native hash copy)
        child.forward_digest = self.forward_digest.copy()
        child.backward_digest = self.backward_digest.copy()

        # Clone encryption state (use of python's ad-hoc copy)
        child.forward_encryptor = copy.copy(self.forward_encryptor)
        child.backward_decryptor = copy.copy(self.backward_decryptor)

        # Don't forget to propagate the RELAY_EARLY count
        child._early_count = self._early_count

        # (note: we don't recursively clone inner layers of state)
        child._inner = self._inner

        return child

def core(state, command, payload=b'', stream_id=0):
    '''Build a RELAY{_EARLY,} cell as an onion core (plaintext w/ `state`)

    :param state: a state object (see onion.state)
    :param str command: RELAY{_EARLY,} cell command (see cell.relay.cmd)
    :param bytes payload: RELAY{_EARLY,} cell content (default: b'')
    :param int stream_id: RELAY{_EARLY,} stream ID (default: 0)

    :returns: a tuple (updated state, cell)

    *Note: should not be called explicitly.*
    '''
    rollback = state._clone()

    # Send RELAY_EARLY cells first
    relay_pack = ltor.cell.relay.pack
    if rollback.early_count > 0:
        rollback.early_count -= 1
        relay_pack = ltor.cell.relay_early.pack

    # Compute the cell with a zeroed 'digest' field.
    cell = relay_pack(
        circuit_id=state.circuit.id,
        cmd=command,
        data=payload,
        stream_id=stream_id,
        digest=b'\x00\x00\x00\x00')

    # Update the "running digest"
    rollback.forward_digest.update(cell.relay.raw)

    # Write the "running digest"
    full_digest = rollback.forward_digest.digest()
    cell.relay.digest = full_digest[:cell.relay._view.digest.width()]

    # Encrypt the to-be-encrypted parts & build final cell
    cell.relay.raw = rollback.forward_encryptor.update(cell.relay.raw)

    return rollback, cell

def build(state, command, payload=b'', stream_id=0):
    '''Build a RELAY{_EARLY,} cell.

    :param state: a state object (see onion.state)
    :param str command: RELAY{_EARLY,} cell command (see cell.relay.cmd)
    :param bytes payload: RELAY{_EARLY,} cell content (default: b'')
    :param int stream_id: RELAY{_EARLY,} stream ID (default: 0)

    :returns: a tuple (updated state, cell)

    *Note: returns an updated state that MUST be used afterwards.*
    '''
    if state.depth == 0:
        return core(state, command, payload, stream_id)
    rollback = state._clone()

    # Retrieve the inner layer of the onion
    rollback._inner, cell = build(rollback._inner, command, payload, stream_id)

    # Wraps the layer with our outer layer of encryption
    cell.relay.raw = rollback.forward_encryptor.update(cell.relay.raw)

    return rollback, cell

def recognize(state, cell, backward=True):
    '''Attempt to recognize a RELAY{_EARLY,} cell.

    :param state: a state object (see onion.state)
    :param cell: a RELAY{_EARLY,} cell object (see cell.relay.cell)
    :param bool backward: is it backward? or else forward? (default: True)

    :returns: a tuple (updated state, bool)

    *Note: returns an updated state that MUST be used afterwards.*
    '''
    rollback = state._clone()

    # We expect the recognized field to be zeroed upon successful decryption
    if not cell.relay.recognized == b'\x00\x00':
        return state, False

    # We build a copy of the cell with a zeroed 'digest field'
    cell_digest = cell.relay.digest
    cell.relay.digest = b'\x00\x00\x00\x00'

    # Update the digest state accordingly (backward or forward)
    digest = rollback.backward_digest if backward else rollback.forward_digest
    digest.update(cell.relay.raw)

    # Check if the computed digest match the cell digest
    if not cell_digest == digest.digest()[:cell.relay._view.digest.width()]:
        return state, False

    # Update state iff the digests matched
    return rollback, True

def peel(state, cell):
    '''Decrypt a RELAY{_EARLY,} cell using provided `state`.

    :param state: a state object (see onion.state)
    :param cell: a RELAY{_EARLY,} cell object (see cell.relay.cell)

    :returns: a tuple (updated state, decrypted cell)

    *Note: returns an updated state that MUST be used afterwards.*
    '''
    rollback = state._clone()
    cell.relay.raw = rollback.backward_decryptor.update(cell.relay.raw)
    if rollback.depth == 0:
        rollback, recognized = recognize(rollback, cell)
        if not recognized:
            raise RuntimeError(
                'Got an unrecognized RELAY cell: {}'.format(cell.raw))

        return rollback, cell

    cell.relay.raw = rollback.backward_decryptor.update(cell.relay.raw)
    rollback._inner, cell = peel(rollback._inner, cell)

    return rollback, cell
