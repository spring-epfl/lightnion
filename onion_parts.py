import cryptography
import hashlib
import copy

import stem
import stem.client.cell

class state:
    """
    We aim here at building "onions" with several layers. Note that handling
    such layer can not be performed "stateless-ly" – as for example a stream
    cipher is used.

    This "state" class captures the stateful nature of onion-layer handling in
    two ways:
     - a "digest state" that captures the integrity check made on the content
       of the RELAY cells passing along the circuit (see state.reset_digest)
     - a "encryption state" that captures the stream cipher (AES counter mode
       with a zeroed IV) used to cipher the cells (see state.reset_encryption)

    Each one of these state have a "forward" and "backward" part used during
    the bidirectional communications (see state.reset_encryption for a recap.).

    Note that here, we only aim at encapsulating RELAY cells within a given
    circuit, as these cells are the one designed to be "relayed".
    """

    def __init__(self, link, circuit):
        """
        :params tuple link: a tuple (link socket, link version)
        :params tuple circuit: a tuple (circuit id, key material)
        """
        self.circuit = circuit
        self.link = link

        self.__sane = 0
        self.reset_digest() # define forward_digest, backward_digest
        self.reset_encryption() # define forward_encryptor, backward_decryptor

    def reset_digest(self, sanity=True):
        """
        This method initialize the "digest state" of a given layer, it should
        be only called once (via __init__) and will fail unless otherwise
        specified (via sanity parameter).

        Now, a bit of rationale around "How do we check RELAY cells integrity
        in an end-to-end fashion?"

        :- Introducing the 'recognized' field

        Each RELAY cell includes a 'recognized' field:
          https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1416

        The recognized field is used to check if a given RELAY cell content is
        still encrypted or not – the recognized field of an unencrypted RELAY
        cell content is zeroed:
          https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1446

        Whenever a relay receive a RELAY cell, it will decrypt the payload
        and will be able to check if the cell needs to be relayed or not – as
        cells "to be relayed" remain encrypted after a first decryption:
          https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1450

        :- Distinguishing recognized & unrecognized RELAY cells

        In order to be recognized, a RELAY cell – after being decrypted –
        must have a 'recognized' field equal to zero and a valid 'digest'
        field.

        See below for details about the 'digest' field.

        Upon checking, a cell is thus either recognized or unrecognized:
         - If we're not the last hop, we forwards every unrecognized cell to
           the next hop – supposing that we know which circuits it belongs to.
         - If we're the last hop and we receive an unrecognized cell from a
           circuit, this is an unrecoverable error and thus we tear down the
           circuit.

        See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1369

        :- Introducing the  'digest' field

        The 'digest' field is a "running hash" of all the recognized forward
        traffic (resp. backward) received (resp. originated). The hash used is
        a sha1 and it is seeded with forward_digest (resp. backward_digest):
            See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1455

        Note that this "running hash" do not includes forwarded data – as
        such relayed cell are deemed as "unrecognized" and thus not included
        in the "recognized traffic":
          https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1465

        This "running" hash can be described with the following pseudocode:

            h0 = sha1(seed)
            h1 = sha1(seed + cell1)
            h2 = sha1(seed + cell1 + cell2)
                ...
            hn = sha1(seed + cell1 + ... + celln)

            (where celln is the n-th payload)
            (where + denotes the concatenation)
            (where "seed" is "key_material.forward_digest" (resp. backward))

        Note that we implicitly require here that when we're not the last hop,
        the recognized field is equal to zero and the digest is invalid – thus
        the cell unrecognized – we still forward the cell.

        :- Distinguishing header & content of RELAY cells

        The 'digest' field only includes the RELAY cells content being
        deciphered and thus excludes headers of the cell – defined as the
        circuit ID and the cell command.

        Note that tor-spec is ambiguous about the fact that the 'digest' field
        MUST only include onion-encrypted data – cells content w/o headers.

        Note that the header size differs between link protocol versions: for
        v3-or-lower, the circuit id is only two bytes long and for v4-or-higher
        the circuit id is mapped on four full bytes. Hence, the header size is
        equal to 3 bytes for v3-or-lower and equal to 5 bytes for v4-or-higher
        as the command always take one byte.

        :- Other subtleties on the 'digest' field

        The 'digest' field of the n-th RELAY cell captures both the content of
        previous RELAY cells – without headers – and the current content of the
        n-th RELAY cell.

        In order to avoid including a hash's value within its input, every
        'digest' field included within the "running hash" input is to be zeroed
        before its inclusion.

        The pseudo-code to update the 'digest' field before sending is:

          if running_digest is not seeded:
              running_digest = sha1(key_material.forward_digest)

          cell_no_digest = build_cell(*parameters, digest=0)
          current_digest = running_digest.update(cell_no_digest)
          cell_with_digest = build_cell(*parameters, digest=current_digest)

          send(cell_with_digest)

        Note that here "running_digest.update" refers to common APIs of most
        hash libraries – such as hashlib used here. This method "concatenates"
        the new content to the previously-stored one and outputs their hash.

        Note that we need to perform this operation on both directions if we
        want to check integrity on both sides. Hence, we'll prefix by forward
        or backward the "running digest" we're using.

        :params bool sanity: enable extra sanity checks
        """
        _, key_material = self.circuit

        # (extra sanity checks)
        if sanity:
            if self.__sane != 0:
                raise RuntimeError('Please do not reset digests! (while sane)')
            self.__sane += 1

        # Seed the "running digests" for both directions
        self.forward_digest = hashlib.sha1(key_material.forward_digest)
        self.backward_digest = hashlib.sha1(key_material.backward_digest)

    def reset_encryption(self, sanity=True):
        """
        This method initialize the "encryption state" of a given layer, it must
        be only called once (via __init__) and will fail unless otherwise
        specified (via sanity parameter).

        See comments within the method for further details.

        :params bool sanity: enable extra sanity checks
        """
        _, key_material = self.circuit

        # (extra sanity checks)
        if sanity:
            if self.__sane != 1:
                raise RuntimeError('Unsafe! Please do not reset counter mode!')
            self.__sane += 1

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import (
            algorithms, modes, Cipher
        )

        # We use AES-CTR with an IV (or nonce) of all 0 bytes as stream cipher.
        #
        # See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L77
        #
        nonce_size = algorithms.AES.block_size // 8
        zeroed_ctr = modes.CTR(b'\x00' * nonce_size)

        # We have a "forward key" and a "backward key", respectively used to
        # encrypt the "forward traffic" (same direction as a CREATE cell) and
        # to decrypt the "backward traffic" (opposite direction).
        #
        # From our point of view (as OP), we use the forward key to encrypt and
        # the backward key to decrypt.
        #
        # From the point of view of an OR, it use the forward key to decrypt
        # and the backward key to encrypt.
        #
        # See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1360
        #
        self.forward_encryptor = Cipher(algorithms.AES(
                key_material.forward_key), zeroed_ctr, default_backend()
            ).encryptor()

        self.backward_decryptor = Cipher(algorithms.AES(
                key_material.backward_key), zeroed_ctr, default_backend()
            ).decryptor()

    def clone(self):
        child = state(self.link, self.circuit)

        # Clone digest state (use of hashlib's native hash copy)
        child.forward_digest = self.forward_digest.copy()
        child.backward_digest = self.backward_digest.copy()

        # Clone encryption state (use of python's ad-hoc copy)
        child.forward_encryptor = copy.copy(self.forward_encryptor)
        child.backward_decryptor = copy.copy(self.backward_decryptor)

        return child

def core(state, command, payload=b'', stream_id=0):
    """
    We build here a v4-or-higher "inner layer" of an onion-encrypted payload –
    this layer when decrypted shall be recognized by the last hop.

    The caller can trust the callee to not tamper with state and to output an
    updated version iff the callee succeeded – or else the unaffected state.

    :param state state: :class:`~state` which embeds digest & encryption state
    :param str command: RELAY cell command to send
    :param bytes payload: content of the RELAY cell (default: b'')
    :param int stream_id: stream ID (default: 0)

    :returns: a tuple (updated state, raw cell)
    """
    link_socket, link_version = state.link
    circuit_id, _ = state.circuit
    rollback = state.clone()

    # (we don't support v3-or-lower with short circIDs)
    if link_version < 4:
        return state, None
    header_size = 5

    # Compute the cell with a zeroed 'digest' field.
    cell_no_digest = stem.client.cell.RelayCell(
        circuit_id, command, payload, 0, stream_id) # 0 is the digest part)
    pack_no_digest = cell_no_digest.pack(link_version)

    # Update the "running digest", pack the cell with the 'digest' field.
    rollback.forward_digest.update(pack_no_digest[header_size:])
    cell_with_digest = stem.client.cell.RelayCell( # ^---- without headers!
        circuit_id, command, payload, rollback.forward_digest, stream_id)

    # Split the cell between the plain & to-be-encrypted parts.
    final_pack = cell_with_digest.pack(link_version)
    header, plaintext = final_pack[:header_size], final_pack[header_size:]

    # Encrypt the to-be-encrypted parts & build final cell
    cell_final = header + rollback.forward_encryptor.update(plaintext)
    return rollback, cell_final

def recognize(state, cell, backward=True):
    """
    We attempt to recognize a cell and update the digest state accordingly.

    The caller can trust the callee to not tamper with state and to output an
    updated version iff the cell is recognized – or else the unaffected state.

    Note that in order to be recognized, a cell must have its 'recognized'
    field zeroed – successful decryption – and its 'digest' field must match
    with the computed digest.

    See `reset_digest` in :class:`~state` for further details on digests.

    Note that whenever we are the intended recipient of a cell – for example as
    an exit node receiving a RELAY_BEGIN cell, an OP receiving RELAY cells, an
    OR receiving an EXTEND cell within RELAY_EARLY cell... – this steps acts as
    an integrity check.

    Thus, whenever we use it to receive data as an OP (our context here), this
    function is used to check the integrity of traffic incoming from ORs.

    :param state state: endpoint's :class:`~state`
    :param RelayCell cell: relay cell to be verified
    :param bool backward: use backward digest? or else forward? (default:True)

    :returns: a tuple (updated state, "is the cell recognized?" boolean)
    """

    _, link_version = state.link
    rollback = state.clone()

    # (we don't support version different than v4 for now)
    if link_version < 4:
        return state, False
    header_size = 5

    # We expect the recognized field to be zeroed upon successful decryption
    if cell.recognized != 0:
        return state, False

    # We build a copy of the cell with a zeroed 'digest field'
    cell_no_digest = stem.client.cell.RelayCell(cell.circ_id, cell.command,
        cell.data, digest=0, stream_id=cell.stream_id) # v---- without headers!
    pack_no_digest = cell_no_digest.pack(link_version)[header_size:]

    # Update the digest state accordingly (backward or forward)
    #
    # See `reset_digest` in :class:`~state` for further details on digests.
    # See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L1455
    #
    digest = rollback.backward_digest if backward else rollback.forward_digest
    digest.update(pack_no_digest)

    # Check if the computed digest match the cell digest
    digest_value = int.from_bytes(digest.digest()[:4], byteorder="big")
    if not digest_value == cell.digest:
        return state, False

    # Update the digest state iff the digests matched
    return rollback, True

def single_recv(state, sanity=True):
    """
    Receive one or more RELAY_CELL cells – assuming a v4-or-higher header size
    and that we are on a one-hop circuit.

    The caller can trust the callee to not tamper with state and to output an
    updated version iff the callee succeeded – or else the unaffected state.

    :param state state: endpoint's :class:`~state`
    :params bool sanity: extra sanity checks

    :returns: a tuple (updated state, received RELAY cells list / None)
    """
    link_socket, link_version = state.link
    circuit_id, _ = state.circuit
    rollback = state.clone()

    # (we don't support v3-or-lower with short circIDs)
    if link_version < 4:
        return state, None
    header_size = 5

    # We receive some data.
    answer = link_socket.recv()
    if len(answer) < 1:
        return state, None

    plains = []
    while len(answer) > 0:
        rcell, answer = stem.client.cell.Cell.pop(
            answer, link_version, is_encrypted=True)

        # Extra sanity checks
        if sanity:
            if rcell.circ_id != circuit_id:
                return state, None
            if not isinstance(rcell, stem.client.cell.RelayCell):
                return state, None

        # (we repack the cell after unpacking it to get its "raw bytes" form,
        #  but it's more a poor man's trick than a requirement)
        #
        repack = rcell.pack(link_version)
        header, ciphertext = repack[:header_size], repack[header_size:]

        # Decrypt the cell content
        plain = rollback.backward_decryptor.update(ciphertext)
        pcell = stem.client.cell.RelayCell._unpack(
            plain, rcell.circ_id, link_version)

        # Check for traffic integrity & Update backward_digest
        rollback, recognized = recognize(rollback, pcell)
        if not recognized:
            return state, None

        # Save the unencrypted cell for later.
        plains.append(pcell)

        # Upon receiving an incomplete RELAY cell, we can expect more data.
        if 514 > len(answer) > 0:
            answer += link_socket.recv()
    return rollback, plains

def single_send(state, command, payload='', stream_id=0):
    """
    Send one RELAY cell – assuming a v4-or-higher header size and that we are
    on a one-hop circuit.

    The caller can trust the callee to not tamper with state and to output an
    updated version iff the callee succeeded – or else the unaffected state.

    :param state state: endpoint's :class:`~state`
    :param str command: RELAY cell command to send
    :param bytes payload: content of the RELAY cell (default: b'')
    :param int stream_id: stream ID (default: 0)

    :returns: a tuple (updated state, number of bytes send / None)
    """
    link_socket, _ = state.link

    # We only need to build the inner layer of the onion.
    rollback, packed_cell = core(state, command, payload, stream_id)
    if packed_cell is None:
        return state, None

    # Then, we send the encrypted payload.
    link_socket.send(packed_cell)
    return rollback, len(packed_cell)

if __name__ == "__main__":
    import link_protocol
    import circuit_fast

    #
    # Here, we showcase how to:
    #   1. Establish a link (VERSIONS)
    #   2. Create a **single-hop** circuit (CREATE_FAST)
    #   3. Handle the encryption & digest state
    #   4. Create a stream that connects with remote OR's directory (BEGIN_DIR)
    #   5. Make an HTTP request that retrieve the network's consensus
    #   6. Receive the answer to our request
    #   7. Send few dummies on our circuit (RELAY_DROP)
    #   8. Close a stream (RELAY_END)
    #

    link = link_protocol.handshake()
    print('Link v{} established – {}'.format(link[1], link[0]))

    circuit = circuit_fast.create(link)
    print('Circuit {} created – Key hash: {}'.format(circuit[0],
        circuit[1].key_hash.hex()))

    # building the endpoint's state
    endpoint = state(link, circuit)

    print('[stream_id=1] Sending RELAY_BEGIN_DIR...')
    endpoint, _ = single_send(endpoint, 'RELAY_BEGIN_DIR', stream_id=1)

    print('[stream_id=1] Receiving now...')
    endpoint, answers = single_recv(endpoint)

    print('[stream_id=1] Success! (with {})'.format(answers[0].command))
    assert len(answers) == 1

    # handmade HTTP request FTW
    http_request = '\r\n'.join((
      'GET /tor/status-vote/current/consensus HTTP/1.0', # retrieve consensus
      'Accept-Encoding: identity', # no compression
    )) + '\r\n\r\n'

    print('[stream_id=1] Sending a RELAY_DATA to HTTP GET the consensus...')
    endpoint, answers = single_send(
        endpoint, 'RELAY_DATA', http_request, stream_id=1)

    print('[stream_id=1] Receiving now...')
    endpoint, answers = single_recv(endpoint)

    print('[stream_id=1] Success! (got {} answers)'.format(len(answers)))
    assert all([cell.command == 'RELAY_DATA' for cell in answers])

    print('[stream_id=1] Receiving again...')
    endpoint, answers = single_recv(endpoint)

    print('[stream_id=1] Success! (got {} answers)'.format(len(answers)))
    assert all([cell.command == 'RELAY_DATA' for cell in answers])

    print('[stream_id=1] Sending a RELAY_DROP for fun...')
    endpoint, _ = single_send(endpoint, 'RELAY_DROP', stream_id=0)

    print('[stream_id=1] Closing the stream...')
    endpoint, _ = single_send(endpoint, 'RELAY_END', stream_id=1)
