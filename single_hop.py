import zlib

import stem
import stem.client.cell

import onion_parts
import circuit_fast
import link_protocol

def recv(state, sanity=True):
    """
    Receive one or more RELAY_CELL cells – assuming a v4-or-higher header size
    and that we are on a one-hop circuit.

    The caller can trust the callee to not tamper with state and to output an
    updated version iff the callee succeeded – or else the unaffected state.

    :param state onion_parts.state: endpoint's cryptographic state
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
        if answer[4] != stem.client.cell.RelayCell.VALUE:
            rcell, answer = stem.client.cell.Cell.pop(answer, link_version)
            plains.append(rcell)
            continue

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
        rollback, recognized = onion_parts.recognize(rollback, pcell)
        if not recognized:
            return state, None

        # Save the unencrypted cell for later.
        plains.append(pcell)

        # Upon receiving an incomplete RELAY cell, we can expect more data.
        if 514 > len(answer) > 0:
            answer += link_socket.recv()
    return rollback, plains

def send(state, command, payload='', stream_id=0):
    """
    Send one RELAY cell – assuming a v4-or-higher header size and that we are
    on a one-hop circuit.

    The caller can trust the callee to not tamper with state and to output an
    updated version iff the callee succeeded – or else the unaffected state.

    :param state onion_parts.state: endpoint's cryptographic state
    :param str command: RELAY cell command to send
    :param bytes payload: content of the RELAY cell (default: b'')
    :param int stream_id: stream ID (default: 0)

    :returns: a tuple (updated state, number of bytes send / None)
    """
    link_socket, _ = state.link

    # We only need to build the inner layer of the onion.
    rollback, packed_cell = onion_parts.core(
        state, command, payload, stream_id)
    if packed_cell is None:
        return state, None

    # Then, we send the encrypted payload.
    link_socket.send(packed_cell)
    return rollback, len(packed_cell)

directory_request_format = '\r\n'.join((
      'GET {query} HTTP/1.0',
      'Accept-Encoding: {compression}',
    )) + '\r\n\r\n'

def directory_query(
        state=None,
        query=None,
        last_stream_id=0,
        compression='deflate',
        sanity=True,
        **kwargs):

    if state is None:
        port = kwargs.get('port', 9050)
        address = kwargs.get('address', '127.0.0.1')
        versions = kwargs.get('versions', [4])
        link = link_protocol.handshake(address, port, versions, sanity)

        if None in link:
            return None, None, None

        circuits = kwargs.get('circuits', [])
        circuit = circuit_fast.create(link, circuits, sanity)

        if None in circuit:
            return None, None, None

        state = onion_parts.state(link, circuit, sanity)
    link_socket, link_version = state.link
    circuit_id, _ = state.circuit

    if last_stream_id is None:
        last_stream_id = 0
    last_stream_id += 1

    if query is None:
        query = '/tor/status-vote/current/consensus'
    if sanity:
        assert query.startswith('/tor/')
        assert not any([c in query for c in ' \r\n'])

    state, nbytes = send(state, 'RELAY_BEGIN_DIR', stream_id=last_stream_id)
    if nbytes is None:
        return state, last_stream_id, None

    state, answers = recv(state, sanity)
    if answers is None or len(answers) < 1:
        return state, last_stream_id, None

    if sanity:
        assert len(answers) == 1
        assert answers[0].command == 'RELAY_CONNECTED'

    if compression not in ['identity', 'deflate', 'gzip']:
        raise NotImplementedError(
            'Compression method "{}" not supported.'.format(compression))

    http_request = directory_request_format.format(
        query=query, compression=compression)
    state, nbytes = send(state, 'RELAY_DATA', http_request,
        stream_id=last_stream_id)
    if nbytes is None:
        return state, last_stream_id, None

    state, answers = recv(state, sanity)
    if answers is None or len(answers) < 1:
        return state, last_stream_id, None

    state, more_answers = recv(state, sanity)
    if more_answers is None or len(more_answers) < 1:
        return state, last_stream_id, None
    answers += more_answers

    state, nbytes = send(state, 'RELAY_END', stream_id=last_stream_id)
    if sanity:
        assert all([cell.command == 'RELAY_DATA' for cell in answers])
        assert nbytes is not None

    content = b''.join([cell.data for cell in answers if (
        cell.command == 'RELAY_DATA' and cell.stream_id == last_stream_id)])

    if compression in ['deflate', 'gzip']:
        http_headers, compressed_data = content.split(b'\r\n\r\n', 1)
        raw_data = zlib_decompress(compressed_data)
        content = http_headers + b'\r\n\r\n' + raw_data

    if sanity:
        assert content.startswith(b'HTTP/1.0')

    return state, last_stream_id, content

def zlib_decompress(compressed_data, min_bufsize=32):
    data = b''
    buff = b''
    part = None
    ilen = len(compressed_data)
    olen = 0
    zobj = zlib.decompressobj()
    while part is None or len(part) > 0:
        buff = zobj.unconsumed_tail
        if len(buff) < 1:
            nlen = max((len(data) + ilen) // 2, min_bufsize)
            buff = compressed_data[olen:nlen]
            if len(buff) < 1:
                break

            olen += len(buff)
        part = zobj.decompress(buff, zlib.MAX_WBITS | 32)
        data += part
    return data

if __name__ == "__main__":
    import link_protocol
    import circuit_fast
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

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
    #   9. Repeat with another stream
    #

    link = link_protocol.handshake(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link[1], link[0]))

    circuit = circuit_fast.create(link)
    print('Circuit {} created – Key hash: {}'.format(circuit[0],
        circuit[1].key_hash.hex()))

    # building the endpoint's state
    endpoint = onion_parts.state(link, circuit)

    print('[stream_id=1] Sending RELAY_BEGIN_DIR...')
    endpoint, _ = send(endpoint, 'RELAY_BEGIN_DIR', stream_id=1)

    print('[stream_id=1] Receiving now...')
    endpoint, answers = recv(endpoint)

    print('[stream_id=1] Success! (with {})'.format(answers[0].command))
    assert len(answers) == 1

    # handmade HTTP request FTW
    http_request = '\r\n'.join((
      'GET /tor/status-vote/current/consensus HTTP/1.0', # regular consensus
      'Accept-Encoding: identity', # no compression
    )) + '\r\n\r\n'

    print('[stream_id=1] Sending a RELAY_DATA to HTTP GET the consensus...')
    endpoint, _ = send(
        endpoint, 'RELAY_DATA', http_request, stream_id=1)

    print('[stream_id=1] Receiving now...')
    endpoint, answers = recv(endpoint)

    print('[stream_id=1] Success! (got {} answers)'.format(len(answers)))
    assert all([cell.command == 'RELAY_DATA' for cell in answers])
    full_answer = b''.join([cell.data for cell in answers])

    print('[stream_id=1] Receiving again...')
    endpoint, answers = recv(endpoint)

    print('[stream_id=1] Success! (got {} answers)'.format(len(answers)))
    assert all([cell.command == 'RELAY_DATA' for cell in answers])
    full_answer += b''.join([cell.data for cell in answers])

    print('[stream_id=0] Sending a RELAY_DROP for fun...')
    endpoint, _ = send(endpoint, 'RELAY_DROP', stream_id=0)

    print('[stream_id=1] Closing the stream...')
    endpoint, _ = send(endpoint, 'RELAY_END', stream_id=1)

    print('\nNote: consensus written to ./descriptors/consensus')
    with open('./descriptors/consensus', 'wb') as f:
        f.write(full_answer)

    #
    # second run (with compression function)
    #
    endpoint, last_stream_id, full_answer = directory_query(
        endpoint, '/tor/status-vote/current/consensus-microdesc',
        last_stream_id=1, compression='gzip')

    print('Note: micro-descriptor consensus',
        'written to ./descriptors/consensus-microdesc')
    with open('./descriptors/consensus-microdesc', 'wb') as f:
        f.write(full_answer)
