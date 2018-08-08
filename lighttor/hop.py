import zlib
import time
import queue

import lighttor as ltor

def recv(state, block=True, once=False, auto_sendme=True):
    '''Receive one or more RELAY{_EARLY,} cells from `state` attached circuit.

    :param state: a state object (see onion.state)
    :param bool block: block while receiving? (default: True)
    :param bool block: attempt only receiving once? (default: False)

    :returns: a tuple (updated state, received RELAY{_EARLY,} cells)

    Notes:
        - returns an updated state that *MUST* be used afterwards.
        - non-RELAY{_EARLY,} cells within the circuit *may be reordered.*
    '''

    while True:
        try:
            payload = state.link.get(circuit=state.circuit, block=block)
        except queue.Empty:
            return state, []
        except KeyError:
            raise RuntimeError('Circuit got destroyed, reason: {}'.format(
                state.circuit.reason))

        header = ltor.cell.header(payload)
        if header.cmd in [ltor.cell.cmd.RELAY, ltor.cell.cmd.RELAY_EARLY]:
            break

        state.link.put(state.circuit, payload)

    cell_type = ltor.cell.relay.cell
    if header.cmd is ltor.cell.cmd.RELAY_EARLY:
        cell_type = ltor.cell.relay_early.cell

    cell = cell_type(payload)
    #import pdb
    #pdb.set_trace()
    #if not cell.valid:
    #    raise RuntimeError(
    #        'Got invalid (encrypted) RELAY cell: {}'.format(cell.raw))

    state, cell = ltor.onion.peel(state, cell)
    if not cell.valid:
        raise RuntimeError(
            'Got invalid (decrypted) RELAY cell: {}'.format(cell.raw))

    if auto_sendme:
        state = _auto_sendme(state, cell)

    cells = [cell]
    while not once:
        state, new_cells = recv(state, block=False, once=True)
        if len(new_cells) == 0:
            break
        cells += new_cells
    return state, cells

# TODO: better sendme handling
def _auto_sendme(state, cell):
    if not cell.relay.cmd == ltor.cell.relay.cmd.RELAY_DATA:
        return state
    link, circuit, flow = state.link, state.circuit, ltor.constants.flow

    # Circuit-level sendme
    #
    if circuit.window is None:
        circuit.window = flow.circuit.default

    circuit.window -= 1
    if circuit.window < flow.circuit.lowlimit:
        circuit.window += flow.circuit.increment
        state = send(state, ltor.cell.relay.cmd.RELAY_SENDME)

    # Stream-level sendme
    #
    if not cell.relay.stream_id > 0:
        return state

    if circuit.stream_windows is None:
        circuit.stream_windows = dict()

    if not cell.relay.stream_id in circuit.stream_windows:
        circuit.stream_windows[cell.relay.stream_id] = flow.stream.default

    circuit.stream_windows[cell.relay.stream_id] -= 1
    if not circuit.stream_windows[cell.relay.stream_id] < flow.stream.lowlimit:
        return state

    circuit.stream_windows[cell.relay.stream_id] += flow.stream.increment
    state = send(state, ltor.cell.relay.cmd.RELAY_SENDME,
        stream_id=cell.relay.stream_id)

    return state

def send(state, command, payload=b'', stream_id=0):
    '''Send one RELAY{_EARLY,} cell through `state` attached circuit.

    :param state: a state object (see onion.state)
    :param str command: RELAY{_EARLY,} cell command (see cell.relay.cmd)
    :param bytes payload: RELAY{_EARLY,} cell content (default: b'')
    :param int stream_id: RELAY{_EARLY,} stream ID (default: 0)

    :returns: an updated state

    *Note: returns an updated state that *MUST* be used afterwards.*
    '''

    # We build our onion
    state, cell = ltor.onion.build(state, command, payload, stream_id)

    # Then, we send the encrypted payload.
    state.link.send(cell)
    return state

directory_request = '\r\n'.join((
      'GET {query} HTTP/1.0',
      'Accept-Encoding: {compression}',
    )) + '\r\n\r\n'

def directory_query(
        state,
        query=None,
        compression='deflate',
        timeout=5,
        **kwargs):
    if compression not in ['identity', 'deflate', 'gzip']:
        raise NotImplementedError(
            'Compression method "{}" not supported.'.format(compression))

    if query is None:
        query = '/tor/status-vote/current/consensus'
    if not query.startswith('/tor/') or any([c in query for c in ' \r\n']):
        raise RuntimeError('Invalid query: {}'.format(query))

    state.circuit.last_stream_id += 1
    stream_id = state.circuit.last_stream_id

    state = send(
        state, ltor.cell.relay.cmd.RELAY_BEGIN_DIR, stream_id=stream_id)
    state, cells = recv(state)

    if not cells[0].relay.cmd == ltor.cell.relay.cmd.RELAY_CONNECTED:
        raise RuntimeError('Expecting RELAY_CONNECTED after RELAY_BEGIN_DIR,'
            + ' got {} in cell:'.format(cells[0].relay.cmd, cells[0].raw))

    http = directory_request.format(query=query, compression=compression)

    http = bytes(http, 'utf8')
    width = ltor.cell.relay.payload_len
    while len(http) > 0:
        chunk, http = http[:width], http[width:]
        state = send(state, ltor.cell.relay.cmd.RELAY_DATA, chunk,
            stream_id=stream_id)

    # TODO: proper support for RELAY_END reasons
    state, cells = recv(state)
    if ltor.cell.relay.cmd.RELAY_END not in [c.relay.cmd for c in cells]:
        candidates = []
        diff_time = time.time()
        while True:
            if time.time() - diff_time > timeout:
                break

            state, new_cells = recv(state, block=False)
            candidates = [c.relay.cmd for c in new_cells]
            cells += new_cells

            if ltor.cell.relay.cmd.RELAY_END in candidates:
                break

            if len(candidates) > 0:
                diff_time = time.time()

        if time.time() - diff_time > timeout:
            raise RuntimeError(
                'Timeout while expecting RELAY_END: {:.2f}s out of {}s'.format(
                time.time() - diff_time, timeout))

    # TODO: proper support for incoming RELAY_SENDME cells
    cells = [c for c in cells if not (c.relay.stream_id == 0
                and c.relay.cmd == ltor.cell.relay.cmd.RELAY_SENDME)]

    # TODO: proper support for concurrent streams on the same circuit
    if not all([c.relay.stream_id == stream_id for c in cells]):
        raise RuntimeError('No proper support for multiple stream!')

    content = b''
    for cell in cells:
        if not cell.relay.cmd == ltor.cell.relay.cmd.RELAY_DATA:
            continue
        content += cell.relay.data

    if compression in ['deflate', 'gzip']:
        http_headers, compressed_data = content.split(b'\r\n\r\n', 1)
        raw_data = zlib_decompress(compressed_data)
        content = http_headers + b'\r\n\r\n' + raw_data

    if not content.startswith(b'HTTP/1.0'):
        raise RuntimeError('Unexpected answer to query "{}": {}'.format(query,
            content))

    return state, content

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
