import time

import link_protocol
import create
import onion
import single_hop

"""
    We check here how long we can wait before sending data after establishing a
    stream within a single-hop circuit within a link.

    This was a good test to check how frequently keepalives are send:
        https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L482

    The answer is "more or less every 5 minutes".
"""

step = 0
def log(string, carriage=False):
    global step
    end = '' if not carriage else '\n'
    pad = ' ' * (72 - len(string))
    print('\r[{:3}] '.format(step) + string + pad, end=end, flush=True)

def stepwise_expiracy_check(step_start, step_size, step_end, keepalive=False):
    """
    Interact with an OR to find out how it reacts against a very-low-traffic
    stream, circuit & link. We establish in a loop a link, circuit & stream
    before waiting a given amount of time to then use the stream.

    We perform `(step_end - step_start)` steps, waiting `current * step_size`
    seconds and where `current` is a counter starting at `step_start` that is
    incremented after each successful turn.

    If `keepalive` is `True`, we send a PADDING_CELL every 4 minutes.
    """
    global step

    step = step_start
    while step < step_end:
        start = time.time()

        log('Connecting...')
        link = link_protocol.handshake()
        if link[0] is None:
            log('Unable to establish link.', True)
            continue

        log('Link -> Creating circuit...')
        circuit = create.fast(link)
        if circuit[1] is None:
            log('Unable to establish circuit.', True)
            continue
        endpoint = onion.state(link, circuit)

        log('Link -> Circuit -> Creating stream...')
        endpoint, res = single_hop.send(
            endpoint, 'RELAY_BEGIN_DIR', stream_id=1)
        if res is None:
            log('Unable to send a circuit creation cell...', True)
            continue

        log('Link -> Circuit -> Confirming stream...')
        endpoint, answers = single_hop.recv(endpoint)
        if answers is None or len(answers) < 1:
            log("Unable to receive 'connected' confirmation cell...", True)
            continue
        if len(answers) != 1 or answers[0].command != 'RELAY_CONNECTED':
            log('Unexpected behavior when confirming stream...', True)
            continue

        start_wait = time.time()
        while time.time() - start_wait < (step_size * step):
            remaining_seconds = (start_wait + step_size * step) - time.time()
            log('Link -> Circuit -> Stream -> [{:5.1f}s remaining]'.format(
                    remaining_seconds))

            time.sleep(0.1)
            if keepalive and (time.time() - start) % (4 * 60) < 0.1:
                log('Link -> Circuit -> Stream -> [{:5.1f}s remaining]'.format(
                    remaining_seconds) + ' ** keepalive', True)
                link_protocol.keepalive(link)

        http_request = '\r\n'.join((
            'GET /tor/status-vote/current/consensus HTTP/1.0',
            'Accept-Encoding: identity',
        )) + '\r\n\r\n'

        log('Link -> Circuit -> Stream -> Is it still alive now? Checking...')
        endpoint, res = single_hop.send(
            endpoint, 'RELAY_DATA', http_request, stream_id=1)
        if res is None:
            log('Unable to send our first data cell...', True)
            continue

        log('Link -> Circuit -> Stream -> Is it still alive now? Waiting...')
        endpoint, answers = single_hop.recv(endpoint)
        if answers is None or len(answers) < 1:
            log("Unable to receive an answer for our request...", True)
            continue
        for cell in answers:
            if cell.VALUE != 3:
                import pdb
                pdb.set_trace()
        if len(answers) < 10:
            log('Unexpectedly short answer to our request...', True)
            continue

        life = time.time() - start
        log('Link -> Circuit -> Stream -> Still working after {:5.1f}s'.format(
            life), True)

        link_socket, _ = link
        link_socket.close()

        link, circuit, endpoint = None, None, None
        step += 1

if __name__ == "__main__":
    # Try to find out when the OR will freak out
    stepwise_expiracy_check(0, 0.1,   9)
    stepwise_expiracy_check(1,   1,  10)
    stepwise_expiracy_check(2,   5,  10)
    stepwise_expiracy_check(5,  10,  10)
    stepwise_expiracy_check(2,  50,  10)

    # After 5 minutes of inactivity, we receive a PADDING_CELL from the OR
    stepwise_expiracy_check(0, 0.1,   9)
    stepwise_expiracy_check(7,  50,  10)

    # Every 4 minutes of inactivity, we send a PADDING_CELL to the OR
    stepwise_expiracy_check(2,  4 * 60,  10, keepalive=True)
    # -> We still receive a PADDING_CELL from the OR, thus we'll need to at
    #    least perform some form of "real traffic" every 4 minutes.
    #
