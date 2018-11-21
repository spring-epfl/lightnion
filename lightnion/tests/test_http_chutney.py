import lightnion as lnn
import lightnion.http


def test_polling():
    endpoint = ('127.0.0.1', 4990)
    padding = 100

    state, channel = lnn.http.client(*endpoint, io=lnn.http.polling.io)

    # Send bunch of padding
    for i in range(padding):
        state = lnn.hop.send(state, lnn.cell.relay.cmd.RELAY_DROP)

    # Retrieve something
    state, authority = lnn.descriptors.download_authority(state)

    # Retrieve something heavier
    state, authority = lnn.consensus.download(state, cache=False)

    # Destroy the channel
    state.link.close()

    assert True


def test_websocket():
    method = 'websocket'
    nb_downloads = 3
    host, port = '127.0.0.1', 4990
    padding = 100

    io_used = dict(
        polling=lnn.http.polling.io,
        websocket=lnn.http.websocket.io)[method]  # or 'polling'

    endpoint = host, port
    state, channel = lnn.http.client(*endpoint, io=io_used)

    # Send bunch of padding
    for i in range(padding):
        state = lnn.hop.send(state, lnn.cell.relay.cmd.RELAY_DROP)

    for _ in range(nb_downloads):
        # Retrieve something
        state, authority = lnn.descriptors.download_authority(state)

        # Retrieve something heavier
        state, _ = lnn.hop.directory_query(state,
            '/tor/status-vote/current/consensus',
            compression='identity')  # (no cache nor parsing nor compression)

    # Destroy the channel
    state.link.close()

    assert True
