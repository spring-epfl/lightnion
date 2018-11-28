import lightnion as lnn
import lightnion.http

import pytest


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


@pytest.fixture()
def websocket_stress_test():
    def _websocket_stress_test(nb_downloads=3,
        padding=100, n_clients=1):

        method = 'websocket'
        host, port = '127.0.0.1', 4990

        io_used = dict(
            polling=lnn.http.polling.io,
            websocket=lnn.http.websocket.io)[method]  # or 'polling'

        endpoint = host, port
        clients = []
        for _ in range(n_clients):
            state, channel = lnn.http.client(*endpoint, io=io_used)
            clients.append(state)

        # Send bunch of padding
        for i in range(padding):
            for j, state in enumerate(clients):
                state = lnn.hop.send(state, lnn.cell.relay.cmd.RELAY_DROP)
                clients[j] = state

        for _ in range(nb_downloads):
            for j, state in enumerate(clients):
                # Retrieve something
                state, authority = lnn.descriptors.download_authority(state)

                # Retrieve something heavier
                state, _ = lnn.hop.directory_query(state,
                    '/tor/status-vote/current/consensus',
                    compression='identity')  # (no cache nor parsing nor compression)

                clients[j] = state

        # Destroy the channel
        for state in clients:
            state.link.close()

    return _websocket_stress_test


def test_websocket(websocket_stress_test):
    websocket_stress_test()
    assert True


def test_websocket_create_10_client(websocket_stress_test):
    websocket_stress_test(n_clients=10, nb_downloads=0,
        padding=0)
    assert True


def test_websocket_create_30_client(websocket_stress_test):
    websocket_stress_test(n_clients=30, nb_downloads=0,
        padding=0)
    assert True


def test_websocket_10_client(websocket_stress_test):
    websocket_stress_test(n_clients=10)
    assert True


def test_websocket_30_client(websocket_stress_test):
    websocket_stress_test(n_clients=30)
    assert True


def test_websocket_1000_padding(websocket_stress_test):
    websocket_stress_test(padding=1000)
    assert True


def test_websocket_10000_padding(websocket_stress_test):
    websocket_stress_test(padding=10000)
    assert True


def test_websocket_10_downloads(websocket_stress_test):
    websocket_stress_test(nb_downloads=10)
    assert True


def test_websocket_30_downloads(websocket_stress_test):
    websocket_stress_test(nb_downloads=30)
    assert True


def test_websocket_100_downloads(websocket_stress_test):
    websocket_stress_test(nb_downloads=100)
    assert True


# @pytest.mark.skip(reason="very slow, can be too slow sometimes, could be a problem")
def test_websocket_1000_downloads(websocket_stress_test):
    websocket_stress_test(nb_downloads=1000)
    assert True
