import lightnion as lnn


def test_create_fast():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)

    # Simple creation of one-hop circuits with CREATE_FAST cells:
    #   - no public keys involved (only exchanging randomness through TLS).
    #   - used in Tor to connects to the guard (the first hop) to reduce load.
    # Creating 10 one-hop circuits with CREATE_FAST cells
    for i in range(10):
        state = lnn.create.fast(link)

    assert True
