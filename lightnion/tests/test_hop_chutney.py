import lightnion as lnn


def test_directory_query():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)
    endpoint = lnn.hop.send(endpoint, lnn.cell.relay.cmd.RELAY_DROP)

    # Download the full consensus without compression
    endpoint, full_answer = lnn.hop.directory_query(endpoint,
        '/tor/status-vote/current/consensus', compression='identity')

    # Download the microdesc consensus with compression
    endpoint, full_answer = lnn.hop.directory_query(endpoint,
        '/tor/status-vote/current/consensus-microdesc')

    assert True
