import lightnion as lnn


def test_consensus():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # downloading unflavored consensus
    endpoint, unflavored = lnn.consensus.download(endpoint,
        flavor='unflavored')

    # downloading microdesc consensus
    endpoint, microdesc = lnn.consensus.download(endpoint, flavor='microdesc')

    assert True
