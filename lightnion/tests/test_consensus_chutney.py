import lightnion as lnn


def test_download_unflavored():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # Downloading unflavored consensus
    endpoint, unflavored = lnn.consensus.download(endpoint,
        flavor='unflavored')

    assert True


def test_download_microdesc():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # Downloading microdesc consensus
    endpoint, microdesc = lnn.consensus.download(endpoint, flavor='microdesc')

    assert True
