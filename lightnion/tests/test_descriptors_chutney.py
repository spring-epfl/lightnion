import lightnion as lnn


def test_download_microdesc():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # Downloading descriptors
    endpoint, descriptors = lnn.descriptors.download(endpoint,
        flavor='microdesc')

    assert True


def test_download_unflavored():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # Downloading descriptors
    endpoint, undescriptors = lnn.descriptors.download(endpoint,
        flavor='unflavored')

    assert True


def test_download_authority():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # Asking politely for our OR's descriptor
    endpoint, authority = lnn.descriptors.download_authority(endpoint)

    assert True
