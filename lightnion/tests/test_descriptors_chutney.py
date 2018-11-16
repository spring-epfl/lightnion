import lightnion as lnn


def test_descriptors():
    import pdb

    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)

    # downloading descriptors
    endpoint, descriptors = lnn.descriptors.download(endpoint)
    endpoint, undescriptors = lnn.descriptors.download(endpoint,
        flavor='unflavored')

    # asking politely for our OR's descriptor
    endpoint, authority = lnn.descriptors.download_authority(endpoint)

    assert True
