import lightnion as lnn


def test_link():
    addr, port = '127.0.0.1', 5000

    link = lnn.link.initiate(addr, port)
    link.close()

    assert True
