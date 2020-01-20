import lightnion as lnn


def test_select_path():
    addr, port = '127.0.0.1', 5000

    # Download the consensus
    lnn.cache.purge()
    link = lnn.link.initiate(address=addr, port=port)
    state = lnn.create.fast(link)
    state, cons = lnn.consensus.download(state, flavor='unflavored')

    state, guard, middle, exit_node = lnn.path_selection.select_path(
        cons['routers'], state, testing=True)

    assert True
