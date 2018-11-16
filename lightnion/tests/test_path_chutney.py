import lightnion as lnn
import lightnion.proxy
import multiprocessing
import queue

    
def test_path():
    addr = '127.0.0.1'
    port = 5000
    target = 7
    tor_local = 0
    control_port = 8001

    # using chutney here, thus purge consensus cache just in case
    lnn.cache.purge()

    link = lnn.link.initiate(address=addr, port=port)
    endpoint = lnn.create.fast(link)
    endpoint, consensus = lnn.consensus.download(endpoint,
        flavor='unflavored')
    link.close()

    producer = lnn.proxy.path.fetch(target, tor_process=False,
        control_port=control_port)

    # retrieve the required number of paths
    paths = []
    while not producer.dead and len(paths) < target:
        paths.append(producer.get())
    producer.close()

    # convert (fingerprint, nickname) into a full consensus entry
    guard = producer.guard
    guard, paths = lnn.proxy.path.convert(guard, paths, consensus=consensus)

    assert True
