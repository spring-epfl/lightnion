import lightnion as lnn


if __name__=="__main__":
    """This serves as an example to see how the consensus and the descriptors are build"""

    link = lnn.link.initiate('127.0.0.1', 5000)
    print('Link v{} established – {}'.format(link.version, link.io))

    endpoint = lnn.create.fast(link)
    print('Link v{} established – {}'.format(link.version, link.io))

    endpoint, cons = lnn.consensus.download(endpoint, flavor='unflavored')

    for router in cons['routers']:
        print("{}: {}".format(router['nickname'], router['flags']))



   # import pdb; pdb.set_trace()