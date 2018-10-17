import lightnion as lnn
from lightnion import path_selection

if __name__ == "__main__":

    #download the consensus
    lnn.cache.purge()
    link = lnn.link.initiate(port=5000)
    state = lnn.create.fast(link)
    state, cons = lnn.consensus.download(state, flavor='unflavored')

    state, guard, middle, exit_node = path_selection.select_path(cons['routers'], state, testing=True)

    print("Guard : {} {}".format(guard['router']['nickname'], guard['router']['address']))
    print("Middle: {} {}".format(middle['router']['nickname'], middle['router']['address']))
    print("Exit  : {} {}".format(exit_node['router']['nickname'], exit_node['router']['address']))