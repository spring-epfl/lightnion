import lightnion as lnn
from lightnion import path_selection
import cProfile

lnn.cache.purge()
link = lnn.link.initiate(port=5000)
state = lnn.create.fast(link)
state, cons = lnn.consensus.download(state, flavor='unflavored')

cProfile.run("path_selection.select_path(cons['routers'], state, testing=True)")
