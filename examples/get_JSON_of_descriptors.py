import lightnion as lnn
import json

if __name__ == "__main__":
    # download the consensus
    lnn.cache.purge()
    link = lnn.link.initiate(port=5000)
    state = lnn.create.fast(link)
    state, cons = lnn.consensus.download(state, flavor='unflavored')

    state, descriptors = lnn.descriptors.download(state, flavor="unflavored")

    with open("/vagrant/descriptors.json", 'w') as file:
        file.write(json.dumps(descriptors))
