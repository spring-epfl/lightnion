import hashlib
import collections

from .. import cell, constants

class kdf_tor:
    def __init__(self, raw_material):
        counter = 0
        derived = bytes()
        while len(derived) < constants.key_len * 2 + constants.hash_len * 3:
            shasum = hashlib.sha1(raw_material + counter.to_bytes(1, 'big'))
            derived += shasum.digest()
            counter += 1

        h = constants.hash_len
        k = constants.key_len

        self.key_hash           = derived[:h]
        self.forward_digest     = derived[h :h*2]
        self.backward_digest    = derived[h*2:h*3]
        self.forward_key        = derived[h*3:h*3+k]
        self.backward_key       = derived[h*3+k:h*3+k*2]
