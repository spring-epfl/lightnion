import hashlib

from .. import constants

class kdf:
    def __init__(self, material):
        width = constants.key_len * 2 + constants.hash_len * 3
        if not len(material) == width:
            raise RuntimeError(
                'Unexpected length: {} (need {})'.format(len(material), width))

        h = constants.hash_len
        k = constants.key_len

        self.key_hash =         material[h*2+k*2:]
        self.forward_digest =   material[:h]
        self.backward_digest =  material[h:h*2]
        self.forward_key =      material[h*2:h*2+k]
        self.backward_key =     material[h*2+k:h*2+k*2]
