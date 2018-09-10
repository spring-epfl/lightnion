import nacl.bindings
import nacl.public
import nacl.hash

from .. import constants

x25519_keylen = 32
sha256_outlen = 32
sha256_blklen = 64

protoid = b'ntor-curve25519-sha256-1'
tweaks = dict(
    expand=protoid+b':key_expand',
    verify=protoid+b':verify',
    server=protoid+b'Server',
    key=protoid+b':key_extract',
    mac=protoid+b':mac')

class hmac:
    prf = lambda data: nacl.hash.sha256(data, encoder=nacl.encoding.RawEncoder)
    block_size = sha256_blklen
    output_size = sha256_outlen

    @staticmethod
    def digest(key, message):
        assert isinstance(key, bytes) and isinstance(message, bytes)

        if len(key) > hmac.block_size:
            key = hmac.prf(key)
        if len(key) < hmac.block_size:
            key = key.ljust(hmac.block_size, b'\x00')

        outer_key = bytes([k ^ 0x5c for k in key])
        inner_key = bytes([k ^ 0x36 for k in key])

        return hmac.prf(outer_key + hmac.prf(inner_key + message))

    @staticmethod
    def tweaked(tweak):
        tweak = tweaks[tweak]
        def _hash(data):
            return hmac.digest(tweak, data)
        return _hash

h_verify = hmac.tweaked('verify')
h_mac = hmac.tweaked('mac')

class kdf:
    @staticmethod
    def rfc5869(material, salt, context, length):
        key = hmac.digest(salt, material)

        n = (length // hmac.output_size) + 1
        output = b''
        previous = b''
        for idx in range(1, n + 1):
            t_idx = previous + context + idx.to_bytes(1, byteorder='big')
            t_idx = hmac.digest(key, t_idx)

            output += t_idx
            previous = t_idx
        return output[:length]

    @staticmethod
    def ntor(material, length):
        return kdf.rfc5869(material, tweaks['key'], tweaks['expand'], length)

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

def hand(identity, onion_key):
    client_keys = nacl.public.PrivateKey.generate()
    message = identity + onion_key + bytes(client_keys.public_key)

    assert len(message) == constants.hash_len + x25519_keylen * 2
    return client_keys, message

def server(server_keys, identity, message, length):
    assert len(message) == constants.hash_len + x25519_keylen * 2

    if identity != message[:20]:
        return None

    if bytes(server_keys.public_key) != message[20:52]:
        return None

    client_pubkey = nacl.public.PublicKey(message[52:])
    ephemeral_key = nacl.public.PrivateKey.generate()

    exp_share = nacl.bindings.crypto_scalarmult(
        bytes(ephemeral_key), bytes(client_pubkey))
    exp_onion = nacl.bindings.crypto_scalarmult(
        bytes(server_keys), bytes(client_pubkey))

    if sum(exp_share) == 0 or sum(exp_onion) == 0:
        return None

    secret_input = (exp_share + exp_onion + identity
        + bytes(server_keys.public_key)
        + bytes(client_pubkey)
        + bytes(ephemeral_key.public_key)
        + protoid)
    verify = h_verify(secret_input)

    auth_input = (verify + identity
        + bytes(server_keys.public_key)
        + bytes(ephemeral_key.public_key)
        + bytes(client_pubkey)
        + tweaks['server'])
    message = bytes(ephemeral_key.public_key) + h_mac(auth_input)

    return kdf.ntor(secret_input, length), message

def shake(client_keys, message, identity, onion_key, length):
    assert len(message) == x25519_keylen + sha256_outlen

    server_pubkey = nacl.public.PublicKey(message[:x25519_keylen])
    server_auth = message[x25519_keylen:]

    exp_share = nacl.bindings.crypto_scalarmult(
        bytes(client_keys), bytes(server_pubkey))
    exp_onion = nacl.bindings.crypto_scalarmult(
        bytes(client_keys), bytes(onion_key))

    if sum(exp_share) == 0 or sum(exp_onion) == 0:
        return None

    secret_input = (exp_share + exp_onion + identity
        + bytes(onion_key)
        + bytes(client_keys.public_key)
        + bytes(server_pubkey)
        + protoid)
    verify = h_verify(secret_input)

    auth_input = (verify + identity
        + bytes(onion_key)
        + bytes(server_pubkey)
        + bytes(client_keys.public_key)
        + tweaks['server'])

    if h_mac(auth_input) != server_auth:
        return None

    return kdf.ntor(secret_input, length)

def _selfshake(length):
    import os
    server_keys = nacl.public.PrivateKey.generate()
    onion_key = bytes(server_keys.public_key)
    identity = os.urandom(constants.hash_len)

    client_keys, message = hand(identity, onion_key)
    shared, message = server(server_keys, identity, message, length)
    assert shared == shake(client_keys, message, identity, onion_key, length)

    assert len(shared) == length
    return shared
