import lighttor as ltor

import nacl.public

import base64

def hand(guard, encode=True):
    identity = base64.b64decode(guard['router']['identity'] + '====')
    onion_key = base64.b64decode(guard['ntor-onion-key'] + '====')

    ephemeral_key, payload = ltor.crypto.ntor.hand(identity, onion_key)

    if encode:
        payload = str(base64.b64encode(payload), 'utf8')
    return payload, (onion_key, ephemeral_key, identity)

def shake(payload, material):
    payload = base64.b64decode(payload)
    onion_key, ephemeral_key, identity = material

    material = ltor.crypto.ntor.shake(ephemeral_key, payload,
        identity, onion_key, length=92)

    return ltor.crypto.ntor.kdf(material)
