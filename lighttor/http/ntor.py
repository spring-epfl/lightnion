import lighttor as ltor
import lighttor.ntor_ref as ntor_ref

import curve25519
import base64

def hand(guard, encode=True):
    identity = base64.b64decode(guard['router']['identity'] + '====')
    onion_key = base64.b64decode(guard['ntor-onion-key'] + '====')

    donna_onion_key = curve25519.keys.Public(onion_key)
    ephemeral_key, payload = ntor_ref.client_part1(identity, donna_onion_key)

    if encode:
        payload = str(base64.b64encode(payload), 'utf8')
    return payload, (donna_onion_key, ephemeral_key, identity)

def shake(payload, material):
    payload = base64.b64decode(payload)
    donna_onion_key, ephemeral_key, identity = material

    material = ntor_ref.client_part2(ephemeral_key, payload,
        identity, donna_onion_key, keyBytes=92)

    return ltor.crypto.ntor.kdf(material)
