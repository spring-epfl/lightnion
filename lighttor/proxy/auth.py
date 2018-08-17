import collections
import curve25519
import logging
import base64
import json
import os

import lighttor as ltor
import lighttor.ntor_ref as ntor_ref

class material(collections.namedtuple('material', ['pkey', 'secret'])):
    @property
    def public(self):
        return self.pkey.get_public().public

    @property
    def suffix(self):
        suffix = base64.urlsafe_b64encode(b'auth ' + self.secret + self.public)
        return str(suffix.replace(b'=', b''), 'utf8')

    def perform(self, client, data):
        data = bytes(json.dumps(data), 'utf8')
        client = base64.b64decode(client)

        keys, msg = ntor_ref.server(self.pkey, self.secret,
            self.secret + self.public + client, keyBytes=92)
        keys = ltor.crypto.ntor.kdf(keys)

        state = ltor.onion.state(None, ltor.create.circuit(None, keys))
        data = base64.b64encode(state.forward_encryptor.update(data))
        auth = base64.b64encode(msg)

        return dict(data=str(data, 'utf8'), auth=str(auth, 'utf8'))

def filename(auth_dir, filename, base_dir=None):
    if base_dir is None:
        base_dir = os.getcwd()
    auth_dir = os.path.join(base_dir, auth_dir)

    if not os.path.isdir(auth_dir):
        logging.info('Note: creating {} for private material.'.format(
            auth_dir))
        os.mkdir(auth_dir)
    return os.path.join(auth_dir, filename)

_x25519_footer = b'-----END PRIVATE KEY-----'
_x25519_header = b'-----BEGIN PRIVATE KEY-----'
_x25519_openssl_asn1 = b'0.\x02\x01\x000\x05\x06\x03+en\x04"\x04 '

def genpkey(auth_dir, base_dir=None):
    logging.warning('New private key and shared secret generated.')

    pkey = curve25519.keys.Private().private
    with open(filename(auth_dir, 'private.pem'), 'wb') as f:
        f.write(_x25519_header + b'\n')
        f.write(base64.b64encode(_x25519_openssl_asn1 + pkey))
        f.write(b'\n' + _x25519_footer)
    with open(filename(auth_dir, 'shared_secret'), 'wb') as f:
        f.write(base64.b64encode(os.urandom(20)))

def getpkey(auth_dir, base_dir=None):
    with open(filename(auth_dir, 'shared_secret'), 'rb') as f:
        shared_secret = base64.b64decode(f.read())
    with open(filename(auth_dir, 'private.pem'), 'rb') as f:
        header, data, footer = f.read().split(b'\n')

    if header != _x25519_header:
        raise RuntimeError('Invalid pem header: {} vs {}'.format(
            header, _x25519_header))

    if footer != _x25519_footer:
        raise RuntimeError('Invalid pem footer: {} vs {}'.format(
            footer, _x25519_footer))

    raw = base64.b64decode(data)
    if (len(data) != 64
        or len(raw) != 48
        or not raw.startswith(_x25519_openssl_asn1)):
        raise RuntimeError('Invalid key encoding, expected asn1:'.format(
            base64.b64encode(_x25519_openssl_asn1)))

    auth = material(curve25519.keys.Private(raw[16:]), shared_secret)
    with open(filename(auth_dir, 'suffix'), 'w') as f:
        f.write(auth.suffix + '\n')
    return auth
