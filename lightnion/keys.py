"""
Handle signing keys
"""

import base64
import hashlib
import re

import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_pem_public_key


RE_FINGERPRINT = re.compile(r'fingerprint ([0-9A-Fa-f]+)')
RE_KEY = re.compile(r"""dir-signing-key
(-----BEGIN RSA PUBLIC KEY-----
[A-Za-z0-9+/=\n]+
-----END RSA PUBLIC KEY-----)
""")
RE_SIGN = re.compile(r"""directory-signature ([0-9A-Fa-f]+) ([0-9A-Fa-f]+)
-----BEGIN SIGNATURE-----
([0-9A-Za-z+/=\n]+)
-----END SIGNATURE-----
""")


def fetch_and_parse_keys(host, port=None, tls=False):
    """Convenience function to call getch_keys() then parse_keys() if needed."""

    keys_raw = fetch_keys(host, port, tls)
    if keys_raw:
        keys = parse_keys(keys_raw)
    else:
        keys = dict()

    return keys


def fetch_keys(host, port=None, tls=False):
    """Retrieve the public signing keys from the host."""
    protocol = 'https' if tls else 'http'
    path = "tor/keys/all"

    if port:
        url = "{}://{}:{}/{}".format(protocol, host, port, path)
    else:
        url = "{}://{}/{}".format(protocol, host, path)

    res = requests.get(url)

    if res.status_code == 200:
        return res.text

    return None


def extract_key_params(key_pem):
    """Extract the exponent and modulus from a key in PEM format."""

    key_pem_b = key_pem.encode("ASCII")
    public_key = load_pem_public_key(key_pem_b, backend=default_backend())
    public_numbers = public_key.public_numbers()
    modulus = public_numbers.n
    exponent = public_numbers.e

    params = {
        "pem": key_pem,
        "modulus": str(modulus),
        "exponent": str(exponent)
    }

    return params


def parse_keys(keys_raw):
    """Parse raw keys."""

    keys = dict()

    for key_raw in keys_raw.split("dir-key-certificate-version "):

        # Extract fingerprint.
        fingerprint_match = RE_FINGERPRINT.search(key_raw)
        if fingerprint_match:
            fingerprint_groups = fingerprint_match.groups()
            fingerprint = fingerprint_groups[0]

            # Extract signing key in PEM.
            key_match = RE_KEY.search(key_raw)
            if key_match:
                key_groups = key_match.groups()
                key_pem = key_groups[0]

                params = extract_key_params(key_pem)

                # Remember keys' parameters for each fingerprints.
                keys[fingerprint] = params

    return keys


def verify_key_integrity(key_pem, digest_hex):
    """Verify the integrity of a key."""
    # Parse the PEM.
    key = base64.b64decode(key_pem[30, -28])
    sha1 = hashlib.sha1(key).digest()
    digest_b = bytes.fromhex(digest_hex)

    return sha1 == digest_b


def verify_consensus_signature(consensus_content, signature, key_pem):
    """Verify the signature of the consensus."""

    #public_key = load_pem_public_key(key_pem, backend=default_backend())

    # TODO Dummy check for now.
    return True


def verify_consensus_integrity(consensus, keys, min_valid_signatures=3):
    """Verify the signature of the consensus with the keys."""

    valid_signatures_num = 0

    signatures = [(s.start(), *(s.groups())) for s in RE_SIGN.finditer(consensus)]
    sign_num = len(signatures)

    cons_end = signatures[0][0]

    # The first "directory-signature " is included in the signature [sic].
    # So 20 extra characters are needed.
    cons_content = consensus[:(cons_end + 20)]

    for _, fingerprint, digest_hex, signature_pem in signatures:

        # Verify the integrity of the key.
        key_pem = keys.get(fingerprint).get('pem').encode("ASCII")
        key_valid = verify_key_integrity(key_pem, digest_hex)

        if not key_valid:
            continue

        cons_valid = verify_consensus_signature(cons_content, signature_pem, key_pem)

        if cons_valid:
            valid_signatures_num += 1

    return valid_signatures_num >= min_valid_signatures

