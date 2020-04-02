import re

import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key


PATTERN_FINGERPRINT = r'fingerprint ([0-9A-Fa-f]+)'

PATTERN_KEY = r"""dir-signing-key
(-----BEGIN RSA PUBLIC KEY-----
[A-Za-z0-9+/=\n]+
-----END RSA PUBLIC KEY-----)
"""


def fetch_and_parse_keys(host, port=None, tls=True):
    """Convenience function to call getch_keys() then parse_keys() if needed."""

    keys_raw = fetch_keys(host, port, tls)
    if keys_raw:
        keys = parse_keys(keys_raw)
    else:
        keys = dict()

    return keys


def fetch_keys(host, port=None, tls=True):
    """Retrieve the public signing keys from the host."""
    protocol = 'https' if tls else 'http'
    path = "tor/keys/all"

    if port:
        url = "{}://{}:{}/{}".format(protocol, host, port, path)
    else:
        url = "{}://{}/{}".format(protocol, host, path)

    res = requests.get(url)

    if res.status_code == 200
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

    regex_fingerprint = re.compile(PATTERN_FINGERPRINT)
    regex_key = re.compile(PATTERN_KEY)

    keys = dict()

    for key_raw in keys_raw.split("dir-key-certificate-version "):

        # Extract fingerprint.
        fingerprint_match = regex_fingerprint.search(key_raw)
        if fingerprint_match:
            fingerprint_groups = fingerprint_match.groups()
            fingerprint = fingerprint_groups[0]

            # Extract signing key in PEM.
            key_match = regex_key.search(key_raw)
            if key_match:
                key_groups = key_match.groups()
                key_pem = key_groups[0]

                params = extract_key_params(key_pem)

                # Remember keys' parameters for each fingerprints.
                keys[fingerprint] = params

    return keys
