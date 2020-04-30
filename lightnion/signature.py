from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import Crypto
import binascii
from Crypto.Util.number import *


def verify(raw_cons, keys, minimal=0.5):
    """
    This function verifies the given raw consensus

    Note:   TOR does not perform a full PKCS#1 v1.5 signature (RFC 2313) as mentioned in the TOR's reference.
            The padding of the data that must be signed is done following the reference (see subsection 8.1 of the
            RFC 2313 for more details), however the digest is not wrapped into the data structure described in the
            subsection 10.1.2. This is the reason why RSA is performed manually and the module PKCS1_v1_5 of pycrypto is
            not used.

    :param raw_cons: the consensus we want to verify
    :param keys: a dictionary of keys as retrieved by the function get_signing_keys_info of tools/keys.py
    :param minimal: the minimal percentage of the authorities whose signatures must be verified in order to accept the given consensus
    :return: true if at least the minimal number of signatures are verified
    """
    assert 0 < minimal <= 1

    nbr_verified = 0
    total = 0

    # split the consensus and hash it
    raw_cons = raw_cons.split('directory-signature ')
    cons = raw_cons[0] + 'directory-signature '
    h = SHA.new(cons.encode('ASCII'))

    # get the signatures and the signing keys
    signatures_and_key_digest = get_signature_and_digests(raw_cons[1:])

    for fingerprint in signatures_and_key_digest.keys():
        total += 1
        # get the RSA public key and verify it is valid
        key = keys.get(fingerprint)
        signing_key_digest = signatures_and_key_digest[fingerprint]['signing-key-digest']

        if key is None or not verify_key(key["pem"], signing_key_digest):
            continue
        else:
            public_key = RSA.importKey(key["pem"])

        signature = get_binary_signature(fingerprint, signatures_and_key_digest)
        padded_hash = get_hash(public_key, signature)

        if not verify_format(padded_hash):
            continue

        sep_idx = padded_hash.index(b'\x00', 2)
        recovered_hash = binascii.hexlify(padded_hash[sep_idx + 1:]).decode()

        if recovered_hash == h.hexdigest():
            print("{}: signature verified".format(fingerprint))
            nbr_verified += 1
        else:
            print("{}: signature not verified".format(fingerprint))

    return nbr_verified > total * minimal


def get_hash(public_key, signature):
    """
    This functions performs RSA on a binary signature
    :param public_key: the key used to compute RSA
    :param signature: the signature
    :return: the binary digest of the signature
    """
    signature=bytes_to_long(signature)
    m = public_key._encrypt(signature)
    m = long_to_bytes(m)

    # Compute k the number of bytes of the original message
    mod_bits = Crypto.Util.number.size(public_key.n)
    k = Crypto.Util.number.ceil_div(mod_bits, 8)
    # Prepend leading 0 bytes that encrypt does not return
    m = b'\x00' * (k - len(m)) + m
    return m

def get_binary_signature(fingerprint, signatures_and_key_digest):
    """
    This function encodes a signature in base64 pem format into binary
    :param fingerprint: the fingerprint of the author of the signature we want to encode
    :param signatures_and_key_digest: the mapping from fingerprints to signature (and the signature key digest)
    :return: the binary version of the signature
    """
    # get the signature corresponding to fingerprint and convert it to binary
    signature_lines = signatures_and_key_digest[fingerprint]['signature'].split('\n')
    start_index = signature_lines.index("-----BEGIN SIGNATURE-----") + 1
    end_index = signature_lines.index("-----END SIGNATURE-----")
    raw_signature = ''.join(signature_lines[start_index:end_index])
    signature = binascii.a2b_base64(raw_signature)
    return signature


def verify_key(actual, hex_digest):
    """
    Function that verify that the downloaded key corresponds to the hex digest of the consensus
    :param actual: the key with the format

    -----BEGIN RSA PUBLIC KEY-----\n
    base64 encoded key split on multiples lines ending with \n
    -----END RSA PUBLIC KEY-----

    :param hex_digest: the sha1 digest of the key
    :return: true if the key is verified
    """
    raw_key = ''.join(actual.split('\n')[1:-1])
    key_bin = binascii.a2b_base64(raw_key)
    key_hash = SHA.new(key_bin)
    return hex_digest == key_hash.hexdigest().upper()


def get_signature_and_digests(remaining):
    """
    Function that get the signature and the hex digests from the remaining part of the consensus
    :param remaining: remaining (without the part that must be hashed) part of the consensus split by authority
    :return: dictionary mapping the fingerprint of an authority and both its signature and the hex digest of its public
    key
    """
    sign_and_digests = {}

    for r in remaining:
        if r != '':
            digests, sign = r.split('\n', 1)
            digests = digests.split(" ")
            identity, key_hex_digest = digests if len(digests) == 2 else digests[1:]

            sign_and_digests[identity] = {
                "signing-key-digest": key_hex_digest,
                "signature": sign
            }
    return sign_and_digests


def verify_format(padded_hash):
    """
    This function verifies that the hash as the good format, i.e:
    # 1 byte  - [null '\x00']
    # 1 byte  - [block type identifier '\x01'] - Should always be 1
    # N bytes - [padding '\xFF' ]
    # 1 byte  - [separator '\x00' ]
    # M bytes - [message]
    :param padded_hash:
    :return: true if the format is correct
    """
    # Check leading two bytes
    if padded_hash[:2] != b'\x00\x01':
        return False
    # Find end of padding and check padding bytes
    sep_idx = padded_hash.index(b'\x00', 2)
    for idx in range(2, sep_idx):
        if padded_hash[idx] != 0xff:
            return False

    return True
