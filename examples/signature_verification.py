# TODO: add pip install pip install pycrypto to install vagrant file?
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import Crypto
import binascii
from lightnion import keys


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
    :param remaining: remaining (without the part that must be hashed) part of the consensus split by authoritiy
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


if __name__ == '__main__':
    # TODO: must be moved to ligthnion.consensus as a function called verify_siganture taking the raw consensus as
    # paramter and returnin a boolean if more than the half of the authority's signatures have been verified

    nbr_verified = 0
    # Get the consensus
    with open('./verif/cons.txt', 'r') as file:
        raw_cons = file.read()

    # split the consensus and hash it
    raw_cons = raw_cons.split('directory-signature ')
    cons = raw_cons[0] + 'directory-signature '
    h = SHA.new(cons.encode('ASCII'))

    # get the signatures and the signing keys
    signatures_and_key_digest = get_signature_and_digests(raw_cons[1:])
    keys_dict = keys.download_signing_keys()

    for fingerprint in signatures_and_key_digest.keys():
        # get the RSA public key and verify it is valid
        key = keys_dict[fingerprint]
        signing_key_digest = signatures_and_key_digest[fingerprint]['signing-key-digest']

        if not verify_key(key, signing_key_digest):
            continue
        else:
            public_key = RSA.importKey(key)

        # get the signature corresponding to fingerprint and convert it to binary
        signature_lines = signatures_and_key_digest[fingerprint]['signature'].split('\n')
        start_index = signature_lines.index("-----BEGIN SIGNATURE-----") + 1
        end_index = signature_lines.index("-----END SIGNATURE-----")
        raw_signature = ''.join(signature_lines[start_index:end_index])
        signature = binascii.a2b_base64(raw_signature)

        # Trying by hand now: apply RSA encrypt operation to signature
        m = public_key.encrypt(signature, 0)[0]

        # Compute k the number of bytes of the original message
        mod_bits = Crypto.Util.number.size(public_key.n)
        k = Crypto.Util.number.ceil_div(mod_bits, 8)

        # Prepend leading 0 bytes that encrypt does not return
        m = b'\x00' * (k - len(m)) + m

        # Check leading two bytes
        if m[:2] != b'\x00\x01':
            continue
        # Find end of padding and check padding bytes
        sep_idx = m.index(b'\x00', 2)
        for idx in range(2, sep_idx):
            if m[idx] != 0xff:
                continue

        # Compare encoded hash using strings, using bytes would work as well
        recovered_hash = binascii.hexlify(m[sep_idx + 1:]).decode()
        if recovered_hash == h.hexdigest():
            print("{}: signature verified".format(fingerprint))
            nbr_verified += 1
        else:
            print("{}: signature not verified".format(fingerprint))

    print("{} out of {} signatures have been verified".format(nbr_verified, len(signatures_and_key_digest.keys())))
