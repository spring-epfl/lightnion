# TODO: add pip install pip install pycrypto to install vagrant file?
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
import Crypto
import binascii

fingerprint = '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4'
sign_hex_digest = '1F4D49989DA1503D5B20EAADB0673C948BA73B49'

if False:
    SIGNATURE_FILE = "./verif/my_signature.txt"
    KEY_FILE = "./verif/my_public2048.pem"
else:
    SIGNATURE_FILE = "./verif/signature.txt"
    KEY_FILE = "./verif/public.pem"


def verify_key(actual, hex_digest):
    key_hash = SHA.new(actual)
    return hex_digest == key_hash.hexdigest().upper()


if __name__ == '__main__':
    """This is an example of verification of the sigantures of the consensus (vote-status)"""
    # TODO: the code that verifies the consensus must be moved to consensus.py when it is working

    # TODO: should be directly parsed from /var/lib/tor/cached-certs
    # Download the key of the first authority and verifies it
    # On actual consensus => public.pem

    with open(KEY_FILE, 'r') as file:
        key = file.read()
        raw_key = ''.join(key.split('\n')[1:-2])
        key_bin = binascii.a2b_base64(raw_key)
        if not verify_key(key_bin, sign_hex_digest):
            raise ValueError("Key does not match digest!")

    # Download the consensus and hash it from the top through the space after directory-signature
    with open('./verif/cons.txt', 'r') as file:
        raw_cons = file.read()
        raw_cons = raw_cons.split('directory-signature ')
        if not raw_cons[1].startswith(fingerprint):
            print(raw_cons[1])
            raise ValueError("Fingerprint does not match")

        cons = raw_cons[0] + 'directory-signature '
        h = SHA.new(cons.encode('ASCII'))
        print("Computed SHA1 hash: ", h.hexdigest())

    # Download the signature and encode it in binary
    # On actual consensus => signature.txt
    with open(SIGNATURE_FILE, 'r') as file:
        signature_lines = file.read().split("\n")
        start_index = signature_lines.index("-----BEGIN SIGNATURE-----") + 1
        end_index = signature_lines.index("-----END SIGNATURE-----")
        raw_signature = ''.join(signature_lines[start_index:end_index])
        signature = binascii.a2b_base64(raw_signature)

    public_key = RSA.importKey(key)
    print("Public key modulus: ", public_key.n)
    print("Public key exponent: ", public_key.e)
    verifier = PKCS1_v1_5.new(public_key)

    # res = verifier.verify(h, signature)
    # if res:
    #    print("IT WORKS")
    # else:
    #    print("IT FAILS ", res)

    # Trying by hand now: apply RSA encrypt operation to signature
    m = public_key.encrypt(signature, 0)[0]

    # Compute k the number of bytes of the original message
    mod_bits = Crypto.Util.number.size(public_key.n)
    k = Crypto.Util.number.ceil_div(mod_bits, 8)

    # Prepend leading 0 bytes that encrypt does not return
    m = b'\x00' * (k - len(m)) + m
    print(binascii.hexlify(m))

    ## Check correct PKCS#1 1.5 padding of message m

    # Check leading two bytes
    if m[:2] != b'\x00\x01':
        raise RuntimeError("Header incorrect")

    # Find end of padding and check padding bytes
    sep_idx = m.index(b'\x00', 2)
    for idx in range(2, sep_idx):
        if m[idx] != 0xff:
            raise RuntimeError("Padding bytes have wrong value {}".format(m[idx]))

    # Compare encoded hash using strings, using bytes would work as well
    recovered_hash = binascii.hexlify(m[sep_idx + 1:]).decode()
    print("Recovered hash: {}".format(recovered_hash))
    if recovered_hash == h.hexdigest():
        print("Signature CORRECT")
    else:
        print("Signature WRONG")
