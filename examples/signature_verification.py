# TODO: add pip install pip install pycrypto to install vagrant file?
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
import binascii

fingerprint = '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4'
sign_hex_digest = '1F4D49989DA1503D5B20EAADB0673C948BA73B49'


def verify_key(actual, hex_digest):
    key_hash = SHA.new(actual)
    return hex_digest == key_hash.hexdigest().upper()


if __name__ == '__main__':
    """This is an example of verification of the sigantures of the consensus (vote-status)"""
    # TODO: the code that verifies the consensus must be moved to consensus.py when it is working

    # TODO: should be directly parsed from /var/lib/tor/cached-certs
    # Download the key of the first authority and verifies it
    # On actual consensus => public.pem
    with open('./verif/my_public2048.pem', 'r') as file:
        key = file.read()
        key_bin = binascii.a2b_base64('\n'.join(key.split('\n')[1:-1]))
        #if not verify_key(key_bin, sign_hex_digest):
        #    raise ValueError("Key does not match digest!")

    # Download the consensus and hash it from the top through the space after directory-signature
    with open('./verif/cons.txt', 'r') as file:
        raw_cons = file.read()
        raw_cons = raw_cons.split('directory-signature ')

        #if not raw_cons[1].startswith(fingerprint):
        #    print(raw_cons[1])
        #    raise ValueError("Fingerprint does not match")

        cons = raw_cons[0] + 'directory-signature '
        h = SHA.new(cons.encode('ASCII'))

    # Download the signature and encode it in binary
    # On actual consensus => signature.txt
    with open('./verif/my_signature.txt', 'r') as file:
        raw_signature = file.read()
        raw_signature = ''.join(raw_signature.split('\n')[1:-1])
        signature = binascii.a2b_base64(raw_signature)

    public_key = RSA.importKey(key)
    verifier = PKCS1_v1_5.new(public_key)

    if verifier.verify(h, signature):
        print("IT WORKS")
    else:
        print("IT FAILS")
