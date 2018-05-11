import cryptography
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher

import stem
import stem.client.cell
import stem.client.datatype
import stem.socket

"""
    Showcase of https://trac.torproject.org/projects/tor/ticket/26060

    Affected:
        stem 1.6.0 (rev b2c8810d ... rev 8a065f42)

    Related:
        See commit 0d0a018d by Damian Johnson on RELAY cells

    Usage:
        git clone "https://git.torproject.org/stem.git" stem-client
        ln -s stem-client/stem
        virtualenv venv
        source venv/bin/activate
        pip install -r ./stem-client/requirements.txt
        tor PublishServerDescriptor 0 AssumeReachable 1 ExitRelay 0 ProtocolWarnings 1 SafeLogging 0 LogTimeGranularity 1 PidFile "$(mktemp)" SOCKSPort 0 ContactInfo none@example.com DataDirectory "$(mktemp -d)" ORPort 9050 DirPort 9051 Log "err stderr" &
        python stem_26060_issue.py
"""

host = '127.0.0.1'
port = 9050
version = 4
header_size = 5

if __name__ == "__main__":
    socket = stem.socket.RelaySocket(host, port)

    # establishing a v4 link
    socket.send(stem.client.cell.VersionsCell([version]).pack())
    socket.recv()

    # (send NETINFO)
    address = stem.client.datatype.Address(host)
    netinfo = stem.client.cell.NetinfoCell(address, [])
    socket.send(netinfo.pack(version))

    # create a new circuit
    circ_id = 0x80000000
    create = stem.client.cell.CreateFastCell(circ_id)

    # (retrieve OR's answer)
    socket.send(create.pack(version))
    created, _ = stem.client.cell.Cell.pop(socket.recv(), version)

    # (retrieve derived key_material)
    key_material = stem.client.datatype.KDF.from_value(
        create.key_material + created.key_material)
    assert key_material.key_hash == created.derivative_key

    # Compute forward digest (with zeroed digest field)
    fwdigest = hashlib.sha1(key_material.forward_digest)
    raw_cell = stem.client.cell.RelayCell(circ_id, 'RELAY_BEGIN_DIR', '', 0, 1)
    fwdigest.update(raw_cell.pack(version)[header_size:])

    # Pack RELAY_BEGIN_DIR cell afterwards (with the correct digest)
    raw_cell.digest = int.from_bytes(fwdigest.digest()[:4], byteorder="big")
    raw_data = raw_cell.pack(version)

    # Build the forward encryptor
    zeroed_ctr = modes.CTR(b'\x00' * (algorithms.AES.block_size // 8))
    fw_encrypt = Cipher(algorithms.AES(key_material.forward_key), zeroed_ctr,
        default_backend()).encryptor()

    # Encrypt the RELAY_BEGIN_DIR cell
    ciphertext = fw_encrypt.update(raw_data[header_size:])
    socket.send(raw_data[:header_size] + ciphertext)

    # We receive a encrypted answer
    relay_cell = socket.recv()
    print('Before repacking:')
    print('\tCell headers:')
    print('\t - circ_id:\t{}'.format(relay_cell[:4].hex()))
    print('\t - command:\t{}'.format(relay_cell[4:5].hex()))
    print('\tRELAY headers:')
    print('\t - command:\t{}'.format(relay_cell[5:6].hex()))
    print('\t - recognized:\t{}'.format(relay_cell[6:8].hex()))
    print('\t - stream_id:\t{}'.format(relay_cell[8:10].hex()))
    print('\t - digest:\t{}'.format(relay_cell[10:14].hex()))
    print('\t - length:\t{}'.format(relay_cell[14:16].hex()), end='\n\n')

    # We emulate stem.client's behavior here (repacking):
    #  https://gitweb.torproject.org/stem.git/tree/stem/client/__init__.py#n250
    #
    unpacked, _ = stem.client.cell.Cell.pop(relay_cell, version)
    repacked = unpacked.pack(version)

    # The "Length" field is now corrupted!
    #
    print('After repacking:')
    print('\tCell headers:')
    print('\t - circ_id:\t{}'.format(repacked[:4].hex()))
    print('\t - command:\t{}'.format(repacked[4:5].hex()))
    print('\tRELAY headers:')
    print('\t - command:\t{}'.format(repacked[5:6].hex()))
    print('\t - recognized:\t{}'.format(repacked[6:8].hex()))
    print('\t - stream_id:\t{}'.format(repacked[8:10].hex()))
    print('\t - digest:\t{}'.format(repacked[10:14].hex()))
    print('\t - length:\t{}'.format(repacked[14:16].hex()), end='\t')
    print('\t !! corrupted !!', end='\n\n')

    # Decrypting the cell
    bw_encrypt = Cipher(algorithms.AES(key_material.backward_key), zeroed_ctr,
        default_backend()).decryptor()
    plain = repacked[:header_size] + bw_encrypt.update(repacked[header_size:])

    # The cell "Length" field remains corrupted!
    print('After decryption:')
    print('\tCell headers:')
    print('\t - circ_id:\t{}'.format(plain[:4].hex()))
    print('\t - command:\t{}'.format(plain[4:5].hex()))
    print('\tRELAY headers:')
    print('\t - command:\t{}\t\t RELAY_CONNECTED'.format(plain[5:6].hex()))
    print('\t - recognized:\t{}'.format(plain[6:8].hex()))
    print('\t - stream_id:\t{}'.format(plain[8:10].hex()))
    print('\t - digest:\t{}'.format(plain[10:14].hex()))
    print('\t - length:\t{}'.format(plain[14:16].hex()), end='\t')
    print('\t !! corrupted !!', end='\n\n')

    # Reading the cell's "Digest" field
    relay_digest = plain[10:14]
    print('Digest (from the RELAY cell):\t{}'.format(relay_digest.hex()))

    # Computing the cell "real" backward digest (with "Length" corrupted)
    bwdigest = hashlib.sha1(key_material.backward_digest)
    plain = plain[:10] + b'\x00' * 4 + plain[14:]
    bwdigest.update(plain[header_size:])

    # (oops, mismatch)
    print('Digest (computed length):\t{}'.format(bwdigest.digest()[:4].hex()))

    # Computing the cell backward digest with the "Length" field guessed.
    bwdigest = hashlib.sha1(key_material.backward_digest)
    plain = plain[:10] + b'\x00' * 6 + plain[16:]
    bwdigest.update(plain[header_size:])

    # (now, it's matching)
    print('Digest (expected length):\t{}'.format(bwdigest.digest()[:4].hex()))
    print('\n')

