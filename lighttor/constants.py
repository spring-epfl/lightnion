
key_len = 16 # (aes128 CTR IV=0)
hash_len = 20 # (sha1)

payload_len = 509
full_cell_len = payload_len + 5
max_payload_len = 1024 * 1024 # (arbitrary, TODO: find a good one)

class flow:
    # 7.3. Circuit-level flow control
    class circuit:
        default = 1000
        lowlimit = 900
        increment = 100

    # 7.4. Stream-level flow control
    class stream:
        default = 500
        lowlimit = 450
        increment = 50
