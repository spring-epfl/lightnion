import lightnion as lnn
import socket
import time
import os

class InvalidCellHeaderException(Exception):
    def __init__(self, header):
        super().__init__('Invalid cell header: {}'.format(header))

class InvalidCellLengthException(Exception):
    pass


cell_cmd_to_string = {
    0: "PADDING",
    1: "CREATE",
    2: "CREATED",
    3: "RELAY",
    4: "DESTROY",
    5: "CREATE_FAST",
    6: "CREATED_FAST",
    7: "VERSIONS",
    8: "NETINFO",
    9: "RELAY_EARLY",
    10: "CREATE2",
    11: "CREATED2",
    12: "PADDING_NEGOTIATE",
    128: "VPADDING",
    129: "CERTS",
    130: "AUTH_CHALLENGE",
    131: "AUTHENTICATE",
    132: "AUTHORIZE"
}

def cell_to_str(cell):
    return cell[:20].hex()

def cell_get_cid(cell):
    return int.from_bytes(cell[0:4], 'big')


def cell_set_cid(cell, cid):
    return cid.to_bytes(4, 'big') + cell[4:]


def cell_get_cmd(cell):
    return cell[4]


def cell_version_get_cmd(cell):
    return cell[2]


def cell_get_len(cell):
    return int.from_bytes(cell[5:7], 'big')


def cell_version_get_len(cell):
    return int.from_bytes(cell[3:5], 'big')


def cell_pad_rnd(cell):
    if cell_is_variable_length(cmd):
        cell_len = 7 + cell_get_len(payload)
    else:
        cell_len = 514

    if cell_len > len(cell):
        return cell + os.urandom(cell_len - len(cell))
    else:
        return cell


def cell_pad_null(cell):
    if cell_is_variable_length(cmd):
        cell_len = 7 + cell_get_len(payload)
    else:
        cell_len = 514

    if cell_len > len(cell):
        return cell + bytearray(cell_len - len(cell))
    else:
        return cell


def cell_is_valid(cell):
    cmd = cell_get_cmd(cell)
    if cmd in  cell_cmd_to_string.keys():
        return False

    cell_len = cell_get_len(cell)
    if cell_len != len(cell):
        return False

    # TODO: add some checks.

    return True


def cell_is_variable_length(cmd):
    return cmd >= 128 or cmd == 7


def cmd_to_str(cmd):
    if cmd in  cell_cmd_to_string.keys():
        return cell_cmd_to_string[cmd]

    return 'UNKNOWN ({})'.format(cmd)


def cell_version_build(versions):
    cell = b'\x00\x00\x07' + (len(versions)*2).to_bytes(2, 'big')

    for version in versions:
        cell += version.to_bytes(2, 'big')

    return cell


def cell_version_is_valid(cell):
    cmd = cell_version_get_cmd(cell)
    if cmd != 7:
        return False

    cell_len = cell_version_get_len(cell)
    if cell_len != len(cell):
        return False

    # TODO: add some checks.

    return True


def cell_version_get_versions(cell):
    return [int.from_bytes(cell[i:i+2], 'big') for i in range(5, len(cell), 2)]


def cell_netinfo_build(host):
    tstmp = int(time.time()).to_bytes(4, 'big')
    if host == 'localhost':
        addr = b'\x7f\x00\x00\x01'
    else:
        addr = socket.inet_aton(host)

    addr_len = len(addr)

    if addr_len == 4:
        addr_t = b'\x04'
    else:
        addr_t = b'\x06'

    cell = b'\x00\x00\x00\x00\x08' + tstmp + addr_t + addr_len.to_bytes(1, 'big') + addr

    # padding
    cell += bytearray(514 - len(cell))

    return cell


def cell_slice(payload):
    """Retrieve the next cell from the payload and truncate that one.
    :param payload: bytearray
    """
    payload_len = len(payload)
    if payload_len < 7: # (payload too small, need data)
        return None, payload

    cmd = cell_get_cmd(payload)

    if cell_is_variable_length(cmd):
        cell_len = 7 + cell_get_len(payload)
    else:
        cell_len = 514

    if payload_len < cell_len:
        return None, payload

    cell = payload[:cell_len]

    return cell, payload[cell_len:]


#def cell_version_slice(payload):
#    payload_len = len(payload)
#    if payload_len < 5: # (payload too small, need data)
#        return None, payload
#
#    cell_len = 5 + cell_version_get_len(payload)
#
#    if payload_len < cell_len:
#        return None, payload
#    
#    cell = payload[:cell_len]
#
#    return cell, payload[cell_len:]


def cell_slice_old(payload):
    """Retrieve the next cell from the payload and truncate that one.
    :param payload: bytearray
    """
    cell_header = lnn.cell.header(payload)
    if len(payload) < cell_header.width: # (payload too small, need data)
        return None, payload

    if not cell_header.valid:
        raise InvalidCellHeaderException(cell_header.raw)

    length = cell_header.width + lnn.constants.payload_len
    if not cell_header.cmd.is_fixed:
        cell_header = lnn.cell.header_variable(payload)
        if len(payload) < cell_header.width: # (payload too small, need data)
            return None, payload

        if not cell_header.valid:
            raise InvalidCellHeaderException(cell_header.raw)

        length = cell_header.width + cell_header.length

    if length > lnn.constants.max_payload_len:
        raise InvalidCellLengthException()

    if len(payload) < length:
        return None, payload

    cell = payload[:length]

    return cell, payload[length:]

