import cell
import cell.view as view

payload_len = 509
max_payload_len = 1024 * 1024 # (arbitrary, TODO: find a good one)

class cmd(view.enum(1)):
    PADDING             = 0x00
    CREATE              = 0x01
    CREATED             = 0x02
    RELAY               = 0x03
    DESTROY             = 0x04
    CREATE_FAST         = 0x05
    CREATED_FAST        = 0x06
    VERSIONS            = 0x07
    NETINFO             = 0x08
    RELAY_EARLY         = 0x09
    CREATE2             = 0x0a
    CREATED2            = 0x0b
    PADDING_NEGOTIATE   = 0x0c
    VPADDING            = 0x80
    CERTS               = 0x81
    AUTH_CHALLENGE      = 0x82
    AUTHENTICATE        = 0x83
    AUTHORIZE           = 0x84

    @property
    def is_fixed(self):
        return not self.is_variable

    @property
    def is_variable(self):
        if bool(0x80 & self._value_):
            return True
        return self._value_ == int(cmd.VERSIONS)

header_view = view.fields(
    circid=view.uint(4), cmd=cmd)
header_legacy_view = view.fields(
    circid=view.uint(2), cmd=cmd, length=view.cache(view.uint, init=[2]))
header_variable_view = view.fields(
    circid=view.uint(4), cmd=cmd, length=view.cache(view.uint, init=[2]))

class cell_view(view.packet):
    _whitelist = [header_view, header_legacy_view, header_variable_view]
    def __init__(self, header):
        if header not in self._whitelist:
            raise ValueError('Invalid header type: {}'.format(header))
        super().__init__(header_view=header, fixed_size=payload_len)

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd.is_fixed == self.fixed_size

variable_size = view.like(cell_view(header_variable_view), 'variable_size')
legacy_size = view.like(cell_view(header_legacy_view), 'legacy_size')
fixed_size = view.like(cell_view(header_view), 'fixed_size')

header = view.like(header_view, 'header')
header_legacy = view.like(header_legacy_view, 'header_legacy')
header_variable = view.like(header_variable_view, 'header_variable')

def _recv_given_size(peer, size):
    payload = b''
    while len(payload) < size:
        payload += peer.recv(size)
    return payload

def recv(peer):
    payload = _recv_given_size(peer, header_view.width())

    cell_header = header(payload)
    if not cell_header.valid:
        raise RuntimeError('Invalid cell header: {}'.format(cell_header.raw))

    if cell_header.cmd.is_fixed:
        return cell_header.raw + _recv_given_size(peer, payload_len)

    remains = header_variable_view.width() - len(payload)
    payload += _recv_given_size(peer, remains)

    cell_header = header_variable(payload)
    if not cell_header.valid:
        raise RuntimeError(
            'Invalid variable cell header: {}'.format(cell_header.raw))

    length = cell_header.length
    if length > max_payload_len:
        raise RuntimeError('Invalid cell length: {}'.format(length))

    return payload + _recv_given_size(peer, length)

import cell.parts

import cell.versions
import cell.netinfo
import cell.relay
import cell.certs

import cell.socket
