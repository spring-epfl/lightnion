from .. import constants
from . import view

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
    circuit_id=view.uint(4), cmd=cmd)
header_legacy_view = view.fields(
    circuit_id=view.uint(2), cmd=cmd, length=view.cache(view.uint, init=[2]))
header_variable_view = view.fields(
    circuit_id=view.uint(4), cmd=cmd, length=view.cache(view.uint, init=[2]))

class cell_view(view.packet):
    _whitelist = [header_view, header_legacy_view, header_variable_view]
    def __init__(self, header):
        if header not in self._whitelist:
            raise ValueError('Invalid header type: {}'.format(header))
        super().__init__(header_view=header, fixed_size=constants.payload_len)

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

def pad(payload):
    try:
        payload = payload.raw
    except AttributeError:
        pass

    cell_header = header(payload)
    if not cell_header.valid:
        raise RuntimeError('Invalid cell header: {}'.format(cell_header.raw))

    length = constants.payload_len + cell_header.width
    if not cell_header.cmd.is_fixed:
        cell_header = header_variable(payload)
        if not cell_header.valid:
            raise RuntimeError(
                'Invalid variable cell header: {}'.format(cell_header.raw))

        length = cell_header.length + cell_header.width
        if length > constants.max_payload_len:
            raise RuntimeError('Invalid cell length: {}'.format(length))

    return payload.ljust(length, b'\x00')

from . import address
from . import (
    padding, relay, destroy, create_fast, created_fast, versions, netinfo,
    relay_early, create2, created2, certs, challenge)
