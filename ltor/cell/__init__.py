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
header_view_legacy = view.fields(
    circid=view.uint(2), cmd=cmd, length=view.length(2))
header_view_variable = view.fields(
    circid=view.uint(4), cmd=cmd, length=view.length(2))

class cell_view(view.packet):
    _whitelist = [header_view, header_view_legacy, header_view_variable]
    def __init__(self, header):
        if header not in self._whitelist:
            raise ValueError('Invalid header type: {}'.format(header))
        super().__init__(header_view=header, fixed_size=payload_len)

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd.is_fixed == self.fixed_size

variable_size = view.like(cell_view(header_view_variable), 'variable_size')
legacy_size = view.like(cell_view(header_view_legacy), 'legacy_size')
fixed_size = view.like(cell_view(header_view), 'fixed_size')
header = view.like(header_view, 'header')

import cell.versions
import cell.relay
