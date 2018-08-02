from .. import constants

from .. import cell as _cell
from . import view as _view

from . import relay

class cell_view(_view.packet):
    _default_data_view = relay.payload_view
    _default_data_name = 'relay'
    _default_fixed_size = constants.payload_len
    _default_header_view = _cell.header_view

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        if not cell_cmd == _cell.cmd.RELAY_EARLY:
            return False

        offset = self.offset(payload, field='relay')
        circuit_id = self.header.value(payload, field='circuit_id')
        relay_cmd = self.relay.header.value(payload[offset:], field='cmd')
        if circuit_id == 0 and not relay_cmd.is_control:
            return False
        return True

view = cell_view()
cell = _view.like(view, 'relay_early_cell')

def pack(circuit_id, cmd, data, recognized=b'\x00\x00', *, stream_id, digest):
    base = cell(b'')
    base.header.set(
        circuit_id=circuit_id,
        cmd=_cell.cmd.RELAY_EARLY)
    return relay._pack_details(base, cmd, recognized, stream_id, digest, data)
