from .. import cell as _cell
from . import view as _view

class reason(_view.enum(1)):
    NONE            = 0x00
    PROTOCOL        = 0x01
    INTERNAL        = 0x02
    REQUESTED       = 0x03
    HIBERNATING     = 0x04
    RESOURCELIMIT   = 0x05
    CONNECTFAILED   = 0x06
    OR_IDENTITY     = 0x07
    OR_CONN_CLOSED  = 0x08
    FINISHED        = 0x09
    TIMEOUT         = 0x0a
    DESTROYED       = 0x0b
    NOSUCHSERVICE   = 0x0c

class cell_view(_view.packet):
    _default_header_view = _cell.header_view
    _default_data_name = 'reason'
    _default_data_view = reason

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.DESTROY

view = cell_view()
cell = _view.like(view, 'destroy_cell')

def pack(circuit_id, reason):
    base = cell(b'')
    base.set(circuit_id=circuit_id, cmd=_cell.cmd.DESTROY, reason=reason)
    return base
