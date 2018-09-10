from .. import cell as _cell
from . import view as _view

class cell_view(_view.packet):
    _default_header_view = _cell.header_view
    _default_fixed_size = 0

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.PADDING

view = cell_view()
cell = _view.like(view, 'padding_cell')

def pack():
    base = cell(b'')
    base.set(circuit_id=0, cmd=_cell.cmd.PADDING)
    return base
