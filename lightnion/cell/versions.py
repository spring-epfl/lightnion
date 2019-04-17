from .. import constants
from . import common

from .. import cell as _cell
from . import view as _view

header_view = _view.fields(
    circuit_id=_view.uint(2),
    cmd=_cell.cmd,
    length=common.length_halved_view(2))

class cell_view(_view.packet):
    def __init__(self, header=header_view):
        super().__init__(header_view=header, data_name='versions')
        self._fields['versions'] = _view.series(
            _view.uint(2), header.length)
        self._max_size = 64 * 2

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.VERSIONS

view = cell_view()
cell = _view.like(view, 'versions_cell')
header = _view.like(header_view, 'versions_header')

def pack(versions):
    vercell = cell(b'')
    vercell.header.set(
        circuit_id=0,
        cmd=_cell.cmd.VERSIONS,
        length=len(versions))
    vercell.set(versions=versions)
    return vercell
