from .. import cell as _cell
from . import view as _view

created_header_view = _view.fields(length=_view.cache(_view.uint, init=[2]))

class created_view(_view.packet):
    _default_header_view = created_header_view

class cell_view(_view.packet):
    _default_header_view = _cell.header_view
    _default_data_name = 'created2'
    _default_data_view = created_view()

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.CREATED2

view = cell_view()
cell = _view.like(view, 'created2_cell')
