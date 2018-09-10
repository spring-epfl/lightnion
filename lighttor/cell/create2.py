from .. import cell as _cell
from . import view as _view

create_header_view = _view.fields(**{
    'type': _cell.relay.extend2.handshake_type,
    'length': _view.cache(_view.uint, init=[2])})

class create_view(_view.packet):
    _default_header_view = create_header_view

class cell_view(_view.packet):
    _default_header_view = _cell.header_view
    _default_data_name = 'create2'
    _default_data_view = create_view()

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.CREATE2

view = cell_view()
cell = _view.like(view, 'create2_cell')

def pack(circuit_id, handshake_data):
    base = cell(b'')
    base.set(
        circuit_id=circuit_id,
        cmd=_cell.cmd.CREATE2,
        create2=dict(**{'type': _cell.relay.extend2.handshake_type.NTOR,
            'length': len(handshake_data),
            'data': handshake_data}))
    return base
