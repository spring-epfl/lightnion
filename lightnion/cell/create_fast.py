from .. import constants
from .. import cell as _cell
from . import view as _view

import os

create_fast_view = _view.fields(material=_view.data(constants.hash_len))

class cell_view(_view.packet):
    _default_header_view = _cell.header_view
    _default_data_name = 'create_fast'
    _default_data_view = create_fast_view

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.CREATE_FAST

view = cell_view()
cell = _view.like(view, 'create_fast_cell')

def pack(circuit_id, material=None):
    if material is None:
        material = os.urandom(constants.hash_len)

    base = cell(b'')
    base.set(
        circuit_id=circuit_id,
        cmd=_cell.cmd.CREATE_FAST,
        create_fast=dict(material=material))
    return base
