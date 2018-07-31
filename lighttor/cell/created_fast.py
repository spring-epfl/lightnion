from .. import constants

from .. import cell as _cell
from . import view as _view

import os

created_fast_view = _view.fields(material=_view.data(constants.hash_len),
    derivative=_view.data(constants.hash_len))

class cell_view(_view.packet):
    _default_header_view = _cell.header_view
    _default_data_name = 'created_fast'
    _default_data_view = created_fast_view

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.CREATED_FAST

view = cell_view()
cell = _view.like(view, 'created_fast_cell')

def pack(circuit_id, material, derivative):
    base = cell(b'')
    base.set(
        circid=circuit_id,
        cmd=_cell.cmd.CREATED_FAST,
        created_fast=dict(material=material, derivative=derivative))
    return base
