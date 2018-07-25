from .. import cell as _cell
from . import view as _view
from . import common

import os

class auth_type(_view.enum(2)):
    RSA_AUTH    = 0x01
    ED_AUTH     = 0x03

auth_header_view = _view.fields(
    challenge=_view.data(32),
    quantity=common.length_halved_view(2))

class _auth_view(_view.packet):
    _default_header_view = auth_header_view
    _default_data_name = 'methods'
    _max_size = 2 * auth_type.width()

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, **kwargs)
        self._fields['methods'] = _view.series(
            auth_type, self._fields['header'].quantity)

auth_view = _auth_view()
class cell_view(_view.packet):
    _default_header_view = _cell.header_variable_view
    _default_data_view = auth_view
    _default_data_name = 'auth'

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.AUTH_CHALLENGE

view = cell_view()
cell = _view.like(view, 'auth_challenge_cell')

def pack(*methods, challenge=None):
    if challenge is None:
        challenge = os.urandom(32)

    base = cell(b'')
    base.header.set(circid=0, cmd=_cell.cmd.AUTH_CHALLENGE, length=0)
    base.auth.set(challenge=challenge, quantity=len(methods), methods=methods)
    base.set(length=base.auth.width)
    return base
