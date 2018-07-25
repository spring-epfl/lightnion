from .. import cell as _cell
from . import view as _view
from . import common

header_view = _view.fields(
    circid=_view.uint(2),
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
    vercell.header.set(circid=0, cmd=_cell.cmd.VERSIONS, length=len(versions))
    vercell.set(versions=versions)
    return vercell

def recv(peer):
    answer = peer.recv(_cell.header_legacy_view.width())

    header = _cell.header_legacy(answer)
    if not header.valid:
        raise RuntimeError('Invalid v2 cell header: {}'.format(header.raw))
    if not header.cmd == _cell.cmd.VERSIONS:
        raise RuntimeError('Expecting VERSIONS, got: {}'.format(header.cmd))

    length = header.length
    if length > _cell.max_payload_len:
        raise RuntimeError('VERSIONS cell too long: {}'.format(header.length))

    answer += peer.recv(length)
    if not view.valid(answer):
        raise RuntimeError('Invalid VERSIONS cell: {}'.format(answer))

    return cell(answer)

def send(peer, payload):
    try:
        payload = payload.raw
    except AttributeError:
        pass

    vercell = cell(payload)
    if not vercell.valid:
        raise RuntimeError('VERSIONS cell invalid: {}'.format(payload))

    return peer.sendall(payload)
