import cell as _cell
import cell.view as _view

class length_view(_view.length):
    @property
    def cache(self):
        return super().cache // 2

    def valid(self, payload=b''):
        if not len(payload) >= self.size:
            return False
        return self.value(payload) > 0 and (self._cache % 2) == 0

    def value(self, payload=b''):
        super().value(payload)
        return self.cache

    def write(self, payload=b'', value=None):
        return super().write(payload, value * 2)

header_view = _view.fields(
    circid=_view.uint(2), cmd=_cell.cmd, length=length_view(2))

class cell_view(_view.packet):
    def __init__(self, header=header_view):
        super().__init__(header_view=header, data_name='versions')
        self._fields['versions'] = _view.series(
            _view.uint(2), header_view.length)
        self._max_size = 64 * 2

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.VERSIONS

view = cell_view()
cell = _view.like(view, 'versions_cell')
header = _view.like(header_view, 'versions_header')
