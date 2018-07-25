from .. import cell as _cell
from . import view as _view

import time

netinfo_header_view = _view.fields(timestamp=_view.uint(4),
    other=_cell.address.view, quantity=_view.cache(_view.uint, init=[1]))

class _netinfo_view(_view.packet):
    _default_header_view = netinfo_header_view
    _default_field_name = 'quantity'
    _default_data_name = 'addresses'

    _addr_type_whitelist = [
        _cell.address.addr_type.IPV4_ADDR, _cell.address.addr_type.IPV6_ADDR]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._fields['addresses'] = _view.series(_cell.address.view,
            self._fields['header'].quantity)

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        number = self.header.value(payload, field='quantity')
        offset = self.offset(payload, field='addresses')
        for i in range(number):
            roff = self.addresses.offset(payload[offset:], field=i)
            addr = self.addresses.item.type.value(payload[offset+roff:])
            if addr not in self._addr_type_whitelist:
                return False
        return True

netinfo_view = _netinfo_view()
class cell_view(_view.packet):
    _default_header_view = _cell.header_view
    _default_data_name = 'netinfo'
    _default_data_view = netinfo_view

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.NETINFO

view = cell_view()
cell = _view.like(view, 'netinfo_cell')

def pack(other_address, *addresses, timestamp=None):
    if timestamp is None:
        timestamp = int(time.time())

    base = cell(b'')
    base.set(
        circid=0,
        cmd=_cell.cmd.NETINFO,
        netinfo=dict(
            timestamp=timestamp,
            other=_cell.address.pack(other_address).value(),
            quantity=len(addresses),
            addresses=[_cell.address.pack(a).value() for a in addresses]))
    return base
