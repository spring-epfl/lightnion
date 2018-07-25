import cell
import cell.view as _view

import ipaddress

class addr_type(_view.enum(1, cached=True)):
    HOSTNAME        = 0x00
    IPV4_ADDR       = 0x04
    IPV6_ADDR       = 0x06
    ERROR_TRANS     = 0xF0
    ERROR_NON_TRANS = 0xF1

header_view = _view.fields(**{
    'type': addr_type,
    'length': _view.cache(_view.uint, init=[1])})

class address_view(_view.packet):
    _default_extra_fields = ['type']
    _default_header_view = header_view
    _default_data_name = 'host'

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, **kwargs)

        length = self.header._fields['length']
        self._fields['host'] = _view.union(
            view_table={
                addr_type.HOSTNAME: _view.codec('utf8', size=length),
                addr_type.IPV4_ADDR: _view.ip_address(version=4),
                addr_type.IPV6_ADDR: _view.ip_address(version=6),
                addr_type.ERROR_TRANS: _view.data(length),
                addr_type.ERROR_NON_TRANS: _view.data(length)
            }, union_tag=self.header._fields['type'])

view = address_view()
address = _view.like(view, 'address')

def pack(host, type_hint=None):
    if type_hint is None:
        try:
            ipaddress.IPv4Address(host)
            type_hint = addr_type.IPV4_ADDR
        except ValueError:
            ipaddress.IPv6Address(host)
            type_hint = addr_type.IPV6_ADDR

    base = address(b'')
    base.header.set(**{'type': type_hint, 'length': 0})

    length = base._view.host.width()
    if length == 0:
        length = len(host)
    base.header.set(length=length)

    base.set(host=host)
    return base
