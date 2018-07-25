import cell
import cell.view as _view

class addr_type(_view.enum(1, cached=True)):
    HOSTNAME        = 0x00
    IPV4_ADDR       = 0x04
    IPV6_ADDR       = 0x06
    ERROR_TRANS     = 0xF0
    ERROR_NON_TRANS = 0xF1

address_header_view = _view.fields(**{
    'type': addr_type,
    'length': _view.cache(_view.uint, init=[1])})

class _address_view(_view.packet):
    _default_extra_fields = ['type']
    _default_header_view = address_header_view
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

address_view = _address_view()
address = _view.like(address_view, 'address')
