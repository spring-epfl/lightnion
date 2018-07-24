import cell
import cell.view as _view

class addr_type(_view.enum(1)):
    HOSTNAME        = 0x00
    IPV4_ADDR       = 0x04
    IPV6_ADDR       = 0x06
    ERROR_TRANS     = 0xF0
    ERROR_NON_TRANS = 0xF1

address_header_view = _view.fields(
    **{'type': addr_type, 'length': _view.cache(_view.uint, init=[1])})

address_view = _view.packet(header_view=address_header_view, data_name='value')
address = _view.like(address_view, 'address')
