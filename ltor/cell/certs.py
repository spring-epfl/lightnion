import cell as _cell
import cell.view as _view

class cert_type(_view.enum(1)):
    RSA_SIGNED_LINK_KEY         = 0x01
    RSA_SELF_SIGNED_IDENTITY    = 0x02
    RSA_SIGNED_AUTHENTICATE     = 0x03
    ED_SIGNED_SIGNING_KEY       = 0x04
    ED_SIGNED_TLS_LINK          = 0x05
    ED_SIGNED_AUTHENTICATE      = 0x06
    RSA_SIGNED_ED_IDENTITY      = 0x07

cert_header_view = _view.fields(**{'type': cert_type, 'clen': _view.length(2)})
cert_view = _view.packet(cert_header_view, field_name='clen')

certs_header_view = _view.fields(quantity=_view.length(1))
class _certs_view(_view.packet):
    def __init__(self, header=certs_header_view):
        super().__init__(header_view=header,
            field_name='quantity', data_name='listing')
        self._fields['listing'] = _view.series(cert_view, header.quantity)

certs_view = _certs_view()
class cell_view(_view.packet):
    def __init__(self, header=_cell.header_variable_view):
        super().__init__(header_view=header, data_name='certs')
        self._fields['certs'] = certs_view

view = cell_view()
cell = _view.like(view, 'certs_cell')
