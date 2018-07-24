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

cert_header_view = _view.fields(**{
    'type': cert_type, 'clen': _view.cache(_view.uint, init=[2])})
cert_view = _view.packet(header_view=cert_header_view, field_name='clen')

certs_header_view = _view.fields(quantity=_view.cache(_view.uint, init=[1]))
class _certs_view(_view.packet):
    _default_header_view = certs_header_view
    _default_field_name = 'quantity'
    _default_data_name = 'listing'

    def __init__(self, **kwargs):
        assert 'data_name' not in kwargs and 'data_view' not in kwargs

        super().__init__(**kwargs)
        self._fields['listing'] = _view.series(cert_view,
            self._fields['header'].quantity)

certs_view = _certs_view()
class cell_view(_view.packet):
    _default_header_view = _cell.header_variable_view
    _default_data_name = 'certs'
    _default_data_view = certs_view

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        return cell_cmd == _cell.cmd.CERTS

view = cell_view()
cell = _view.like(view, 'certs_cell')
