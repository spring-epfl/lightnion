import cell as _cell
import cell.view as _view

"""Tor CERTS cells views & wrappers

This module contains views and wrappers to help manipulation of CERTS cell.

It exposes:

    - cell -- The main public class for abstracting CERTS cells. After being
        constructed with a given raw bytes representation, it gives access to
        functions

This module

The following is a simple usage example that wraps bytes as a CERTS cell,
retrieve the third certificate, write it to file and then remove the last
certificate from the payload:

    certs_cell = cell.certs.cell(peer.recv())
    if not certs_cell.valid:
        raise RuntimeError

    if len(certs_cell.certs.listing) < 3:
        raise RuntimeError

    cert = certs_cell.certs.listing[2]
    with open('cert', 'wb') as f:
        f.write(cert.data)
    print('{} bytes written ({} cert)'.format(cert.clen, cert.type))

    certs_cell.certs.quantity -= 1
    certs_cell.truncate()

:

    -

    --------------------
    CERTS cell hierarchy
    --------------------

        [cell.certs.view]
            |
            + header        [cell.header_variable_view]
            |   + circid        [view.uint(2)]
            |   + cmd           [cell.cmd]
            |   + length        [view.cache(view.uint(2))]
            |
            + certs         [cell.certs.certs_view]
                |
                + header        [cell.certs.certs_header_view]
                |   + quantity      [view.cache(view.uint(1))]
                |
                + listing       [view.series(n=quantity)]
                    |
                    + 0 ... n       [cell.certs.cert_view]
                        |
                        + header        [cell.certs.cert_header_view]
                        |   + type          [cell.certs.cert_type]
                        |   + clen          [view.cache(view.uint(2))]
                        |
                        + data          [view.data(size=clen)]

"""

class cert_type(_view.enum(1)):
    RSA_SIGNED_LINK_KEY         = 0x01
    RSA_SELF_SIGNED_IDENTITY    = 0x02
    RSA_SIGNED_AUTHENTICATE     = 0x03
    ED_SIGNED_SIGNING_KEY       = 0x04
    ED_SIGNED_TLS_LINK          = 0x05
    ED_SIGNED_AUTHENTICATE      = 0x06
    RSA_SIGNED_ED_IDENTITY      = 0x07

cert_header_view = _view.fields(
    **{'type': cert_type, 'clen': _view.cache(_view.uint, init=[2])})
cert_view = _view.packet(header_view=cert_header_view, field_name='clen')

certs_header_view = _view.fields(quantity=_view.cache(_view.uint, init=[1]))
class _certs_view(_view.packet):
    _default_header_view = certs_header_view
    _default_field_name = 'quantity'
    _default_data_name = 'listing'

    def __init__(self, **kwargs):
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
