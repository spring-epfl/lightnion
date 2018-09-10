import base64

from ... import cell as _cell
from .. import view as _view

class linkspec_type(_view.enum(1, cached=True)):
    TLS_TCP_4   = 0x00
    TLS_TCP_6   = 0x01
    LEGACY_ID   = 0x02
    ED_ID       = 0x03

linkspec_header_view = _view.fields(**{
    'type': linkspec_type,
    'length': _view.cache(_view.uint, init=[1])})

class linkspec_view(_view.packet):
    _default_extra_fields = ['type']
    _default_header_view = linkspec_header_view

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, **kwargs)

        self._fields['data'] = _view.union(
            view_table={
                linkspec_type.TLS_TCP_4: _view.fields(
                    addr=_view.ip_address(version=4), port=_view.uint(2)),
                linkspec_type.TLS_TCP_6: _view.fields(
                    addr=_view.ip_address(version=6), port=_view.uint(2)),
                linkspec_type.LEGACY_ID: _view.data(20),
                linkspec_type.ED_ID: _view.data(32)
            }, union_tag=self.header._fields['type'])
linkspec = _view.like(linkspec_view(), 'linkspec')

linkspecs_header_view = _view.fields(
    quantity=_view.cache(_view.uint, init=[1]))

class linkspecs_view(_view.packet):
    _default_header_view = linkspecs_header_view
    _default_field_name = 'quantity'
    _default_data_name = 'specs'

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, **kwargs)
        self._fields['specs'] = _view.series(linkspec_view(),
            self._fields['header'].quantity)

class handshake_type(_view.enum(2)):
    # TAP   = 0x0001 # TODO: add support for TAP handshakes?
    NTOR    = 0x0002

extend2_header_view = _view.fields(**{'link': linkspecs_view(),
        'type': handshake_type, 'length': _view.cache(_view.uint, init=[2])})

class extend2_view(_view.packet):
    _default_header_view = extend2_header_view

view = extend2_view()
payload = _view.like(view, 'extend2_payload')

def _pack_linkspec_addr(addr, port):
    addr = _cell.address.pack(addr)

    base = linkspec(b'')
    if addr['type'] == _cell.address.addr_type.IPV4_ADDR:
        base.type = linkspec_type.TLS_TCP_4
    elif addr['type'] == _cell.address.addr_type.IPV6_ADDR:
        base.type = linkspec_type.TLS_TCP_6
    else:
        raise RuntimeError('Invalid address: {}'.format(addr))

    base.length = 0
    base.data.addr = addr.host
    base.data.port = port

    base.set(length=base.data.width)
    return base

def _pack_linkspec_identity(identity):
    if isinstance(identity, str):
        identity = base64.b64decode(identity + '====')

    base = linkspec(b'')
    if len(identity) == 20:
        base.type = linkspec_type.LEGACY_ID
    elif len(identity) == 32:
        base.type = linkspec_type.ED_ID
    else:
        raise RuntimeError('Invalid identity: {}'.format(identity))

    base.length = 0
    base.data = identity

    base.set(length=len(identity))
    return base

def pack(handshake, addresses=[], identities=[]):
    if len(addresses) < 1:
        raise RuntimeError('Expect at least one address!')
    if len(identities) > 2:
        raise RuntimeError('Expect at most two identities!')

    specs = []
    for addr, port in addresses:
        specs.append(_pack_linkspec_addr(addr, port).value())

    for identity in identities:
        specs.append(_pack_linkspec_identity(identity).value())

    if not any([s['type'] == linkspec_type.ED_ID for s in specs]):
        raise RuntimeError('Require at least one ed25519 identity!')

    base = payload(b'')
    base.header.link.set(quantity=len(specs), specs=specs)
    base.header.set(**{'type': handshake_type.NTOR, 'length': len(handshake)})
    base.set(data=handshake)
    return base
