from .. import constants

from .. import cell as _cell
from . import view as _view

payload_len = constants.payload_len - 11

class cmd(_view.enum(1)):
    RELAY_BEGIN         = 0x01
    RELAY_DATA          = 0x02
    RELAY_END           = 0x03
    RELAY_CONNECTED     = 0x04
    RELAY_SENDME        = 0x05
    RELAY_EXTEND        = 0x06
    RELAY_EXTENDED      = 0x07
    RELAY_TRUNCATE      = 0x08
    RELAY_TRUNCATED     = 0x09
    RELAY_DROP          = 0x0a
    RELAY_RESOLVE       = 0x0b
    RELAY_RESOLVED      = 0x0c
    RELAY_BEGIN_DIR     = 0x0d
    RELAY_EXTEND2       = 0x0e
    RELAY_EXTENDED2     = 0x0f

    @property
    def is_forward(self):
        return self in [
            cmd.RELAY_BEGIN,
            cmd.RELAY_DATA,
            cmd.RELAY_END,
            cmd.RELAY_SENDME,
            cmd.RELAY_EXTEND,
            cmd.RELAY_TRUNCATE,
            cmd.RELAY_DROP,
            cmd.RELAY_RESOLVE,
            cmd.RELAY_BEGIN_DIR,
            cmd.RELAY_EXTEND2]

    @property
    def is_backward(self):
        return self in [
            cmd.RELAY_DATA,
            cmd.RELAY_END,
            cmd.RELAY_CONNECTED,
            cmd.RELAY_SENDME,
            cmd.RELAY_EXTENDED,
            cmd.RELAY_TRUNCATED,
            cmd.RELAY_DROP,
            cmd.RELAY_RESOLVED,
            cmd.RELAY_EXTENDED2]

    @property
    def is_circuit(self):
        return self in [
            cmd.RELAY_BEGIN,
            cmd.RELAY_DATA,
            cmd.RELAY_END,
            cmd.RELAY_CONNECTED,
            cmd.RELAY_SENDME,
            cmd.RELAY_RESOLVE,
            cmd.RELAY_RESOLVED,
            cmd.RELAY_BEGIN_DIR]

    @property
    def is_control(self):
        return self in [
            cmd.RELAY_SENDME,
            cmd.RELAY_EXTEND,
            cmd.RELAY_EXTENDED,
            cmd.RELAY_TRUNCATE,
            cmd.RELAY_TRUNCATED,
            cmd.RELAY_DROP,
            cmd.RELAY_EXTEND2,
            cmd.RELAY_EXTENDED2]

relay_header_view = _view.fields(
    cmd=cmd,
    recognized=_view.data(2),
    streamid=_view.uint(2),
    digest=_view.data(4),
    length=_view.cache(_view.uint, init=[2]))

class relay_view(_view.packet):
    _default_header_view = relay_header_view
    _max_size = payload_len

    def valid(self, payload=b''):
        if not self.header.valid(payload):
            return False

        if not self.header.value(payload, 'recognized') == b'\x00\x00':
            return True

        return super().valid(payload)

payload_view = relay_view()
payload = _view.like(payload_view, 'relay_payload')

class cell_view(_view.packet):
    _default_data_view = payload_view
    _default_data_name = 'relay'
    _default_fixed_size = constants.payload_len
    _default_header_view = _cell.header_view

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        cell_cmd = self.header.value(payload, field='cmd')
        if not cell_cmd == _cell.cmd.RELAY:
            return False

        offset = self.offset(payload, field='relay')
        circuit_id = self.header.value(payload, field='circuit_id')
        relay_cmd = self.relay.header.value(payload[offset:], field='cmd')
        if circuit_id == 0 and not relay_cmd.is_control:
            return False
        return True

view = cell_view()
cell = _view.like(view, 'relay_cell')

def _pack_details(base, relay_cmd, recognized, streamid, digest, data):
    base.relay.header.set(
        cmd=relay_cmd,
        recognized=recognized,
        streamid=streamid,
        digest=digest,
        length=len(data))
    base.set(relay=dict(data=data))
    return base

def pack(circuit_id, cmd, data, recognized=b'\x00\x00', *, streamid, digest):
    base = cell(b'')
    base.header.set(
        circuit_id=circuit_id,
        cmd=_cell.cmd.RELAY)
    return _pack_details(base, cmd, recognized, streamid, digest, data)
