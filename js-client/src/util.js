lighttor.enc = {}
lighttor.enc.bits = sjcl.codec.bytes.toBits
lighttor.enc.utf8 = nacl.util.encodeUTF8
lighttor.enc.base64 = nacl.util.encodeBase64

lighttor.dec = {}
lighttor.dec.bits = function(data)
{
    return new Uint8Array(sjcl.codec.bytes.fromBits(data))
}
lighttor.dec.utf8 = nacl.util.decodeUTF8
lighttor.dec.base64 = nacl.util.decodeBase64
