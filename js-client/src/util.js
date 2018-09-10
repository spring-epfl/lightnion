lnn.enc = {}
lnn.enc.bits = sjcl.codec.bytes.toBits
lnn.enc.utf8 = nacl.util.encodeUTF8
lnn.enc.base64 = nacl.util.encodeBase64
lnn.enc.bin = function(data)
{
    var str = ""
    for(var idx = 0; idx < data.length; idx++)
        str += String.fromCharCode(data[idx])
    return str
}

lnn.dec = {}
lnn.dec.bits = function(data)
{
    return new Uint8Array(sjcl.codec.bytes.fromBits(data))
}
lnn.dec.utf8 = nacl.util.decodeUTF8
lnn.dec.base64 = nacl.util.decodeBase64
lnn.dec.bin = function(str)
{
    var data = new Uint8Array(str.length)
    for(var idx = 0; idx < str.length; idx++)
        data[idx] = str.charCodeAt(idx)
    return data
}
