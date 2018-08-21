lighttor.enc = {}
lighttor.enc.bits = sjcl.codec.bytes.toBits
lighttor.enc.utf8 = nacl.util.encodeUTF8
lighttor.enc.base64 = nacl.util.encodeBase64
lighttor.enc.binary = function(data)
{
    var str = ""
    for(var idx = 0; idx < data.length; idx++)
        str += String.fromCharCode(data[idx])
    return str
}

lighttor.dec = {}
lighttor.dec.bits = function(data)
{
    return new Uint8Array(sjcl.codec.bytes.fromBits(data))
}
lighttor.dec.utf8 = nacl.util.decodeUTF8
lighttor.dec.base64 = nacl.util.decodeBase64
lighttor.dec.binary = function(str)
{
    var data = new Uint8Array(str.length)
    for(var idx = 0; idx < str.length; idx++)
        data[idx] = str.charCodeAt(idx)
    return data
}
