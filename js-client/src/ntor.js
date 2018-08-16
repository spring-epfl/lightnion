lighttor.ntor = {}
lighttor.ntor.keybytes = 92
lighttor.ntor.protoid = "ntor-curve25519-sha256-1"
lighttor.ntor.tweaks = {
    expand: lighttor.ntor.protoid + ":key_expand",
    verify: lighttor.ntor.protoid + ":verify",
    server: lighttor.ntor.protoid + "Server",
    key: lighttor.ntor.protoid + ":key_extract",
    mac: lighttor.ntor.protoid + ":mac"}

lighttor.ntor.hash_factory = function(tweak)
{
    tweak = lighttor.ntor.tweaks[tweak]
    tweak = sjcl.codec.utf8String.toBits(tweak)

    var hash = {
        hmac: new sjcl.misc.hmac(tweak),
        encrypt: function(data)
        {
            data = lighttor.enc.bits(data)
            data = hash.hmac.encrypt(data)
            return lighttor.dec.bits(data)
        }}
    return hash
}

lighttor.ntor.hash = {}
lighttor.ntor.hash.mac = lighttor.ntor.hash_factory("mac")
lighttor.ntor.hash.prk = lighttor.ntor.hash_factory("key")
lighttor.ntor.hash.verify = lighttor.ntor.hash_factory("verify")

lighttor.ntor.kdf = function(material, n)
{
    material = lighttor.ntor.hash.prk.encrypt(material)
    var hash = new sjcl.misc.hmac(lighttor.enc.bits(material))

    var tweak = lighttor.ntor.tweaks["expand"]
    tweak = sjcl.codec.utf8String.toBits(tweak)

    var idx = 1
    var out = lighttor.enc.bits([])
    var last = lighttor.enc.bits([])
    while (sjcl.bitArray.bitLength(out) < n * 8)
    {
        var idxbits = lighttor.enc.bits([idx])
        var current = sjcl.bitArray.concat(tweak, idxbits)

        last = hash.encrypt(sjcl.bitArray.concat(last, current))
        out = sjcl.bitArray.concat(out, last)
        idx = idx + 1
    }

    return lighttor.dec.bits(sjcl.bitArray.clamp(out, n * 8))
}

lighttor.ntor.hand = function(endpoint, descriptor, encode)
{
    if (encode === undefined)
        encode = true
    if (descriptor === undefined)
        descriptor = endpoint.guard

    var identity = lighttor.dec.base64(descriptor.router.identity + "=")
    var onionkey = lighttor.dec.base64(descriptor["ntor-onion-key"])

    endpoint.material = {}
    endpoint.material.ntor = nacl.box.keyPair()
    endpoint.material.identity = identity
    endpoint.material.onionkey = onionkey

    var pubkey = endpoint.material.ntor.publicKey
    var length = identity.length + onionkey.length + pubkey.length

    var payload = new Uint8Array(length)
    payload.set(identity, 0)
    payload.set(onionkey, identity.length)
    payload.set(pubkey, identity.length+onionkey.length)

    if (encode)
        return lighttor.enc.base64(payload)
    return payload
}

lighttor.ntor.fast = function(endpoint)
{
    endpoint.material = {}
    endpoint.material.ntor = nacl.box.keyPair()
    endpoint.material.identity = null
    endpoint.material.onionkey = null
    return lighttor.enc.base64(endpoint.material.ntor.publicKey)
}

lighttor.ntor.shake = function(endpoint, data, encoded)
{
    if (encoded === undefined)
        encoded = true
    if (encoded)
        data = lighttor.dec.base64(data)

    var client_pubkey = endpoint.material.ntor.publicKey
    var client_secret = endpoint.material.ntor.secretKey
    var server_pubkey = data.slice(0, nacl.scalarMult.scalarLength)
    var server_auth = data.slice(nacl.scalarMult.scalarLength)

    var identity = endpoint.material.identity
    var onionkey = endpoint.material.onionkey

    var exp_share = nacl.scalarMult(client_secret, server_pubkey)
    var exp_onion = nacl.scalarMult(client_secret, onionkey)

    var protoid = lighttor.dec.utf8(lighttor.ntor.protoid)
    var length = exp_share.length * 2 + identity.length + onionkey.length * 3
    var off = 0

    var secret_input = new Uint8Array(length + protoid.length)
    secret_input.set(exp_share, off); off += exp_share.length
    secret_input.set(exp_onion, off); off += exp_onion.length
    secret_input.set(identity, off); off += identity.length
    secret_input.set(onionkey, off); off += onionkey.length
    secret_input.set(client_pubkey, off); off += client_pubkey.length
    secret_input.set(server_pubkey, off); off += server_pubkey.length
    secret_input.set(protoid, off)
    var verify = lighttor.ntor.hash.verify.encrypt(secret_input)

    var server = lighttor.dec.utf8(lighttor.ntor.tweaks["server"])
    var length = verify.length + identity.length + onionkey.length * 3
    var off = 0

    var auth_input = new Uint8Array(length + server.length)
    auth_input.set(verify, off); off += verify.length
    auth_input.set(identity, off); off += identity.length
    auth_input.set(onionkey, off); off += onionkey.length
    auth_input.set(server_pubkey, off); off += server_pubkey.length
    auth_input.set(client_pubkey, off); off += client_pubkey.length
    auth_input.set(server, off)
    var client_auth = lighttor.ntor.hash.mac.encrypt(auth_input)

    var valid = true
    length = client_auth.length
    for (var i = 0; i < length; i++)
    {
        if (client_auth[i] != server_auth[i])
            valid = false
    }

    var zero_onion = 0
    var zero_share = 0
    length = exp_onion.length
    for (var i = 0; i < length; i++)
    {
        if (exp_onion[i] == 0)
            zero_onion = zero_onion + 1
        if (exp_share[i] == 0)
            zero_share = zero_share + 1
    }

    if (zero_onion == exp_onion.length || zero_share == exp_share.length)
        valid = false

    if (valid)
    {
        return lighttor.ntor.kdf(secret_input, lighttor.ntor.keybytes)
    }
    return null
}

lighttor.ntor.slice = function(material)
{
    var k = 16 // KEY_LEN
    var h = 20 // HASH_LEN
    var material = {
        key_hash: material.slice(h * 2 + k * 2),
        forward_digest: material.slice(0, h),
        backward_digest: material.slice(h, h * 2),
        forward_key: material.slice(h * 2, h * 2 + k),
        backward_key: material.slice(h * 2 + k, h * 2 + k * 2)
    }
    return material
}
