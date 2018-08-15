var lighttor = {}
lighttor.api = {}

lighttor.api.version = '0.1'
lighttor.api.url = '/lighttor/api/v' + lighttor.api.version

lighttor.api.http_port = '4990'
lighttor.api.ws_port = '8765'

lighttor.endpoint = function(host)
{
    var http = 'http://' + host + ':' + lighttor.api.http_port
    http += lighttor.api.url

    var ws = 'ws://' + host + ':' + lighttor.api.ws_port
    ws += lighttor.api.url

    var urls = {
        ws: ws,
        http: http,
        guard: http + '/guard',
        channels: http + '/channels',
        consensus: http + '/consensus',
        websockets: ws + '/channels'}

    var endpoint = {
        host: host,
        urls: urls,
        io: null,
        material: null,
        forward: null,
        backward: null,
        id: null,
        url: null,
        path: null,
        guard: null,
        consensus: null}

    return endpoint
}

lighttor.get = {}
lighttor.get.guard = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest();
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 200)
        {
            endpoint.guard = JSON.parse(this.responseText)
            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4 && error !== undefined)
        {
            error(endpoint, this.status)
        }
    }
    rq.open('GET', endpoint.urls.guard, true)
    rq.send()
}
lighttor.get.consensus = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 200)
        {
            endpoint.consensus = JSON.parse(this.responseText)
            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4 && error !== undefined)
        {
            error(endpoint, this.status)
        }
    }
    rq.open('GET', endpoint.urls.consensus, true)
    rq.send()
}

lighttor.ntor = {}
lighttor.ntor.keybytes = 92
lighttor.ntor.protoid = 'ntor-curve25519-sha256-1'
lighttor.ntor.tweaks = {
    expand: lighttor.ntor.protoid + ':key_expand',
    verify: lighttor.ntor.protoid + ':verify',
    server: lighttor.ntor.protoid + 'Server',
    key: lighttor.ntor.protoid + ':key_extract',
    mac: lighttor.ntor.protoid + ':mac'}

lighttor.ntor.hash_factory = function(tweak)
{
    tweak = lighttor.ntor.tweaks[tweak]
    tweak = sjcl.codec.utf8String.toBits(tweak)

    var hash = {
        hmac: new sjcl.misc.hmac(tweak),
        encrypt: function(data)
        {
            data = sjcl.codec.bytes.toBits(data)
            data = this.hmac.encrypt(data)
            return new Uint8Array(sjcl.codec.bytes.fromBits(data))
        }}
    return hash
}

lighttor.ntor.hash = {}
lighttor.ntor.hash.mac = lighttor.ntor.hash_factory('mac')
lighttor.ntor.hash.prk = lighttor.ntor.hash_factory('key')
lighttor.ntor.hash.verify = lighttor.ntor.hash_factory('verify')

lighttor.ntor.kdf = function(material, n)
{
    material = lighttor.ntor.hash.prk.encrypt(material)
    var hash = new sjcl.misc.hmac(sjcl.codec.bytes.toBits(material))

    var tweak = lighttor.ntor.tweaks['expand']
    tweak = sjcl.codec.utf8String.toBits(tweak)

    var idx = 1
    var out = sjcl.codec.bytes.toBits([])
    var last = sjcl.codec.bytes.toBits([])
    while (sjcl.bitArray.bitLength(out) < n * 8)
    {
        var idxbits = sjcl.codec.bytes.toBits([idx])
        var current = sjcl.bitArray.concat(tweak, idxbits)

        last = hash.encrypt(sjcl.bitArray.concat(last, current))
        out = sjcl.bitArray.concat(out, last)
        idx = idx + 1
    }

    out = sjcl.bitArray.clamp(out, n * 8)
    return new Uint8Array(sjcl.codec.bytes.fromBits(out))
}

lighttor.ntor.hand = function(endpoint)
{
    var identity = nacl.util.decodeBase64(endpoint.guard.router.identity + '=')
    var onionkey = nacl.util.decodeBase64(endpoint.guard['ntor-onion-key'])

    endpoint.material = {}
    endpoint.material.ntor = nacl.box.keyPair()
    endpoint.material.identity = identity
    endpoint.material.onionkey = onionkey

    var pubkey = endpoint.material.ntor.publicKey
    var length = identity.length + onionkey.length + pubkey.length

    var payload = new Uint8Array(length)
    payload.set(identity, offset=0)
    payload.set(onionkey, offset=identity.length)
    payload.set(pubkey, offset=identity.length+onionkey.length)

    return nacl.util.encodeBase64(payload)
}

lighttor.ntor.shake = function(endpoint, data)
{
    data = nacl.util.decodeBase64(data)

    var client_pubkey = endpoint.material.ntor.publicKey
    var client_secret = endpoint.material.ntor.secretKey
    var server_pubkey = data.slice(0, nacl.scalarMult.scalarLength)
    var server_auth = data.slice(nacl.scalarMult.scalarLength)

    var identity = endpoint.material.identity
    var onionkey = endpoint.material.onionkey

    var exp_share = nacl.scalarMult(client_secret, server_pubkey)
    var exp_onion = nacl.scalarMult(client_secret, onionkey)

    var protoid = nacl.util.decodeUTF8(lighttor.ntor.protoid)
    var length = exp_share.length * 2 + identity.length + onionkey.length * 3
    var off = 0

    var secret_input = new Uint8Array(length + protoid.length)
    secret_input.set(exp_share, offset=off); off += exp_share.length
    secret_input.set(exp_onion, offset=off); off += exp_onion.length
    secret_input.set(identity, offset=off); off += identity.length
    secret_input.set(onionkey, offset=off); off += onionkey.length
    secret_input.set(client_pubkey, offset=off); off += client_pubkey.length
    secret_input.set(server_pubkey, offset=off); off += server_pubkey.length
    secret_input.set(protoid, offset=off)
    var verify = lighttor.ntor.hash.verify.encrypt(secret_input)

    var server = nacl.util.decodeUTF8(lighttor.ntor.tweaks['server'])
    var length = verify.length + identity.length + onionkey.length * 3
    var off = 0

    var auth_input = new Uint8Array(length + server.length)
    auth_input.set(verify, offset=off); off += verify.length
    auth_input.set(identity, offset=off); off += identity.length
    auth_input.set(onionkey, offset=off); off += onionkey.length
    auth_input.set(server_pubkey, offset=off); off += server_pubkey.length
    auth_input.set(client_pubkey, offset=off); off += client_pubkey.length
    auth_input.set(server, offset=off)
    var client_auth = lighttor.ntor.hash.mac.encrypt(auth_input)

    var valid = true
    length = client_auth.length
    for (var i = 0; i < length; i++)
    {
        if (client_auth[i] != server_auth[i])
            valid = false
    }

    zero_onion = 0
    zero_share = 0
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
    k = 16 // KEY_LEN
    h = 20 // HASH_LEN
    var material = {
        key_hash: material.slice(h * 2 + k * 2),
        forward_digest: material.slice(0, h),
        backward_digest: material.slice(h, h * 2),
        forward_key: material.slice(h * 2, h * 2 + k),
        backward_key: material.slice(h * 2 + k, h * 2 + k * 2)
    }
    return material
}

lighttor.relay = {}
lighttor.relay.payload_len = 509
lighttor.relay.full_len = 5 + lighttor.relay.payload_len
lighttor.relay.cmd = {
        'begin'     : 1,   1: 'begin',
        'data'      : 2,   2: 'data',
        'end'       : 3,   3: 'end',
        'connected' : 4,   4: 'connected',
        'sendme'    : 5,   5: 'sendme',
        'extend'    : 6,   6: 'extend',
        'extended'  : 7,   7: 'extended',
        'truncate'  : 8,   8: 'truncate',
        'truncated' : 9,   9: 'truncated',
        'drop'      : 10, 10: 'drop',
        'resolve'   : 11, 11: 'resolve',
        'resolved'  : 12, 12: 'resolved',
        'begin_dir' : 13, 13: 'begin_dir',
        'extend2'   : 14, 14: 'extend2',
        'extended2' : 15, 15: 'extended2'
    }

lighttor.relay.pack = function(cmd, stream_id, data)
{
    if (data === undefined)
        data = new Uint8Array(0)
    if (stream_id === undefined)
        stream_id = 0

    if (typeof(data) == "string")
        data = nacl.util.decodeUTF8(data)

    var cell = new Uint8Array(lighttor.relay.full_len) /* padded with \x00 */
    var view = new DataView(cell.buffer)

    view.setUint32(0, 2147483648 /* fake circuit_id */, false)
    view.setUint8(4, 3 /* RELAY CELL */, false)
    view.setUint8(5, lighttor.relay.cmd[cmd], false)
    view.setUint16(6, 0 /* recognized */, false)
    view.setUint16(8, stream_id, false)
    // (implicit 4-bytes zeroed digest at offset 10)
    view.setUint16(14, data.length, false)
    cell.set(data, offset=16)

    return cell
}

lighttor.onion = {}
lighttor.onion.ctr = function(key)
{
    var key = sjcl.codec.bytes.toBits(key)
    var aes = new sjcl.cipher.aes(key)

    var ctr = {
        prf: aes,
        nonce: 0,
        buffer: new Uint8Array(0),
        extend: function(n)
        {
            var length = (Math.floor(n / 16) + 1) * 16
            var remains = this.buffer
            this.buffer = new Uint8Array(length+remains.length)
            this.buffer.set(remains, offset=0)

            for (var idx = remains.length; idx < length; idx += 16)
            {
                var nonce = new Uint8Array(16)
                new DataView(nonce.buffer).setUint32(12, this.nonce, false)
                nonce = sjcl.codec.bytes.toBits(nonce)

                var pad = this.prf.encrypt(nonce)
                pad = new Uint8Array(sjcl.codec.bytes.fromBits(pad))

                this.buffer.set(pad, offset=idx)
                this.nonce = this.nonce + 1
            }
        },
        process: function(data)
        {
            if (data.length > this.buffer.length)
                this.extend(data.length)

            var data = data.slice(0)
            for (var idx = 0; idx < data.length; idx++)
            {
                data[idx] ^= this.buffer[idx]
            }
            this.buffer = this.buffer.slice(data.length)

            return data
        }
    }
    return ctr
}

lighttor.onion.sha = function(digest)
{
    var digest = sjcl.codec.bytes.toBits(digest)

    var sha = {
        hash: new sjcl.hash.sha1(),
        digest: function(data)
        {
            this.hash.update(sjcl.codec.bytes.toBits(data))
            data = new sjcl.hash.sha1(this.hash).finalize()
            return new Uint8Array(sjcl.codec.bytes.fromBits(data))
        }
    }

    sha.hash.update(digest)
    return sha
}

lighttor.onion.forward = function(endpoint)
{
    var forward = {
        iv: 0,
        ctr: lighttor.onion.ctr(endpoint.material.forward_key),
        sha: lighttor.onion.sha(endpoint.material.forward_digest),
        early: 8, // (first 8 relay cells will be replaced by relay_early)
        encrypt: function(cell)
        {
            if ((cell.length) != lighttor.relay.full_len)
                console.log('Invalid size for cell, fatal.')

            body = cell.slice(5)
            cell.set(this.ctr.process(body), offset=5)

            if (this.early > 0 && cell[4] == 3 /* relay */)
            {
                this.early = this.early - 1
                cell[4] = 9 /* relay_early */
            }
            return cell
        },
        digest: function(cell)
        {
            if ((cell.length) != lighttor.relay.full_len)
                console.log('Invalid size for cell, fatal.')

            body = cell.slice(5)
            body.set(new Uint8Array(4), offset=5)
            return this.sha.digest(body).slice(0, 4)
        }
    }
    return forward
}

lighttor.onion.backward = function(endpoint)
{
    var backward = {
        iv: 0,
        ctr: lighttor.onion.ctr(endpoint.material.backward_key),
        sha: lighttor.onion.sha(endpoint.material.backward_digest),
        decrypt: function(cell)
        {
            if ((cell.length) != lighttor.relay.full_len)
                console.log('Invalid size for cell, fatal.')

            body = cell.slice(5)
            cell.set(this.ctr.process(body), offset=5)
            return cell
        },
        digest: function(cell)
        {
            if ((cell.length) != lighttor.relay.full_len)
                console.log('Invalid size for cell, fatal.')

            body = cell.slice(5)
            body.set(new Uint8Array(4), offset=5)
            return this.sha.digest(body).slice(0, 4)
        }
    }
    return backward
}

lighttor.onion.build = function(endpoint, cmd, stream_id, data)
{
    var cell = lighttor.relay.pack(cmd, stream_id, data)
    cell.set(endpoint.forward.digest(cell), offset=10)
    return endpoint.forward.encrypt(cell)
}

lighttor.onion.peel = function(endpoint, cell)
{
    var cell = endpoint.backward.decrypt(cell)
    var digest = cell.slice(10, 14)
    cell.set(new Uint8Array(4), 10)

    var expect = endpoint.backward.digest(cell)
    if (!(true
        && digest[0] == expect[0]
        && digest[1] == expect[1]
        && digest[2] == expect[2]
        && digest[3] == expect[3]))
    {
        console.log('Invalid cell digest.')
        return null
    }

    var recognized = cell.slice(6, 8)
    if (!(recognized[0] == recognized[1] && recognized[0] == 0))
    {
        console.log('Invalid cell recognized field.')
        return null
    }

    var length = new DataView(cell.slice(14, 16).buffer).getUint16(0, false)
    if (length > lighttor.relay.payload_len - 11)
    {
        console.log('Invalid cell length.')
        return null
    }

    var id = new DataView(cell.slice(8, 10).buffer).getUint16(0, false)
    var cmd = lighttor.relay.cmd[cell.slice(5, 6)[0]]
    var data = cell.slice(16, 16 + length)
    var relay = {cmd: cmd, stream_id: id, data: data}
    return relay
}

lighttor.io = {}
lighttor.io.simple = function(handler, success, error)
{
    var io = {
        incoming: [],
        outcoming: [],
        pending: 0,
        handler: handler,
        success: success,
        error: error,
        send: function(cell)
        {
            this.outcoming.push(nacl.util.encodeBase64(cell))
        },
        recv: function()
        {
            if (this.incoming.length < 1)
                return null

            cell = this.incoming[0]
            this.incoming = this.incoming.slice(1)
            return nacl.util.decodeBase64(cell)
        }
    }
    return io
}

lighttor.io.polling = function(endpoint, handler, success, error)
{
    var io = lighttor.io.simple(handler, success, error)
    io.poll = function()
    {
        setTimeout(function()
        {
            lighttor.post.channel(endpoint, io.poll)
        }, 1000)
    }
    io.start = function()
    {
        lighttor.post.channel(endpoint, io.poll)
    }
    endpoint.io = io
    return io
}

lighttor.post = {}
lighttor.post.create = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 201)
        {
            var info = JSON.parse(this.responseText)
            endpoint.id = info['id']
            endpoint.url = endpoint.urls.channels + '/' + info['id']
            endpoint.path = info['path']

            var material = lighttor.ntor.shake(endpoint, info['ntor'])
            material = lighttor.ntor.slice(material)
            endpoint.material = material

            endpoint.forward = lighttor.onion.forward(endpoint)
            endpoint.backward = lighttor.onion.backward(endpoint)
            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4 && error !== undefined)
        {
            error(endpoint, this.status)
        }
    }

    payload = lighttor.ntor.hand(endpoint)
    payload = JSON.stringify({ntor: payload})

    rq.open('POST', endpoint.urls.channels, true)
    rq.setRequestHeader("Content-type", "application/json");
    rq.send(JSON.stringify({ntor: lighttor.ntor.hand(endpoint)}))
}

lighttor.post.channel = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 201)
        {
            var cells = JSON.parse(this.responseText)['cells']
            if (cells === undefined)
            {
                if (endpoint.io.error !== undefined)
                    endpoint.io.error(endpoint)
                return
            }

            var pending = endpoint.io.pending
            if (pending > 0 && endpoint.io.success !== undefined)
                endpoint.io.success(endpoint)

            if (cells.length > 0)
            {
                endpoint.io.incoming = endpoint.io.incoming.concat(cells)
                if (endpoint.io.handler !== undefined)
                    endpoint.io.handler(endpoint)
            }

            endpoint.io.outcoming = endpoint.io.outcoming.slice(pending)
            endpoint.io.pending = 0

            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4)
        {
            if (endpoint.io.error !== undefined)
                endpoint.io.error(endpoint)

            if (error !== undefined)
                error(endpoint, this.status)
        }
    }

    endpoint.io.pending = endpoint.io.outcoming.length

    rq.open('POST', endpoint.url, true)
    rq.setRequestHeader("Content-type", "application/json");
    rq.send(JSON.stringify({cells: endpoint.io.outcoming}))
}
