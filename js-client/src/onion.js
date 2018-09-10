lnn.onion = {}
lnn.onion.ctr = function(key)
{
    var key = lnn.enc.bits(key)
    var aes = new sjcl.cipher.aes(key)

    var ctr = {
        prf: aes,
        nonce: 0,
        buffer: new Uint8Array(0),
        extend: function(n)
        {
            var length = (Math.floor(n / 16) + 1) * 16
            var remains = ctr.buffer
            ctr.buffer = new Uint8Array(length+remains.length)
            ctr.buffer.set(remains, 0)

            for (var idx = remains.length; idx < ctr.buffer.length; idx += 16)
            {
                var nonce = new Uint8Array(16)
                new DataView(nonce.buffer).setUint32(12, ctr.nonce, false)

                nonce = lnn.enc.bits(nonce)
                var pad = lnn.dec.bits(ctr.prf.encrypt(nonce))

                ctr.buffer.set(pad, idx)
                ctr.nonce = ctr.nonce + 1
            }
        },
        process: function(data)
        {
            if (data.length > ctr.buffer.length)
                ctr.extend(data.length)

            var data = data.slice(0)
            for (var idx = 0; idx < data.length; idx++)
            {
                data[idx] ^= ctr.buffer[idx]
            }
            ctr.buffer = ctr.buffer.slice(data.length)

            return data
        }
    }
    return ctr
}

lnn.onion.sha = function(digest)
{
    var digest = lnn.enc.bits(digest)

    var sha = {
        hash: new sjcl.hash.sha1(),
        digest: function(data)
        {
            sha.hash.update(lnn.enc.bits(data))
            data = new sjcl.hash.sha1(sha.hash).finalize()
            return lnn.dec.bits(data)
        }
    }

    sha.hash.update(digest)
    return sha
}

lnn.onion.forward = function(endpoint)
{
    var early = 8
    var layers = []
    if (endpoint.forward != null)
    {
        layers = endpoint.forward.layers
        layers.push(endpoint.forward)
        early = endpoint.forward.early
    }

    var forward = {
        iv: 0,
        ctr: lnn.onion.ctr(endpoint.material.forward_key),
        sha: lnn.onion.sha(endpoint.material.forward_digest),
        early: early, // (first 8 relay cells will be replaced by relay_early)
        layers: layers,
        encrypt: function(cell)
        {
            if ((cell.length) != lnn.relay.full_len)
                throw "Invalid size for cell, fatal."

            var body = cell.slice(5)
            for (var idx = 0; idx < forward.layers.length; idx++)
            {
                body.set(forward.layers[idx].ctr.process(body), 0)
            }
            cell.set(forward.ctr.process(body), 5)

            if (forward.early > 0 && cell[4] == 3 /* relay */)
            {
                forward.early = forward.early - 1
                cell[4] = 9 /* relay_early */
            }
            return cell
        },
        digest: function(cell)
        {
            if ((cell.length) != lnn.relay.full_len)
                throw "Invalid size for cell, fatal."

            var body = cell.slice(5)
            body.set(new Uint8Array(4), 5)
            return forward.sha.digest(body).slice(0, 4)
        }
    }
    return forward
}

lnn.onion.backward = function(endpoint)
{
    var layers = []
    if (endpoint.backward != null)
    {
        layers = endpoint.backward.layers
        layers.push(endpoint.backward)
    }

    var backward = {
        iv: 0,
        ctr: lnn.onion.ctr(endpoint.material.backward_key),
        sha: lnn.onion.sha(endpoint.material.backward_digest),
        layers: layers,
        decrypt: function(cell)
        {
            if ((cell.length) != lnn.relay.full_len)
                throw "Invalid size for cell, fatal."

            var body = cell.slice(5)
            for (var idx = 0; idx < backward.layers.length; idx++)
            {
                body.set(backward.layers[idx].ctr.process(body), 0)
            }
            cell.set(backward.ctr.process(body), 5)
            return cell
        },
        digest: function(cell)
        {
            if ((cell.length) != lnn.relay.full_len)
                throw "Invalid size for cell, fatal."

            var body = cell.slice(5)
            body.set(new Uint8Array(4), 5)
            return backward.sha.digest(body).slice(0, 4)
        }
    }
    return backward
}

lnn.onion.build = function(endpoint, cmd, stream_id, data)
{
    var cell = lnn.relay.pack(cmd, stream_id, data)
    cell.set(endpoint.forward.digest(cell), 10)
    return endpoint.forward.encrypt(cell)
}

lnn.onion.peel = function(endpoint, cell)
{
    var cell = endpoint.backward.decrypt(cell)
    var digest = cell.slice(10, 14)
    cell.set(new Uint8Array(4), 10)

    var recognized = cell.slice(6, 8)
    if (!(recognized[0] == recognized[1] && recognized[0] == 0))
    {
        throw "Invalid cell recognized field."
    }

    var expect = endpoint.backward.digest(cell)
    if (!(true
        && digest[0] == expect[0]
        && digest[1] == expect[1]
        && digest[2] == expect[2]
        && digest[3] == expect[3]))
    {
        throw "Invalid cell digest."
    }

    var length = new DataView(cell.slice(14, 16).buffer).getUint16(0, false)
    if (length > lnn.relay.data_len)
    {
        throw "Invalid cell data length."
    }

    var id = new DataView(cell.slice(8, 10).buffer).getUint16(0, false)
    var cmd = lnn.relay.cmd[cell.slice(5, 6)[0]]
    var data = cell.slice(16, 16 + length)
    var relay = {cmd: cmd, stream_id: id, data: data}
    return relay
}
