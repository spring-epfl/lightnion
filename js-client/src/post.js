lighttor.post = {}
lighttor.post.create = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 201)
        {
            var info = JSON.parse(rq.responseText)
            if (endpoint.auth != null)
            {
                info = lighttor.ntor.auth(endpoint, info["auth"], info["data"])
            }

            endpoint.id = info["id"]
            endpoint.url = endpoint.urls.channels + "/" + info["id"]
            endpoint.path = info["path"]

            if (endpoint.fast)
            {
                endpoint.guard = info["guard"]
                endpoint.material.identity = lighttor.dec.base64(
                    info["guard"].router.identity + "=")
                endpoint.material.onionkey = lighttor.dec.base64(
                    info["guard"]["ntor-onion-key"])
            }

            var material = lighttor.ntor.shake(endpoint, info["ntor"])
            if (material == null)
                throw "Invalid guard handshake."

            material = lighttor.ntor.slice(material)
            endpoint.material = material

            endpoint.forward = lighttor.onion.forward(endpoint)
            endpoint.backward = lighttor.onion.backward(endpoint)
            if (success !== undefined)
                success(endpoint)
        }
        else if (rq.readyState == 4 && error !== undefined)
        {
            error(endpoint, rq.status)
        }
    }

    var payload = null
    if (endpoint.fast)
        payload = lighttor.ntor.fast(endpoint)
    else
        payload = lighttor.ntor.hand(endpoint)

    payload = {ntor: payload}
    if (endpoint.auth != null)
    {
        payload["auth"] = lighttor.enc.base64(endpoint.auth.ntor.publicKey)
    }
    payload = JSON.stringify(payload)

    rq.open("POST", endpoint.urls.channels, true)
    rq.setRequestHeader("Content-type", "application/json")
    rq.send(payload)
}

lighttor.post.channel = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 201)
        {
            var cells = JSON.parse(rq.responseText)["cells"]
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
        else if (rq.readyState == 4)
        {
            if (endpoint.io.error !== undefined)
                endpoint.io.error(endpoint)

            if (error !== undefined)
                error(endpoint, rq.status)
        }
    }

    endpoint.io.pending = endpoint.io.outcoming.length

    rq.open("POST", endpoint.url, true)
    rq.setRequestHeader("Content-type", "application/json")
    rq.send(JSON.stringify({cells: endpoint.io.outcoming}))
}

lighttor.post.extend = function(endpoint, descriptor, success, error)
{
    var hand = lighttor.ntor.hand(endpoint, descriptor, false)

    var eidentity = descriptor["identity"]["master-key"] // (assuming ed25519)
    var identity = endpoint.material.identity
    var addr = descriptor["router"]["address"]
    var port = descriptor["router"]["orport"]

    var data = lighttor.relay.extend(hand, addr, port, identity, eidentity)
    var cell = lighttor.onion.build(endpoint, "extend2", 0, data)

    var extend_error = error
    var extend_success = success
    var normal_handler = endpoint.io.handler

    var handler = function(endpoint)
    {
        endpoint.io.handler = normal_handler

        var cell = lighttor.onion.peel(endpoint, endpoint.io.recv())
        if (cell == null || cell.cmd != "extended2")
        {
            throw "Invalid answer, expecting extended2 cell, fatal!"
            if (extend_error !== undefined)
                return extend_error(endpoint)
        }

        var view = new DataView(cell.data.buffer)
        var length = view.getUint16(0, false)
        var data = cell.data.slice(2, 2+length)

        var material = lighttor.ntor.shake(endpoint, data, false)
        material = lighttor.ntor.slice(material)
        endpoint.material = material

        if (material == null && extend_error !== undefined)
            return extend_error(endpoint)

        endpoint.forward = lighttor.onion.forward(endpoint)
        endpoint.backward = lighttor.onion.backward(endpoint)

        if (extend_success !== undefined)
            extend_success(endpoint)
    }

    endpoint.io.handler = handler
    endpoint.io.send(cell)
}
