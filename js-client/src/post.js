lnn.post = {}
lnn.post.create = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 201)
        {
            var info = JSON.parse(rq.responseText)
            if (endpoint.auth != null)
            {
                info = lnn.ntor.auth(endpoint, info["auth"], info["data"])
            }
            endpoint.id = info["id"]
            endpoint.url = endpoint.urls.channels + "/" + info["id"]
            endpoint.path = info["path"]

            if (endpoint.fast)
            {
                endpoint.guard = info["guard"]
                endpoint.material.identity = lnn.dec.base64(
                    info["guard"].router.identity + "=")
                endpoint.material.onionkey = lnn.dec.base64(
                    info["guard"]["ntor-onion-key"])
            }

            var material = lnn.ntor.shake(endpoint, info["ntor"])
            if (material == null)
                throw "Invalid guard handshake."

            material = lnn.ntor.slice(material)
            endpoint.material = material

            endpoint.forward = lnn.onion.forward(endpoint)
            endpoint.backward = lnn.onion.backward(endpoint)
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
        payload = lnn.ntor.fast(endpoint)
    else
        payload = lnn.ntor.hand(endpoint)

    payload = {ntor: payload}
    if (endpoint.auth != null)
    {
        payload["auth"] = lnn.enc.base64(endpoint.auth.ntor.publicKey)
    }
    payload = JSON.stringify(payload)

    rq.open("POST", endpoint.urls.channels, true)
    rq.setRequestHeader("Content-type", "application/json")
    rq.send(payload)
}


lnn.post.circuit_info = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 201)
        {
            var info = JSON.parse(rq.responseText)
            if (endpoint.auth != null)
            {
                info = lnn.ntor.auth(endpoint, info["auth"], info["data"])
            }

            endpoint.id = info["id"]
            endpoint.url = endpoint.urls.channels + "/" + info["id"]
            endpoint.path = info["path"]

            if (endpoint.fast)
            {
                endpoint.guard = info["guard"]
            }
            if (success !== undefined)
                success(endpoint, info)
        }
        else if (rq.readyState == 4 && error !== undefined)
        {
            error(endpoint, rq.status)
        }
    }

    var payload = {}
    /**
    if (endpoint.fast)
        payload = lnn.ntor.fast(endpoint)
    else
        payload = lnn.ntor.hand(endpoint)

    payload = {ntor: payload}*/
    if (endpoint.auth != null)
    {
        payload["auth"] = lnn.enc.base64(endpoint.auth.ntor.publicKey)
    }
    payload = JSON.stringify(payload)

    rq.open("POST", endpoint.urls.channels, true)
    rq.setRequestHeader("Content-type", "application/json")
    rq.send(payload)
}

lnn.post.handshake = function(endpoint, info, success, error)
{
    //var handshake = info['handshake']
    var normal_handler = endpoint.io.handler

    var handler = function(endpoint, material)
    {
        endpoint.io.handler = normal_handler
        //var material = endpoint.io.recv()

        material = lnn.ntor.shake(endpoint, material.slice(7, 7+64), false)

        if (material == null)
            throw "Invalid guard handshake."


        material = lnn.ntor.slice(material)
        endpoint.material = material

        endpoint.forward = lnn.onion.forward(endpoint)
        endpoint.backward = lnn.onion.backward(endpoint)

        if (success !== undefined)
            success(endpoint)
    }

    endpoint.io.handler = handler
    //console.log(lnn.dec.base64(handshake))
    var handshake = new Uint8Array(lnn.relay.full_len)
    var payload = lnn.ntor.hand(endpoint,endpoint.guard,false)


    var view = new DataView(handshake.buffer)
    view.setUint32(0, 2147483648 /* fake circuit_id */, false)
    view.setUint8(4, 10 /* CREATE2 CELL */, false)
    view.setUint16(5, 2 /* ntor handshake */, false)
    view.setUint16(7, payload.length, false)
    handshake.set(payload,9)

    console.log(handshake)

    endpoint.io.send(handshake)
}

lnn.post.channel = function(endpoint, success, error)
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

lnn.post.extend = function(endpoint, descriptor, success, error)
{
    var hand = lnn.ntor.hand(endpoint, descriptor, false)

    var eidentity = descriptor["identity"]["master-key"] // (assuming ed25519)
    var identity = endpoint.material.identity
    var addr = descriptor["router"]["address"]
    var port = descriptor["router"]["orport"]

    var data = lnn.relay.extend(hand, addr, port, identity, eidentity)
    var cell = lnn.onion.build(endpoint, "extend2", 0, data)

    var extend_error = error
    var extend_success = success
    var normal_handler = endpoint.io.handler

    var handler = function(endpoint, data)
    {
        endpoint.io.handler = normal_handler

        var cell = lnn.onion.peel(endpoint, data)
        if (cell == null || cell.cmd != "extended2")
        {
            if (extend_error !== undefined)
                return extend_error(endpoint)
            throw "Invalid answer, expecting extended2 cell, fatal!"
        }

        var view = new DataView(cell.data.buffer)
        var length = view.getUint16(0, false)
        var data = cell.data.slice(2, 2+length)

        var material = lnn.ntor.shake(endpoint, data, false)
        material = lnn.ntor.slice(material)
        endpoint.material = material

        if (material == null && extend_error !== undefined)
            return extend_error(endpoint)

        endpoint.forward = lnn.onion.forward(endpoint)
        endpoint.backward = lnn.onion.backward(endpoint)

        if (extend_success !== undefined)
            extend_success(endpoint)
    }

    endpoint.io.handler = handler
    endpoint.io.send(cell)
}


lnn.post.close = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 202)
        {
            if (success !== undefined)
                success("Circuit closed")
        }
        else if (rq.readyState == 4 && error !== undefined)
        {
            error("Error in closing circuit")
        }
    }

    rq.open("DELETE", endpoint.url, true)
    rq.send()
}

