lighttor.fast = function(host, port, success, error, io)
{
    return lighttor.open(host, port, success, error, io, true)
}

lighttor.auth = function(host, port, suffix, success, error, io)
{
    if (typeof(suffix) == "string")
    {
        suffix = suffix.replace(/-/g, "+").replace(/_/g, "/")
        suffix = lighttor.dec.base64(suffix)
    }
    if (lighttor.enc.utf8(suffix.slice(0, 5)) != "auth ")
        throw "Invalid prefix in auth. suffix!"

    suffix = suffix.slice(5)
    if (suffix.length != 20 + 32)
        throw "Invalid auth. suffix length!"

    return lighttor.open(host, port, success, error, io, true, {
        identity: suffix.slice(0, 20),
        onionkey: suffix.slice(20),
        ntor: nacl.box.keyPair()})
}

lighttor.open = function(host, port, success, error, io, fast, auth)
{
    var endpoint = lighttor.endpoint(host, port)
    if (io === undefined)
        io = lighttor.io.socket
    if (fast === undefined)
        fast = false
    if (error === undefined)
        error = function() { }
    if (success === undefined)
        success = function() { }
    endpoint.fast = fast
    endpoint.auth = auth

    var cb = {
        guard: function(endpoint)
        {
            endpoint.state = lighttor.state.guarded
            success(endpoint)

            lighttor.post.create(endpoint, cb.create, error)
        },
        create: function(endpoint)
        {
            endpoint.state = lighttor.state.created
            success(endpoint)

            endpoint.stream = lighttor.stream.backend(error)
            io(endpoint, lighttor.stream.handler, function(endpoint)
            {
                var state = endpoint.state

                endpoint.state = lighttor.state.pending
                success(endpoint)
                endpoint.state = state
            }, error)

            lighttor.post.extend(endpoint, endpoint.path[0], cb.extend, error)
            endpoint.io.start()
        },
        extend: function(endpoint)
        {
            endpoint.state = lighttor.state.extpath
            success(endpoint)

            lighttor.post.extend(endpoint, endpoint.path[1], cb.success, error)
        },
        success: function(endpoint)
        {
            endpoint.state = lighttor.state.success
            success(endpoint)
            endpoint.io.success = function() { }
        }
    }

    endpoint.state = lighttor.state.started
    success(endpoint)

    // fast channel: one-request channel creation (no guard pinning)
    if (endpoint.fast)
        lighttor.post.create(endpoint, cb.create, error)
    else
        lighttor.get.guard(endpoint, cb.guard, error)

    return endpoint
}
