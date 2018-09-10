lnn.fast = function(host, port, success, error, io)
{
    return lnn.open(host, port, success, error, io, true)
}

lnn.auth = function(host, port, suffix, success, error, io)
{
    if (typeof(suffix) == "string")
    {
        suffix = suffix.replace(/-/g, "+").replace(/_/g, "/")
        suffix = lnn.dec.base64(suffix)
    }
    if (lnn.enc.utf8(suffix.slice(0, 5)) != "auth ")
        throw "Invalid prefix in auth. suffix!"

    suffix = suffix.slice(5)
    if (suffix.length != 20 + 32)
        throw "Invalid auth. suffix length!"

    return lnn.open(host, port, success, error, io, true, {
        identity: suffix.slice(0, 20),
        onionkey: suffix.slice(20),
        ntor: nacl.box.keyPair()})
}

lnn.open = function(host, port, success, error, io, fast, auth)
{
    var endpoint = lnn.endpoint(host, port)
    if (io === undefined)
        io = lnn.io.socket
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
            endpoint.state = lnn.state.guarded
            success(endpoint)

            lnn.post.create(endpoint, cb.create, error)
        },
        create: function(endpoint)
        {
            endpoint.state = lnn.state.created
            success(endpoint)

            endpoint.stream = lnn.stream.backend(error)
            io(endpoint, lnn.stream.handler, function(endpoint)
            {
                var state = endpoint.state

                endpoint.state = lnn.state.pending
                success(endpoint)
                endpoint.state = state
            }, error)

            lnn.post.extend(endpoint, endpoint.path[0], cb.extend, error)
            endpoint.io.start()
        },
        extend: function(endpoint)
        {
            endpoint.state = lnn.state.extpath
            success(endpoint)

            lnn.post.extend(endpoint, endpoint.path[1], cb.success, error)
        },
        success: function(endpoint)
        {
            endpoint.state = lnn.state.success
            success(endpoint)
            endpoint.io.success = function() { }
        }
    }

    endpoint.state = lnn.state.started
    success(endpoint)

    // fast channel: one-request channel creation (no guard pinning)
    if (endpoint.fast)
        lnn.post.create(endpoint, cb.create, error)
    else
        lnn.get.guard(endpoint, cb.guard, error)

    return endpoint
}
