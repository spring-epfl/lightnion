lighttor.io = {}
lighttor.io.polling = function(endpoint, handler, success, error)
{
    var io = {
        incoming: [],
        outcoming: [],
        pending: 0,
        handler: handler,
        success: success,
        error: error,
        cell: null,
        poll: function()
        {
            setTimeout(function()
            {
                lighttor.post.channel(endpoint, io.poll)
            }, 100)
        },
        send: function(cell)
        {
            io.outcoming.push(lighttor.enc.base64(cell))
        },
        recv: function()
        {
            if (io.incoming.length < 1)
                return undefined

            io.cell = io.incoming.shift()
            return lighttor.dec.base64(io.cell)
        },
        start: function()
        {
            lighttor.post.channel(endpoint, io.poll)
        }
    }
    endpoint.io = io
    return io
}

lighttor.io.socket = function(endpoint, handler, success, error)
{
    if (handler === undefined)
        handler = function(endpoint) { }
    if (success === undefined)
        success = function(endpoint) { }
    if (error === undefined)
        error = function(endpoint) { }

    var io = {
        event: null,
        socket: null,
        closed: false,
        incoming: [],
        outcoming: [],
        handler: handler,
        success: success,
        error: error,
        cell: null,
        send: function(cell)
        {
            io.outcoming.push(cell)
        },
        recv: function()
        {
            if (io.incoming.length < 1)
                return undefined

            io.cell = io.incoming.shift()
            return io.cell
        },
        start: function() { }
    }
    var socket = new WebSocket(endpoint.urls.socket + "/" + endpoint.id)

    socket.binaryType = "arraybuffer"
    socket.onopen = function(event)
    {
        io.event = event
        io.success(endpoint)

        while (io.outcoming.length > 0)
            io.socket.send(io.outcoming.shift())

        io.send = function(cell)
        {
            if (io.closed)
                throw "Unable to send, connection closed."
            io.socket.send(cell.buffer)
        }
    }
    socket.onerror = function(event)
    {
        io.event = event
        io.error(endpoint)
    }
    socket.onmessage = function(event)
    {
        io.event = event
        io.incoming.push(new Uint8Array(event.data))
        io.handler(endpoint)
    }
    socket.onclose = function(event)
    {
        io.event = event
        io.closed = true
        io.error(endpoint)
    }

    endpoint.io = io
    endpoint.io.socket = socket
    return io
}
