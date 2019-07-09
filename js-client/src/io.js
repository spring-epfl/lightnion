lnn.io = {}
lnn.io.polling = function(endpoint, handler, success, error)
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
                lnn.post.channel(endpoint, io.poll)
            }, 100)
        },
        send: function(cell)
        {
            io.outcoming.push(lnn.enc.base64(cell))
        },
        recv: function()
        {
            if (io.incoming.length < 1)
                return undefined

            io.cell = io.incoming.shift()
            return lnn.dec.base64(io.cell)
        },
        start: function()
        {
            lnn.post.channel(endpoint, io.poll)
        }
    }
    endpoint.io = io
    return io
}

lnn.io.socket = function(endpoint, handler, success, error)
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
	cell_recv: 0,
	//cell_sent: 0,
        send: function(cell)
        {
            io.outcoming.push(cell)

            //io.cell_sent += 1
            //var cell_repr = Array.from(cell.slice(0,20)).map(function(x) {return x.toString(16).padStart(2, '0')}).join('')
            //console.log("cell ", io.cell_sent.toString(), " sent to wbskt ", cell_repr)
        },
        recv: function()
        {
            if (io.incoming.length < 1)
                return undefined

            io.cell = io.incoming.shift()

            io.cell_recv += 1
            var cell_repr = Array.from(io.cell.slice(0,20)).map(function(x) {return x.toString(16).padStart(2, '0')}).join('')
            console.log("cell recv by wbskt ", cell_repr)

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

            //io.cell_sent += 1
            //var cell_repr = Array.from(cell.slice(0,20)).map(function(x) {return x.toString(16).padStart(2, '0')}).join('')
            //console.log("cell ", io.cell_sent.toString(), " sent to wbskt ", cell_repr)
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

	var data = new Uint8Array(event.data)

	var cell_repr = Array.from(data.slice(0,20)).map(function(x) {return x.toString(16).padStart(2, '0')}).join('')
	console.log("cell recv by wbskt ", cell_repr)

        // io.incoming.push(data)
	io.cell = data
        io.handler(endpoint, data)
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
