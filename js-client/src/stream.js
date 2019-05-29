lnn.stream = {}
lnn.stream.entrancy = 0
lnn.stream.backend = function(error)
{
    var sendme = function(cell, endpoint)
    {
        if (cell.cmd == "sendme")
            endpoint.stream.sendme += 1
        else
        {
            error(endpoint)
            throw "Got unexpected control cell."
        }
    }

    var backend = {
        id: 0,
        sendme: 0,
        handles: {0: {callback: sendme}},
        smwindow: 1000, // (sendme circuit-level window)
        register: function(handle)
        {
            backend.id += 1
            handle.id = backend.id
            handle.smwindow = 500 // (sendme stream-level window)
            backend.handles[backend.id] = handle
            return backend.id
        }
    }
    return backend
}

lnn.stream.handler = function(endpoint, cell)
{
    lnn.stream.entrancy += 1
    if(lnn.stream.entrancy > 1) {
	console.log("ENTRANCY BUG")
    }

    if (cell[4] != 3) // (relay cell only)
    {
	console.log("Got non-relay cell, dropped: ", cell[4])
	lnn.stream.entrancy -= 1
	return
    }

    cell = lnn.onion.peel(endpoint, cell)
    if (cell == null)
    {
	console.log("Got invalid cell, dropped.")
	lnn.stream.entrancy -= 1
	return
    }

    if (!(cell.stream_id in endpoint.stream.handles))
    {
	console.log("Got cell outside stream, dropped: ", cell.stream_id)
	lnn.stream.entrancy -= 1
	return
    }

    var handle = endpoint.stream.handles[cell.stream_id]
    if (cell.cmd == "end")
	delete endpoint.stream.handles[cell.stream_id]

    handle.cell = cell
    handle.callback(cell, endpoint)

    /* handle circuit-level sendme */


    if(cell.cmd == "data") {
        endpoint.stream.smwindow -= 1
    }
    console.log('Update window: ', endpoint.stream.smwindow)
    if (endpoint.stream.smwindow < 900)
    {
	//console.log("Circuit window is ", endpoint.stream.smwindow)
	//console.log("Sending circuit level sendme cell now ", endpoint.io.counter)
	endpoint.io.send(lnn.onion.build(endpoint, 'sendme'))
	endpoint.stream.smwindow += 100
    }

    /* handle stream-level sendme */
    if(cell.cmd == "data"){
        handle.smwindow -= 1
    }
    if (handle.smwindow < 450)
    {
	//console.log("Stream window is ", handle.smwindow)
	//console.log("Sending stream level sendme cell now ", endpoint.io.counter)
	cell = lnn.onion.build(endpoint, 'sendme', handle.id)
	endpoint.io.send(cell)
	handle.smwindow += 50
    }

    lnn.stream.entrancy -= 1
}

lnn.stream.raw = function(endpoint, handler)
{
    var request = {
        id: null,
        data: [],
        cell: null,
        send: function(cmd, data)
        {
            var cell = lnn.onion.build(
                request.endpoint, cmd, request.id, data)
            endpoint.io.send(cell)
        },
        recv: function()
        {
            var data = request.data
            request.data = []
            return data
        },
        state: lnn.state.started,
        smwindow: null,
        endpoint: endpoint,
        callback: function(cell)
        {
            if (cell.cmd == "connected")
                request.state = lnn.state.created
            if (cell.cmd == "end")
                request.state = lnn.state.success

            request.data.push(cell)
            handler(request)

            if (cell.cmd == "connected")
                request.state = lnn.state.pending
        }
    }

    var id = endpoint.stream.register(request)
    handler(request)
    return request
}

lnn.stream.dir = function(endpoint, path, handler)
{
    var request = {
        id: null,
        data: "",
        cell: null,
        send: function() { throw "No send method on directory streams." },
        recv: function()
        {
            var data = request.data
            request.data = ""
            return data
        },
        state: lnn.state.started,
        smwindow: null,
        endpoint: endpoint,
        callback: function(cell)
        {
            if (cell.cmd == "connected")
            {
                request.state = lnn.state.created
                handler(request)
                request.state = lnn.state.pending
            }
            if (cell.cmd == "end")
            {
                request.state = lnn.state.success
                handler(request)
            }
            if (cell.cmd != "data")
                return

            request.data += lnn.enc.utf8(cell.data)
            handler(request)
        }
    }

    var id = endpoint.stream.register(request)
    var cell = lnn.onion.build(endpoint, "begin_dir", id)
    endpoint.io.send(cell)

    var data = "GET " + path + " HTTP/1.0\r\n"
    data += "Accept-Encoding: identity\r\n\r\n"
    data = lnn.dec.utf8(data)

    cell = lnn.onion.build(endpoint, "data", id, data)
    endpoint.io.send(cell)

    handler(request)
    return request
}

lnn.stream.tcp = function(endpoint, host, port, handler)
{
    var request = {
        id: null,
        data: new Uint8Array(0),
        cell: null,
        send: function(data)
        {
            if (typeof(data) == "string")
                data = lnn.dec.utf8(data)

            var payload = new Uint8Array(lnn.relay.data_len)
            while (data.length > payload.length)
            {
                payload.set(data.slice(0, payload.length), 0)
                data = data.slice(payload.length)

                var cell = lnn.onion.build(
                    request.endpoint, "data", request.id, payload)
                endpoint.io.send(cell)
            }
            var cell = lnn.onion.build(
                    request.endpoint, "data", request.id, data)
            endpoint.io.send(cell)
        },
        recv: function()
        {
            var data = request.data
            request.data = new Uint8Array(0)
            return data
        },
        state: lnn.state.started,
        smwindow: null,
        endpoint: endpoint,
        callback: function(cell)
        {
            if (cell.cmd == "connected")
                request.state = lnn.state.created
            if (cell.cmd == "end")
                request.state = lnn.state.success
            if (cell.cmd == "data")
            {
                var data = request.data
                request.data = new Uint8Array(data.length + cell.data.length)
                request.data.set(data, 0)
                request.data.set(cell.data, data.length)
            }

            handler(request)
            if (cell.cmd == "connected")
                request.state = lnn.state.pending
        }
    }

    var id = endpoint.stream.register(request)

    var data = lnn.relay.begin(host, port)
    var cell = lnn.onion.build(endpoint, "begin", id, data)
    endpoint.io.send(cell)

    handler(request)
    return request
}
