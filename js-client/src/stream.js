lnn.stream = {}
lnn.stream.entrancy = 0
lnn.stream.backend = function(error)
{
    var sendme = function(cell, endpoint)
    {
        if (cell.cmd == "sendme"){
            endpoint.stream.sendme += 1
            endpoint.stream.deliverywindow += 100
            //flush the send queue for the circuit

            while(endpoint.stream.deliverywindow > 0 && endpoint.stream.tosend.length > 0) {
                var cell = endpoint.stream.tosend.shift()
                endpoint.io.send(cell)
                endpoint.stream.deliverywindow -= 1
            }
        }
        else
        {
            error(endpoint)
            throw "Got unexpected control cell."
        }
    }

    var backend = {
        id: 0,
        tosend: [],
        sendme: 0,
        handles: {0: {callback: sendme}},
        packagewindow: 1000, // (circuit-level receiving window)
        deliverywindow: 1000,// circuit level sending window
        register: function(handle)
        {
            backend.id += 1
            handle.id = backend.id
            handle.packagewindow = 500 // (stream-level receiving window)
            handle.deliverywindow = 500// stream level sending window
            backend.handles[backend.id] = handle
            return backend.id
        },
        send: function(cell, endpoint)
        {
            if(backend.deliverywindow > 0) { //if we can send
                endpoint.io.send(cell)
                backend.deliverywindow -= 1 
            }
            else { ///add to the send queue, will be sent when "sendme" is received. 
                backend.tosend.push(cell)
            }
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
        endpoint.stream.packagewindow -= 1
    }
    console.log('Update window: ', endpoint.stream.packagewindow)
    if (endpoint.stream.packagewindow < 900)
    {
    	//console.log("Circuit window is ", endpoint.stream.packagewindow)
    	//console.log("Sending circuit level sendme cell now ", endpoint.io.counter)
    	endpoint.io.send(lnn.onion.build(endpoint, 'sendme'))
    	endpoint.stream.packagewindow += 100
    }

    /* handle stream-level sendme */
    if(cell.cmd == "data"){
        handle.packagewindow -= 1
    }
    if (handle.packagewindow < 450)
    {
        //console.log("Stream window is ", handle.packagewindow)
        //console.log("Sending stream level sendme cell now ", endpoint.io.counter)
        cell = lnn.onion.build(endpoint, 'sendme', handle.id)
        endpoint.io.send(cell)
        handle.packagewindow += 50
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

            if(cmd != "data") {
                endpoint.io.send(cell) //non-data cells dont affect congestion control
                return
            }

            if(request.deliverywindow > 0) { //send if stream level window is non zero
                endpoint.stream.send(cell,endpoint) //send thru circuit level window.
                request.deliverywindow -= 1 
            }
            else {
                request.tosend.push(cell) //add to queue of stream level window
            }
        },
        recv: function()
        {
            var data = request.data
            request.data = []
            return data
        },
        state: lnn.state.started,
        packagewindow: null,
        deliverywindow: null,
        tosend: [],
        endpoint: endpoint,
        callback: function(cell)
        {
            if (cell.cmd == "connected")
                request.state = lnn.state.created
            if (cell.cmd == "end")
                request.state = lnn.state.success

            if(cell.cmd == "sendme") { //receive stream level sendme
                request.deliverywindow += 50
                while(request.deliverywindow > 0 && request.tosend.length > 0) {
                    var cell = request.tosend.shift()
                    endpoint.stream.send(cell,endpoint)
                    request.deliverywindow -= 1
                }
            }

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
        packagewindow: null,
        deliverywindow: null,
        tosend: [],
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
            if(cell.cmd == "sendme") {
                request.deliverywindow += 50
                while(request.deliverywindow > 0 && request.tosend.length > 0) {
                    var cell = request.tosend.shift()
                    endpoint.stream.send(cell,endpoint)
                    request.deliverywindow -= 1
                }
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
    request.deliverywindow -= 1
    endpoint.stream.send(cell,endpoint)

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

                if(request.deliverywindow > 0) {
                    endpoint.stream.send(cell,endpoint)
                    request.deliverywindow -= 1 
                }
                else {
                    request.tosend.push(cell)
                }

            }
            var cell = lnn.onion.build(
                    request.endpoint, "data", request.id, data)

            if(request.deliverywindow > 0) {
                endpoint.stream.send(cell,endpoint)
                request.deliverywindow -= 1 
            }
            else {
                request.tosend.push(cell)
            }

        },
        recv: function()
        {
            var data = request.data
            request.data = new Uint8Array(0)
            return data
        },
        state: lnn.state.started,
        packagewindow: null,
        deliverywindow: null,
        tosend: [],
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
            if(cell.cmd == "sendme") {

                request.deliverywindow += 50
                while(request.deliverywindow > 0 && request.tosend.length > 0) {
                    var cell = request.tosend.shift()
                    endpoint.stream.send(cell,endpoint)
                    request.deliverywindow -= 1
                }
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
