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

            lnn.post.create2(endpoint, cb.startWebSocket, error)
        },
	startWebSocket: function(endpoint, info) {
	    console.log('called startWebSocket cb')
            endpoint.stream = lnn.stream.backend(error)
            io(endpoint, lnn.stream.handler, function(endpoint)
            {
                var state = endpoint.state

                endpoint.state = lnn.state.pending
                success(endpoint)
                endpoint.state = state
            }, error)
            endpoint.io.start()

            lnn.post.handshake(endpoint, info, cb.create, error)
	},
        create: function(endpoint)
        {
	    console.log('called create cb')
            endpoint.state = lnn.state.created
            success(endpoint)

            lnn.post.extend(endpoint, endpoint.path[0], cb.extend, error)
        },
        extend: function(endpoint)
        {
	    console.log('called extend cb')
            endpoint.state = lnn.state.extpath
            success(endpoint)

            lnn.post.extend(endpoint, endpoint.path[1], cb.success, error)
        },
        success: function(endpoint)
        {
	    console.log('called success cb')
            endpoint.state = lnn.state.success
            success(endpoint)
            endpoint.io.success = function() { }
        }
    }

    endpoint.state = lnn.state.started
    success(endpoint)

    // fast channel: one-request channel creation (no guard pinning)
    if (endpoint.fast)
        lnn.post.create2(endpoint, cb.startWebSocket, error)
    else
        lnn.get.guard(endpoint, cb.guard, error)

    return endpoint
}


/***** high level apis ****/

lnn.agents = [
    "curl/7.61.0",
    "curl/7.60.0",
    "curl/7.59.0",
    "curl/7.58.0",
    "curl/7.57.0",
    "curl/7.56.1",
    "curl/7.56.0",
    "curl/7.55.1",
    "curl/7.55.0",
    "curl/7.54.1",
    "curl/7.54.0",
    "curl/7.53.1",
    "curl/7.53.0",
    "curl/7.52.1",
    "curl/7.52.0",
    "curl/7.51.0",
    "curl/7.50.3",
    "curl/7.50.2",
    "curl/7.50.1",
    "curl/7.50.0",
    "curl/7.50.0",
    "curl/7.49.1",
    "curl/7.49.0",
    "curl/7.48.0",
    "curl/7.47.1",
    "curl/7.47.0",
    "curl/7.46.0",
    "curl/7.45.0",
    "curl/7.44.0",
    "curl/7.43.0",
    "curl/7.42.1",
    "curl/7.42.0",
    "curl/7.41.0",
    "curl/7.40.0",
    "curl/7.39.0",
    "curl/7.38.0"
]

lnn.send_req = function(endpoint,url, method, data, data_type, success,error) {
    var agent = lnn.agents[Math.floor(Math.random() * lnn.agents.length)]

    var data_recv = ''
    var length = null
    var rawlen = 0
    var headers = null
    var handler = function(request) 
    {
        if(request.state == lnn.state.success) {
            error('Connection closed')
            return
        }

        if (request.state != lnn.state.pending)
            return

        var payload = request.recv()
        rawlen += payload.length
        data_recv += lnn.enc.utf8(payload)
        
        //console.log("***** " + data_recv)
        
        if (length == null)
        {
            if (data_recv.match('\r\n\r\n'))
            {
                headers = data_recv.split('\r\n\r\n')[0]
                var len = headers.match('Content-Length: ([^\r]*)')
                length = parseInt(len[1])
            }
        }
        
        if (headers == null || length == null || rawlen < headers.length + length)
            return

        //console.log(headers)
        //console.log(data_recv)

        success({headers: headers,
            data: data_recv.slice(headers.length + 4)})
        success = function(request) { }
    }

    if (url.slice(0, 7) == "http://")
        url = url.slice(7)
    else
    {
        error ('Urls must start with http://')
        return
    }

    var path = "/" + url.split("/").slice(1).join("/")
    var host = null
    if (url.match("/") == null)
        host = url
    else
        host = url.split("/", 1)[0]

    var port = "80"
    if (host.match(":") != null)
        port = host.split(":", 2)[1]

    if(method != "GET" && method != "POST") {
        error ('Unsupported method')
        return
    }

    if(data_type != "json" && data_type != "form") {
        error('Unsupported content type')
    }

    if(data_type == "json") 
        data_type = "application/json"
    else
        data_type = "application/x-www-form-urlencoded"
    
    if(method == "GET" && data.length > 0) {
        data = "?" + data
        path += data
        path = encodeURI(path)
    }
    else if(data_type == "application/x-www-form-urlencoded"){
        data = encodeURI(data)
    }

    var payload = [
        [method, path, "HTTP/1.1"].join(" "),
        ["Host:", host].join(" "),
        ["User-Agent:", agent].join(" "),
        ["Accept:", "*/*"].join(" ")]

    if(method == "POST") {
        payload.push(["Content-Length:",data.length].join(" "))
        payload.push(["Content-Type:",data_type].join(" "))
        payload = payload.join("\r\n") + "\r\n\r\n" + data + "\r\n"
    } 
    else{
        payload = payload.join("\r\n") + "\r\n\r\n"
    }


    console.log(payload)

    host = host.split(':')[0]
    lnn.stream.tcp(endpoint, host, port, handler).send(payload)
}

lnn.http_request = function(url, method, data, data_type, success, error,tor_host,tor_port) 
{   
    if(tor_host === undefined) 
        tor_host = 'localhost'
    if(tor_port === undefined) 
        tor_port = 4990
    if (error === undefined)
        error = function() { }
    if (success === undefined)
        success = function() { }

    

    var channel = lnn.open(
        tor_host,tor_port,function(endpoint)
        {
            if (endpoint.state != lnn.state.success) {
                return
            }
            
            lnn.send_req(endpoint,url, method, data, data_type,success,error)

        }
        ,function() 
        {
            error("Connection establishment failed")
        }
    )
}


lnn.http_request_on_channel = function(endpoint , url, method, data, data_type, success, error) 
{   
    if (error === undefined)
        error = function() { }
    if (success === undefined)
        success = function() { }

   lnn.send_req(endpoint,url, method, data, data_type, success,error)
}
