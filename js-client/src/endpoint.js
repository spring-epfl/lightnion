lighttor.endpoint = function(host, port)
{
    var http = "http://" + host + ":" + port.toString()
    http += lighttor.api.url

    var ws = "ws://" + host + ":" + lighttor.api.ws_port
    ws += lighttor.api.url

    var urls = {
        ws: ws,
        http: http,
        guard: http + "/guard",
        socket: ws + "/channels",
        channels: http + "/channels",
        consensus: http + "/consensus"}

    var endpoint = {
        host: host,
        urls: urls,
        io: null,
        state: 0,
        material: null,
        forward: null,
        backward: null,
        id: null,
        url: null,
        path: null,
        guard: null,
        stream: null,
        consensus: null}

    return endpoint
}
