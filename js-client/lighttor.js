var lighttor = {};
lighttor.api = {};
lighttor.get = {};

lighttor.api.version = '0.1'
lighttor.api.url = '/lighttor/api/v' + lighttor.api.version

lighttor.api.http_port = '4990'
lighttor.api.ws_port = '8765'

lighttor.endpoint = function(host)
{
    http = 'http://' + host + ':' + lighttor.api.http_port
    http += lighttor.api.url

    ws = 'ws://' + host + ':' + lighttor.api.ws_port
    ws += lighttor.api.url

    var urls = {
        ws: ws,
        http: http,
        guard: http + '/guard',
        channels: http + '/channels',
        websockets: ws + '/channels'}

    var endpoint = {
        host: host,
        urls: urls,
        guard: null}

    return endpoint
}

lighttor.get.guard = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest();
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 200)
        {
            endpoint.guard = JSON.parse(this.responseText);
            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4 && error !== undefined)
        {
            error(endpoint, this.status);
        }
    }
    rq.open('GET', endpoint.urls.guard, true);
    rq.send()
}
