var lighttor = {}
lighttor.api = {}

lighttor.api.version = '0.1'
lighttor.api.url = '/lighttor/api/v' + lighttor.api.version

lighttor.api.http_port = '4990'
lighttor.api.ws_port = '8765'

lighttor.endpoint = function(host)
{
    var http = 'http://' + host + ':' + lighttor.api.http_port
    http += lighttor.api.url

    var ws = 'ws://' + host + ':' + lighttor.api.ws_port
    ws += lighttor.api.url

    var urls = {
        ws: ws,
        http: http,
        guard: http + '/guard',
        channels: http + '/channels',
        consensus: http + '/consensus',
        websockets: ws + '/channels'}

    var material = {
        ntor: null}

    var endpoint = {
        host: host,
        urls: urls,
        material: material,
        id: null,
        path: null,
        guard: null,
        consensus: null}

    return endpoint
}

lighttor.get = {}
lighttor.get.guard = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest();
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 200)
        {
            endpoint.guard = JSON.parse(this.responseText)
            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4 && error !== undefined)
        {
            error(endpoint, this.status)
        }
    }
    rq.open('GET', endpoint.urls.guard, true)
    rq.send()
}
lighttor.get.consensus = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 200)
        {
            endpoint.consensus = JSON.parse(this.responseText)
            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4 && error !== undefined)
        {
            error(endpoint, this.status)
        }
    }
    rq.open('GET', endpoint.urls.consensus, true)
    rq.send()
}

lighttor.ntor = {}
lighttor.ntor.protoid = 'ntor-curve25519-sha256-1'

lighttor.ntor.magics = {}
lighttor.ntor.magics.expand = lighttor.ntor.protoid + ':key_expand'
lighttor.ntor.magics.verify = lighttor.ntor.protoid + ':verify'
lighttor.ntor.magics.server = 'Server'
lighttor.ntor.magics.key = lighttor.ntor.protoid + ':key_extract'
lighttor.ntor.magics.mac = lighttor.ntor.protoid + ':mac'

lighttor.ntor.hand = function(endpoint)
{
    var identity = nacl.util.decodeBase64(endpoint.guard.router.identity + '=')
    var onionkey = nacl.util.decodeBase64(endpoint.guard['ntor-onion-key'])

    endpoint.material = {}
    endpoint.material.ntor = nacl.box.keyPair()
    endpoint.material.identity = identity
    endpoint.material.onionkey = onionkey

    var pubkey = endpoint.material.ntor.publicKey
    var length = identity.length + onionkey.length + pubkey.length

    var payload = new Uint8Array(length)
    payload.set(identity, offset=0)
    payload.set(onionkey, offset=identity.length)
    payload.set(pubkey, offset=identity.length+onionkey.length)

    return nacl.util.encodeBase64(payload)
}

lighttor.post = {}
lighttor.post.create = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (this.readyState == 4 && this.status == 201)
        {
            info = JSON.parse(this.responseText)
            endpoint.id = info['id']
            endpoint.ntor = info['ntor'] // TODO: remove (temporary)
            endpoint.path = info['path']
            if (success !== undefined)
                success(endpoint)
        }
        else if (this.readyState == 4 && error !== undefined)
        {
            error(endpoint, this.status)
        }
    }

    payload = lighttor.ntor.hand(endpoint)
    payload = JSON.stringify({ntor: payload})

    rq.open('POST', endpoint.urls.channels, true)
    rq.setRequestHeader("Content-type", "application/json");
    rq.send(JSON.stringify({ntor: lighttor.ntor.hand(endpoint)}))
}
