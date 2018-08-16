lighttor.io = {}
lighttor.io.simple = function(handler, success, error)
{
    var io = {
        incoming: [],
        outcoming: [],
        pending: 0,
        handler: handler,
        success: success,
        error: error,
        send: function(cell)
        {
            io.outcoming.push(lighttor.enc.base64(cell))
        },
        recv: function()
        {
            if (io.incoming.length < 1)
                return undefined

            var cell = io.incoming.shift()
            return lighttor.dec.base64(cell)
        }
    }
    return io
}

lighttor.io.polling = function(endpoint, handler, success, error)
{
    var io = lighttor.io.simple(handler, success, error)
    io.poll = function()
    {
        setTimeout(function()
        {
            lighttor.post.channel(endpoint, io.poll)
        }, 100)
    }
    io.start = function()
    {
        lighttor.post.channel(endpoint, io.poll)
    }
    endpoint.io = io
    return io
}
