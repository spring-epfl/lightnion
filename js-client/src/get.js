lighttor.get = {}
lighttor.get.guard = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 200)
        {
            endpoint.guard = JSON.parse(rq.responseText)
            if (success !== undefined)
                success(endpoint)
        }
        else if (rq.readyState == 4 && error !== undefined)
        {
            error(endpoint, rq.status)
        }
    }
    rq.open("GET", endpoint.urls.guard, true)
    rq.send()
}

lighttor.get.consensus = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 200)
        {
            endpoint.consensus = JSON.parse(rq.responseText)
            if (success !== undefined)
                success(endpoint)
        }
        else if (rq.readyState == 4 && error !== undefined)
        {
            error(endpoint, rq.status)
        }
    }
    rq.open("GET", endpoint.urls.consensus, true)
    rq.send()
}
