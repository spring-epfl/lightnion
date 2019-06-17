/**
 * GET operations.
 * @namespace
 * @see lnn.get.guard
 */
lnn.get = {}

/**
 * Perform GET /guard and update endpoint accordingly,
 * see {@link endpoint_t#guard}.
 *
 * @param {endpoint_t} endpoint     endpoint in use, stores answer
 * @param {callback} success        optional, called on success
 * @param {callback} error          optional, called on error
 * @example
 * // Note: lnn.open perform these steps for you whenever needed.
 * endpoint = lnn.endpoint('localhost', 4990)
 * lnn.get.guard(endpoint, function (endpoint)
 * {
 *     console.log('Guard identity:', endpoint.guard.router.identity)
 * })
 * // (can also have error callback: function (endpoint, xhttp_status) { })
 */
lnn.get.guard = function(endpoint, success, error)
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

/**
 * Perform GET /consensus and update endpoint accordingly,
 * see {@link endpoint_t#consensus}.
 *
 * <pre>
 * Note: provided for testing purposes and currently have no use.
 * </pre>
 *
 * Usage and parameters are similar to {@link lnn.get.guard}, stores the
 * consensus as parsed from the proxy-server answer.
 *
 * @param {endpoint_t} endpoint     endpoint in use, stores answer
 * @param {callback} success        optional, called on success
 * @param {callback} error          optional, called on error
 *
 * @see lnn.get.guard
 */
lnn.get.consensus = function(endpoint, success, error)
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

/**
 * Perform GET /descriptors 
 */
lnn.get.descriptors = function(endpoint, success, error){
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function(){
        if(rq.readyState == 4 && rq.status == 200){
            endpoint.descriptors = JSON.parse(rq.responseText)
            
            if(success !== undefined) success(endpoint)
        }
        else if (rq.readyState == 4 && error !== undefined){
            error(endpoint, rq.status)
        }
    }

    rq.open("GET", endpoint.urls.descriptors, true)
    rq.send()
}

lnn.get.consensus_raw = function(endpoint, success, error)
{
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function()
    {
        if (rq.readyState == 4 && rq.status == 200)
        {
            endpoint.consensus_raw =  rq.responseText
            if (success !== undefined)
                success(endpoint)
        }
        else if (rq.readyState == 4 && error !== undefined)
        {
            error(endpoint, rq.status)
        }
    }
    rq.open("GET", endpoint.urls.consensus+"-raw", true)
    rq.send()
}

/**
 * Perform GET /descriptors 
 */
lnn.get.descriptors_raw = function(endpoint, success, error){
    var rq = new XMLHttpRequest()
    rq.onreadystatechange = function(){
        if(rq.readyState == 4 && rq.status == 200){
            endpoint.descriptors_raw = rq.responseText
            
            if(success !== undefined) success(endpoint)
        }
        else if (rq.readyState == 4 && error !== undefined){
            error(endpoint, rq.status)
        }
    }

    rq.open("GET", endpoint.urls.descriptors+"-raw", true)
    rq.send()
}

