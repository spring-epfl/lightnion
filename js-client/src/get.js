/**
 * GET operations.
 * @namespace
 */
lighttor.get = {}

/**
 * Perform GET /guard and update endpoint accordingly,
 * see {@link endpoint_t#guard}.
 *
 * @param {endpoint_t} endpoint     endpoint in use, stores answer
 * @param {callback} success        optional, called on success
 * @param {callback} error          optional, called on error
 * @example
 * // Note: lighttor.open perform these steps for you whenever needed.
 * endpoint = lighttor.endpoint('localhost', 4990)
 * lighttor.get.guard(endpoint, function (endpoint)
 * {
 *     console.log('Guard identity:', endpoint.guard.router.identity)
 * })
 * // (can also have error callback: function (endpoint, xhttp_status) { })
 */
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

/**
 * Perform GET /consensus and update endpoint accordingly,
 * see {@link endpoint_t#consensus}.
 *
 * <pre>
 * Note: provided for testing purposes and currently have no use.
 * </pre>
 *
 * Usage and parameters are similar to {@link lighttor.get.guard}, stores the
 * consensus as parsed from the proxy-server answer.
 *
 * @see lighttor.get.guard
 */
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
