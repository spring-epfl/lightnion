/**
 * @module api
 */

import * as utils from "./util.js";
import * as lnnEndpoint from "./endpoint.js";
import * as lnnIO from "./io.js";
import * as post from "./post.js";
import * as get from "./get.js";
import * as signature from "./signature.js";
import { stream } from "./stream.js";

export function fast(host, port, success, error, io, select_path) {
    if (select_path === undefined)
        select_path = true
    return open(host, port, success, error, io, true, null, select_path)
}

export function auth(host, port, suffix, success, error, io, select_path) {
    if (select_path === undefined)
        select_path = true
    if (typeof (suffix) == "string") {
        suffix = suffix.replace(/-/g, "+").replace(/_/g, "/")
        suffix = utils.dec.base64(suffix)
    }
    if (utils.enc.utf8(suffix.slice(0, 5)) != "auth ")
        throw "Invalid prefix in auth. suffix!"

    suffix = suffix.slice(5)
    if (suffix.length != 20 + 32)
        throw "Invalid auth. suffix length!"

    return open(host, port, success, error, io, true, {
        identity: suffix.slice(0, 20),
        onionkey: suffix.slice(20),
        ntor: nacl.box.keyPair()
    }, select_path)
}

export function open(host, port, success, error, io, fast, auth, select_path, tcp_ports) {
    let endpoint = lnnEndpoint.endpoint(host, port)
    if (io === undefined)
        io = lnnIO.socket
    if (fast === undefined)
        fast = false
    if (error === undefined)
        error = function () { }
    if (success === undefined)
        success = function () { }
    if (select_path === undefined)
        select_path = true

    if (tcp_ports === undefined)
        tcp_ports = [80, 443]

    endpoint.fast = fast
    endpoint.auth = auth
    endpoint.select_path = select_path

    var cb = {
        guard: function (endpoint) {
            endpoint.state = lnn.state.guarded


            post.circuit_info(endpoint, cb.startWebSocket, error, select_path, tcp_ports)
        },
        startWebSocket: function (endpoint, info) {
            console.log('called startWebSocket cb')
            endpoint.stream = stream.backend(error)
            io(endpoint, stream.handler, function (endpoint) {
                var state = endpoint.state

                endpoint.state = lnn.state.pending

                endpoint.state = state
            }, error)
            endpoint.io.start()

            post.handshake(endpoint, info, cb.create, error)
        },
        create: function (endpoint) {
            console.log('called create cb')
            endpoint.state = lnn.state.created

            post.extend(endpoint, endpoint.path[0], cb.extend, error)
        },
        extend: function (endpoint) {
            console.log('called extend cb')
            endpoint.state = lnn.state.extpath

            post.extend(endpoint, endpoint.path[1], cb.success, error)
        },
        success: function (endpoint) {
            console.log('called success cb')
            endpoint.state = lnn.state.success
            info("circuit created")
            success(endpoint)
            endpoint.io.success = function () { }
        }
    }

    endpoint.state = lnn.state.started


    if (select_path) {
        get.consensus_raw(endpoint, function () {
            get.signing_keys(endpoint, function () {
                if (!signature.verify(endpoint.consensus_raw, endpoint.signing_keys, 0.5)) {
                    throw "signature verification failed."
                }
                console.log("signature verification success")
                get.descriptors_raw(endpoint, function () {
                    if (endpoint.fast)
                        post.circuit_info(endpoint, cb.startWebSocket, error, select_path, tcp_ports)
                    else
                        get.guard(endpoint, cb.guard, error)

                }, function () {
                    throw "Failed to fetch raw descriptors"
                })
            }, function () {
                throw "Failed to fetch signing keys"
            })
        }, function () {
            throw "Failed to fetch raw consensus!"
        })
    }
    else {
        // fast channel: one-request channel creation (no guard pinning)
        if (endpoint.fast)
            post.circuit_info(endpoint, cb.startWebSocket, error, select_path, tcp_ports)
        else
            get.guard(endpoint, cb.guard, error)
    }

    return endpoint
}


/***** high level apis ****/

export let agents = [
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

export function send_req(endpoint, url, method, data, data_type, success, error) {
    var agent = agents[Math.floor(Math.random() * agents.length)]

    var data_recv = ''
    var length = null
    var rawlen = 0
    var headers = null
    var handler = function (request) {
        if (request.state == lnn.state.success) {
            error('Connection closed')
            return
        }

        if (request.state != lnn.state.pending)
            return

        var payload = request.recv()
        rawlen += payload.length
        data_recv += utils.enc.utf8(payload)


        if (length == null) {
            if (data_recv.match('\r\n\r\n')) {
                headers = data_recv.split('\r\n\r\n')[0]
                var len = headers.match('Content-Length: ([^\r]*)')
                length = parseInt(len[1])
            }
        }

        if (headers == null || length == null || rawlen < headers.length + length)
            return

        request.close()
        console.log("Stream closed")

        success({
            headers: headers,
            data: data_recv.slice(headers.length + 4)
        })
        success = function (request) { }
    }

    if (url.slice(0, 7) == "http://")
        url = url.slice(7)
    else {
        error('Urls must start with http://')
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

    if (method != "GET" && method != "POST") {
        error('Unsupported method')
        return
    }

    if (data_type != "json" && data_type != "form") {
        error('Unsupported content type')
        return
    }

    if (data_type == "json")
        data_type = "application/json"
    else
        data_type = "application/x-www-form-urlencoded"

    if (method == "GET" && data.length > 0) {
        data = "?" + data
        path += data
        path = encodeURI(path)
    }
    else if (data_type == "application/x-www-form-urlencoded") {
        data = encodeURI(data)
    }

    var payload = [
        [method, path, "HTTP/1.1"].join(" "),
        ["Host:", host].join(" "),
        ["User-Agent:", agent].join(" "),
        ["Accept:", "*/*"].join(" ")]

    if (method == "POST") {
        payload.push(["Content-Length:", data.length].join(" "))
        payload.push(["Content-Type:", data_type].join(" "))
        payload = payload.join("\r\n") + "\r\n\r\n" + data + "\r\n"
    }
    else {
        payload = payload.join("\r\n") + "\r\n\r\n"
    }


    console.log(payload)

    host = host.split(':')[0]
    stream.tcp(endpoint, host, port, handler).send(payload)
}

export function http_request(url, method, data, data_type, success, error, tor_host, tor_port) {
    if (tor_host === undefined)
        tor_host = 'localhost'
    if (tor_port === undefined)
        tor_port = 4990
    if (error === undefined)
        error = function () { }
    if (success === undefined)
        success = function () { }

    var closed = false

    var channel = open(
        tor_host, tor_port, function (endpoint) {
            if (endpoint.state != lnn.state.success) {
                return
            }

            send_req(endpoint, url, method, data, data_type, function (request) {
                //close circuit here.
                if (!closed) {
                    endpoint.close(function (success_msg) { console.log(success_msg) })
                    closed = true
                }
                success(request)
            }, function (message) {
                //close circuit here
                if (!closed) {
                    endpoint.close(function (success_msg) { console.log(success_msg) })
                    closed = true
                }
                error(message)
            })

        }
        , function () {
            error("Connection establishment failed")
        }
    )
}


