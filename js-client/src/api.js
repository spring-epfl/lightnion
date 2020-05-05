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

/**
 * Create a circuit on the Tor network, return a handler to send request on
 * this circuit, or close it.
 * @param {String} host host of the Lightnion proxy
 * @param {Number} port port where the Lightnion proxy is reachable
 * @param {Function} success callback in case of success
 * @param {Function} error callback in case of error
 * @param {io.io_t} io io adapter in use
 * @param {half_t} auth lnn.auth material
 * @param {Boolean} select_path Compute the circuit path in the client*
 * @param {List} tcp_ports list of ports which need to be accepted by the exit node
 * @returns connection handler
 */
export function open(host, port, success, error, io, auth, select_path, tcp_ports) {
    let endpoint = lnnEndpoint.endpoint(host, port)
    if (io === undefined)
        io = lnnIO.socket
    if (error === undefined)
        error = function () { }
    if (success === undefined)
        success = function () { }
    if (select_path === undefined)
        select_path = true

    if (tcp_ports === undefined)
        tcp_ports = [80, 443]

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
            console.log("circuit created")
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
        get.guard(endpoint, cb.guard, error)
    }

    return endpoint
}


/***** high level apis ****/


/**
 * Send an HTTP request by using an handler.
 * @param {lnn.endpoint} endpoint handler created by {@link lnn.open}
 * @param {String} url URL where the request is send
 * @param {String} method method of the HTTP request
 * @param {String} data payload of the request
 * @param {string} data_type data type of the payload of the request
 * @param {Function} success callback in case of success
 * @param {Function} error callback in case of error
 */
export function send_req(endpoint, url, method, data, data_type, success, error) {
    endpoint.http_request(url, method, data, data_type, success, error)
}


/**
 * Build a circuit to do a single HTTP request over the Tor network.
 * @param {String} url URL where the request is send
 * @param {String} method method of the HTTP request
 * @param {String} data payload of the request
 * @param {string} data_type data type of the payload of the request
 * @param {Function} success callback in case of success
 * @param {Function} error callback in case of error
 * @param {String} tor_host host of the Lightnion proxy
 * @param {Number} tor_port port where the Lightnion proxy is reachable
 */
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


