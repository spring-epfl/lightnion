/**
 * @module endpoint
 */

import * as utils from "./util.js";
import { lnn } from "./header.js";
import * as post from "./post.js";
import { stream } from "./stream.js";


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

/**
 * Create an empty endpoint object, consider using {@link lnn.open} first.
 *
 * @todo TODO: migrate from http+ws to https+wss
 * @todo TODO: use only one port for https+wss
 *
 * @param {string} host (ex: localhost, example.com)
 * @param {string} port (ex: 4990, 8080, 5000, 443…)
 * @return {endpoint_t}
 */
export function endpoint(host, port) {
    var http = "http://" + host + ":" + port.toString()
    http += lnn.api.url

    var ws = "ws://" + host + ":" + lnn.api.ws_port
    ws += lnn.api.url

    /**
     * Internal object, stores API urls used for parent endpoint calls.
     *
     * <pre>
     * Note: {@link lnn.api.ws_port} is inlined in .ws and .socket
     *       (used by {@link lnn.io.socket}).
     * </pre>
     *
     * @interface endpoint_t~urls_t
     * @see endpoint_t
     *
     * @property {string} ws        websocket base url
     * @property {string} http      http calls base url
     * @property {string} guard     GET /consensus
     * @property {string} consensus GET /consensus
     * @property {string} socket    websocket endpoint
     * @property {string} channels  POST+DELETE /channels
     * @property {string} consensus GET /consensus
     */
    var urls = {
        ws: ws,
        http: http,
        guard: http + "/guard",
        socket: ws + "/channel",
        channels: http + "/channels",
        consensus: http + "/consensus",
        descriptors: http + "/descriptors",
        signing_keys: http + "/signing-keys"
    }

    /**
     * Captures the state of a channel, returned by {@link lnn.open}.
     *
     * @interface endpoint_t
     * @see lnn.endpoint
     *
     * @property {lnn.state} state              channel state
     * @property {io.io_t} io                   io adapter in use
     * @property {endpoint_t~urls_t} urls       static API urls in use
     * @property {backend_t} stream             stream backend in use
     * @property {backward_t} backward          backward cryptographic state
     * @property {forward_t} forward            forward cryptographic state
     * @property {material_t|half_t} material   shared cryptographic material
     * @property {null|half_t} auth             stores {@link lnn.auth}
     *                                          material
     */
    var endpoint = {
        /**
         * Host in use, as given to {@link lnn.endpoint} factory.
         *
         * @name endpoint_t#host
         * @readonly
         */
        host: host,
        /**
         * Port in use, as given to {@link lnn.endpoint} factory.
         *
         * @name endpoint_t#port
         * @readonly
         */
        port: port,
        auth: null,
        urls: urls,
        io: null,
        state: 0,
        /**
         * Last shared cryptographic material retrieved, written by:
         * <ul>
         *  <li> {@link lnn.post.create}
         *  <li> {@link lnn.post.extend}
         *  <li> {@link lnn.ntor.hand}
         *  <li> {@link lnn.ntor.auth}
         * </ul>
         *
         * Either stores {@link material_t} or {@link half_t}.
         *
         * @name endpoint_t#material
         * @type {material_t|half_t}
         *
         * @see lnn.ntor.hand
         */
        material: null,
        forward: null,
        backward: null,
        /**
         * Identifier of the channel in used, written by successful a
         * {@link lnn.post.create} call.
         * @name endpoint_t#id
         * @readonly
         * @default null
         */
        id: null,
        /**
         * Polling url endpoint used for polling io requests.
         * @see lnn.post.channel
         * @see lnn.io.polling
         *
         * @name endpoint_t#url
         * @readonly
         * @default null
         */
        url: null,
        /**
         * Middle and Exit nodes descriptors obtained by {@link lnn.open}
         * during channel setup.
         *
         * <pre>
         * Note: writing this field will NOT change the path in use.
         * </pre>
         *
         * @name endpoint_t#path
         * @readonly
         * @default null
         */
        path: null,
        /**
         * Guard descriptor obtained by {@link lnn.open} during channel
         * setup, written by {@link lnn.get.guard}.
         *
         * @name endpoint_t#guard
         * @readonly
         * @default null
         */
        guard: null,
        stream: null,
        /**
         * Consensus obtained by {@link lnn.get.consensus} upon request.
         *
         * @name endpoint_t#consensus
         * @readonly
         * @default null
         */
        consensus: null,

        /**
         * Consensus obtained by {@link lnn.get.descriptors} upon request
         * @name endpoint_t#descriptors
         * @readonly
         * @default null
         */
        descriptors: null,
        consensus_raw: null,
        descriptors_raw: null,
        signing_keys: null,

        select_path: false,

        /**
         * Perform the HTTP request.
         * @param {String} url URL where the request is send
         * @param {String} method method of the HTTP request
         * @param {String} data payload of the request
         * @param {String} data_type data type of the payload of the request
         * @param {Function} success callback in case of success
         * @param {Function} error callback in case of error
         */
        http_request: function (url, method, data, data_type, success, error) {
            //api.send_req(endpoint, url, method, data, data_type, success, error)
            if (success === undefined)
                success = function () { }
            if (error === undefined)
                error = function () { }

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

        },

        /*destroy the circuit*/
        close: function (success, error) {
            post.close(endpoint, success, error)
        }
    }

    return endpoint
}
