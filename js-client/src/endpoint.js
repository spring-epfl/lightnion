/**
 * Create an empty endpoint object, consider using {@link lighttor.open} first.
 *
 * @todo TODO: migrate from http+ws to https+wss
 * @todo TODO: use only one port for https+wss
 *
 * @param {string} host (ex: localhost, example.com)
 * @param {string} port (ex: 4990, 8080, 5000, 443…)
 * @return {endpoint_t}
 */
lighttor.endpoint = function(host, port)
{
    var http = "http://" + host + ":" + port.toString()
    http += lighttor.api.url

    var ws = "ws://" + host + ":" + lighttor.api.ws_port
    ws += lighttor.api.url

    /**
     * Internal object, stores API urls used for parent endpoint calls.
     *
     * <pre>
     * Note: {@link lighttor.api.ws_port} is inlined in .ws and .socket
     *       (used by {@link lighttor.io.socket}).
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
        socket: ws + "/channels",
        channels: http + "/channels",
        consensus: http + "/consensus"}

    /**
     * Captures the state of a channel, returned by {@link lighttor.open}.
     *
     * @interface endpoint_t
     * @see lighttor.endpoint
     *
     * @property {lighttor.state} state         channel state
     * @property {io.io_t} io                   io adapter in use
     * @property {endpoint_t~urls_t} urls       static API urls in use
     * @property {stream.backend_t} stream      stream backend in use
     * @property {onion.backward_t} backward    backward cryptographic state
     * @property {onion.forward_t} forward      forward cryptographic state
     * @property {ntor.material_t} material     shared cryptographic material
     */
    var endpoint = {
        /**
         * Host in use, as given to {@link lighttor.endpoint} factory.
         *
         * @name endpoint_t#host
         * @readonly
         */
        host: host,
        /**
         * Port in use, as given to {@link lighttor.endpoint} factory.
         *
         * @name endpoint_t#port
         * @readonly
         */
        port: port,
        urls: urls,
        io: null,
        state: 0,
        material: null,
        forward: null,
        backward: null,
        /**
         * Channel id obtained upon successful /create call.
         * @name endpoint_t#id
         * @readonly
         * @default null
         */
        id: null,
        /**
         * Polling url endpoint used for polling io requests.
         * @see lighttor.post.channel
         * @see lighttor.io.polling
         *
         * @name endpoint_t#url
         * @readonly
         * @default null
         */
        url: null,
        /**
         * Middle and Exit nodes descriptors obtained by {@link lighttor.open}
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
         * Guard descriptor obtained by {@link lighttor.open} during channel
         * setup (written by {@link lighttor.get.guard}).
         *
         * @name endpoint_t#guard
         * @readonly
         * @default null
         */
        guard: null,
        stream: null,
        /**
         * Consensus obtained by {@link lighttor.get.consensus} upon request.
         *
         * @name endpoint_t#consensus
         * @readonly
         * @default null
         */
        consensus: null}

    return endpoint
}
