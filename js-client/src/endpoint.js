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
lnn.endpoint = function(host, port)
{
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
        socket: ws + "/channels",
        channels: http + "/channels",
        consensus: http + "/consensus",
        descriptors: http + "/descriptors"
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
     * @property {Boolean} fast                 is {@link lnn.fast}
     *                                          in use?
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
        fast: null,
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
         *  <li> {@link lnn.ntor.fast}
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

        /*perform http get/post request*/
        
        http_request: function(url, method, data, data_type, success, error) 
        {   
            if (error === undefined)
                error = function() { }
            if (success === undefined)
                success = function() { }

           lnn.send_req(endpoint,url, method, data, data_type, success,error)
        },

        /*destroy the circuit*/
        close: function(success,error)
        {
            lnn.post.close(endpoint,success,error)
        }
    }

    return endpoint
}
