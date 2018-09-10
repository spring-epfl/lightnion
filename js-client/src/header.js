"use strict"

/**
 * The Lightnion Javascript client, top-level namespace.
 *
 * @namespace
 * @see lnn.open
 * @see lnn.stream.tcp
 * @see lnn.state
 * @example
 * lnn.open('proxy.server', 4990, function(endpoint)
 * {
 *     if (endpoint.state != lnn.state.success)
 *         return
 *     tcp = lnn.stream.tcp(endpoint, 'api.ipify.org', 80, handler)
 *     tcp.send('GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n')
 * })
 *
 * function handler(request)
 * {
 *     switch(request.state)
 *     {
 *         case lnn.state.created: console.log('ready')
 *             return
 *         case lnn.state.pending:
 *             console.log(lnn.enc.utf8(request.recv()))
 *             return
 *         case lnn.state.success: console.log('closed')
 *             return
 *     }
 * }
 *
 */
var lnn = {}

/**
 * Common API constants.
 * @namespace
 */
lnn.api = {}

/**
 * Supported API version.
 * @readonly
 * @default
 */
lnn.api.version = "0.1"

/**
 * Prefix used to craft API endpoints.
 * @default
 **/
lnn.api.url = "/lightnion/api/v0.1"

/**
 * Port used to craft websockets.
 * @default
 **/
lnn.api.ws_port = "8765"

/**
 * Request state enumeration.
 * @enum
 * @readonly
 **/
lnn.state = {
        /**
         * operation started
         * @type channel
         */
        started: 1,
        /**
         * /guard get success (channel only)
         * @type channel
         */
        guarded: 2,
        /**
         * circuit created
         * @type channel
         */
        created: 3,
        /**
         * circuit negotiation
         * @type channel
         */
        pending: 4,
        /** circuit extended (channel only)
         * @type channel
         */
        extpath: 5,
        /**
         * ready to use
         * @type channel
         */
        success: 6,
        /**
         * operation started
         * @type stream
         */
        started: 1,
        /**
         * ready to use
         * @type stream
         */
        created: 3,
        /**
         * incoming data
         * @type stream
         */
        pending: 4,
        /**
         * completed or closed
         * @type stream
         */
        success: 6
    }
