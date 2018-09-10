"use strict"

/**
 * The Lighttor Javascript client, top-level namespace.
 *
 * @namespace
 * @see lighttor.open
 * @see lighttor.stream.tcp
 * @see lighttor.state
 * @example
 * lighttor.open('proxy.server', 4990, function(endpoint)
 * {
 *     if (endpoint.state != lighttor.state.success)
 *         return
 *     tcp = lighttor.stream.tcp(endpoint, 'api.ipify.org', 80, handler)
 *     tcp.send('GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n')
 * })
 *
 * function handler(request)
 * {
 *     switch(request.state)
 *     {
 *         case lighttor.state.created: console.log('ready')
 *             return
 *         case lighttor.state.pending:
 *             console.log(lighttor.enc.utf8(request.recv()))
 *             return
 *         case lighttor.state.success: console.log('closed')
 *             return
 *     }
 * }
 *
 */
var lighttor = {}

/**
 * Common API constants.
 * @namespace
 */
lighttor.api = {}

/**
 * Supported API version.
 * @readonly
 * @default
 */
lighttor.api.version = "0.1"

/**
 * Prefix used to craft API endpoints.
 * @default
 **/
lighttor.api.url = "/lighttor/api/v0.1"

/**
 * Port used to craft websockets.
 * @default
 **/
lighttor.api.ws_port = "8765"

/**
 * Request state enumeration.
 * @enum
 * @readonly
 **/
lighttor.state = {
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
         * circuit negotiation
         * @type channel
         */
        pending: 4,
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
