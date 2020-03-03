/**
 * @module lightnion-websocket
 */

import { WebSocketClient } from "../websocket-client/websocket-client.js";
import { lnnOpen, ltcpOpen } from "./lightnion-helpers.js";
// import { ltlsOpen } from "./lightnion-helpers.js"; // TODO: TLS support

/**
 * LightnionWebSocket is a WebSocket client tunnelled through Lightnion.
 */
export default class LightnionWebSocket extends WebSocketClient {

    /**
     * Create a LightnionWebSocket, a WebSocket tunelled through Tor via a Lightnion proxy.
     * 
     * @param {string} url the WebSocket server URL
     * @param {array} protocols a list of subprotocols to use, currently not-supported
     * @param {string} lightnionHost the lightnion proxy host
     * @param {Number} lightnionPort the lightnion proxy port
     */
    constructor(url, protocols = [], lightnionHost = "localhost", lightnionPort = 4990) {
        let urlP = new URL(url);

        let port = urlP.port;
        if (!port) {
            port = urlP.protocol == "ws:" ? "80" : "443";
        }

        super(urlP, protocols);

        // user defined event handlers
        this.onmessage = () => { };
        this.onopen = () => { };
        this.onclose = () => { };
        this.onerror = () => { };

        // schedule the tcp handshake to start when the underlying socket is ready
        lnnOpen(lightnionHost, lightnionPort).then(lnnEndpoint => {
            // open tcp socket to host, through lightnion
            return ltcpOpen(lnnEndpoint, urlP.hostname, port);
            // or open a tls socket
            // return ltlsOpen(lnnEndpoint, urlP.hostname, port);
        }).then(ltcp => {
            console.debug("[LTCP]: connected");

            // start websocket handshake protocol
            this._start_opening_handshake(ltcp);

            // install handlers
            this.__onmessage = (event) => {
                this.onmessage(event);
            };
            this.__onopen = (event) => {
                this.onopen(event);
            };
            this.__onclose = (event) => {
                this.onclose(event);
            };
            this.__onerror = (event) => {
                this.onerror(event);
            };

        });
    }
}
