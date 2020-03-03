/**
 * A definition of a WebSocket client.
 * 
 * @module websocket-client
 */

import { isNode } from 'browser-or-node';
import { parseURL } from "./utils.js";
import naclutil from "tweetnacl-util";
import * as wspackets from "./packets.js";
import * as wspacketsutils from "./packets-utils.js";
import * as handlers from "./handlers.js";
import * as httpParsing from "../http/parsing.js";
import { EventTargetClass, MessageEventClass, CloseEventClass } from "./mocks.js";
import { StreamHandler } from "./stream-handler.js";
import { FrameDefragmenter } from "./defragmenter.js";

export let binaryTypes = {
    blob: "blob",
    arraybuffer: "arraybuffer",
};

/**
 * An abstract WebSocket client.
 * 
 * Uses an underlying socket to be supplied by implementing classes when calling {@linkcode WebSocketClient._start_opening_handshake}.
 */
export class WebSocketClient extends EventTargetClass {
    // CONSTANTS
    // static getters are used to implement static constants
    static get CONNECTING() { return 0; }
    static get OPEN() { return 1; }
    static get CLOSING() { return 2; }
    static get CLOSED() { return 3; }

    constructor(url, protocols = []) {
        super();

        if (protocols.length > 0) {
            console.error(`websocket subprotocols are not yet supported: ${protocols}`);
        }

        // url
        this._url = new URL(url);

        // TODO: see https://www.w3.org/TR/websockets/#dom-websocket-bufferedamount
        // need to use the underlying buffer measures as well,
        // lightnion-js uses lnn.stream.tcp.cache.length
        this._bufferedAmount = 0;

        this._extensions = "";
        this._protocol = "";
        this._readyState = WebSocketClient.CONNECTING;
        this._binaryType = binaryTypes.blob; // defaults

        // 'private' event handlers
        // these are the handlers called by the underlying socket
        // each of them will call the user-defined handler (e.g. this.onmessage) after some processing
        this.__onclose = (event) => { this.onclose(event); };
        this.__onerror = (event) => { this.onerror(event); };
        this.__onmessage = (event) => { this.onmessage(event); };
        this.__onopen = (event) => { this.onopen(event); };

        // 'public' event handlers
        this._onclose = () => { };
        this._onerror = () => { };
        this._onmessage = () => { };
        this._onopen = () => { };


        // true if the closing handshake has been initiated
        this._the_websocket_closing_handshake_is_started = false;

        // for translation of stream to frames
        this._streamHandler = new StreamHandler();

        // for reception of fragmented message
        this._frameDefragmenter = new FrameDefragmenter();

        // check if duplicates in protocols
        // TODO
        // if (new Set(this.protocols).size != this.protocols.length) {
        //     throw SyntaxError(`duplicates in protocols: ${this.protocols}`);
        // }


        let origin = "";
        if (!isNode) {
            origin = new URL(window.location.href);
        } else {
            origin = "http://localhost/";
        }

        // parse url
        let secure;
        try {
            secure = parseURL(this._url)[3];
        } catch (err) {
            throw SyntaxError(`could not parse url: ${err}`);
        }

        if (secure && origin.protocol !== "https") {
            throw Error(`SecurityError: cannot open non-secure websocket from a secure origin`);
        }

        // transport level socket connection
        // should be set when the handshake is requested
        this._socket = undefined;
    }

    // PROPERTIES

    // url: read-only DOMString
    get url() {
        return this._url.href;
    }

    // readyState: read-only unsigned short
    get readyState() {
        return this._readyState;
    }

    // bufferedAmount: read-only unsigned long
    get bufferedAmount() {
        return this._bufferedAmount;
    }

    // extensions: read-only DOMString
    get extensions() {
        return this._extensions;
    }

    // protocol: read-only DOMString
    get protocol() {
        return this._protocol;
    }

    // binaryType: DOMString
    get binaryType() { return this._binaryType; }
    set binaryType(binaryType) {
        switch (binaryType) {
            case "blob":
                this._binaryType = binaryTypes.blob;
                break;
            case "arraybuffer":
                this._binaryType = binaryTypes.arraybuffer;
                break;
            default:
                throw new SyntaxError(`websocket binaryType cannot be set to ${binaryType}, allowed values are 'blob' and 'arraybuffer'`);
        }
    }


    // EVENT HANDLERS

    /**
     * Get the onopen handler.
     */
    get onopen() {
        return this._onopen;
    }
    /**
     * Set the onopen handler.
     */
    set onopen(onopen) {
        this._onopen = onopen;
    }

    /**
     * Get the onmessage handler.
     */
    get onmessage() {
        return this._onmessage;
    }

    /**
     * Set the onmessage handler.
     */
    set onmessage(onmessage) {
        this._onmessage = onmessage;
    }

    /**
     * Get the onerror handler.
     */
    get onerror() {
        return this._onerror;
    }
    /**
     * Set the onerror handler.
     */
    set onerror(onerror) {
        this._onerror = onerror;
    }

    /**
     * Get the onclose handler.
     */
    get onclose() {
        return this._onclose;
    }
    /**
     * Set the onclose handler.
     */
    set onclose(onclose) {
        this._onclose = onclose;
    }


    // INTERFACE METHODS

    /**
     * Send to the websocket endpoint.
     * @param {string|Blob|ArrayBuffer|ArrayBufferView} data the payload to send 
     */
    send(data) {
        // FIXME: bufferedAmount, closing handshake started

        if (!(this._socket)) {
            throw `Socket not initialized`;
        }

        if (this._readyState === WebSocketClient.CONNECTING) {
            throw `InvalidStateError: cannot send data while websocket is in CONNECTING state`;
        }

        let frame;
        if (typeof data === "string") {
            // convert data to a sequence of Unicode characters
            const payload = naclutil.decodeUTF8(data);
            if (this._readyState === WebSocketClient.OPEN) {
                frame = new wspackets.Frame(false, false, false, wspackets.opcodes.text, payload);
            }
        } else if (data instanceof Blob) {
            frame = new wspackets.Frame(false, false, false, wspackets.opcodes.binary, data);
        } else if (data instanceof ArrayBuffer) {
            frame = new wspackets.Frame(false, false, false, wspackets.opcodes.binary, data);
        } else {
            // assume ArrayBufferView
            // send data stored in the section of the buffer described by the ArrayBuffer object that the ArrayBufferView object references
            frame = new wspackets.Frame(false, false, false, wspackets.opcodes.binary, data);
        }

        if (frame) {
            // console.debug("[WS] sending websocket message");
            // console.debug(frame);
            this._socket.send(frame.encapsulate());
        } else {
            // not connected or closing, ...
            return;
        }
    }

    /**
     * Close the WebSocket connection.
     * @param {int} code 
     * @param {DOMString} reason 
     */
    close(code, reason) {
        // check code
        if (code && (code !== 1000 || (code >= 3000 && code <= 4999))) {
            throw Error(`InvalidAccessError: code must be 1000 or in the range 3000-4999`);
        }

        if (reason) {
            const unicodeReason = naclutil.encodeUTF8(reason);
            if (unicodeReason.byteLength > 123) {
                throw SyntaxError(`reason is too long: ${reason}`);
            }
        }

        if (this._readyState === WebSocketClient.CLOSED || this._readyState === WebSocketClient.CLOSING) {
            // do nothing
            return;
        } else if (this._readyState !== WebSocketClient.OPEN) {
            // connection not yet established
            // fail the websocket connection and set the readyState attribute's value to CLOSING
            this._closing();
            this._fail_the_websocket_connection();
        } else if (!this._the_websocket_closing_handshake_is_started) {
            // the closing handshake has not yet been started
            // start the closing handshake and set the readyState attribute's value to CLOSING
            this._closing();
            this._start_the_websocket_closing_handshake(code, reason);
        } else {
            this._closing();
        }
    }

    // CLOSING THE CONNECTION
    // https://tools.ietf.org/html/rfc6455#section-7

    /**
     * Close the WebSocket Connection
     * @private
     */
    _close_the_websocket_connection() {
        // cleanly close the TLS & TCP connection
        if (this._socket) {
            this._socket.close();
        }
        this._readyState = WebSocketClient.CLOSED;
        this._closed(true);
    }

    /**
     * Start the WebSocket Closing Handshake
     * @param {int} code status code for closing the connection
     * @param {reason} string reason for closing the connection
     * @private
     */
    _start_the_websocket_closing_handshake(code, reason = undefined) {
        if (!(this._socket)) {
            throw `Socket not initialized`;
        }

        this._the_websocket_closing_handshake_is_started = true;
        this._socket.send(wspackets.closeFrame(code, reason));

        // wait for the close control frame from the endpoint
        // and _close_the_websocket_connection
        // this is done in the onmessage callback
    }

    /**
     * Fail the WebSocket Connection.
     * @private
     */
    _fail_the_websocket_connection() {
        this._close_the_websocket_connection();
    }

    // TASKS

    /**
     * Task to run when "the WebSocket connection is established"
     * @private
     */
    _established() {
        // 1. change the readyState attribute's value to OPEN
        this._readyState = WebSocketClient.OPEN;

        // 2. TODO: change the extensions attribute's value to the extensions in use, if is not the null value
        // this._extensions = 

        // 3. TODO: change the protocol attribute's value to the subprotocol in use, if is not the null value
        // this._protocol = 

        // 4. TODO: act as if the user agent had received a set-cookie-string consisting of the cookies 
        //          set during the server's opening handshake, for the URL url given to the WebSocket() constructor
        // document.cookie = 

        // 5. fire a simple event named open at the WebSocket object
        this.dispatchEvent(new Event("open"));
    }

    /**
     * Task to run when "a WebSocket message has been received"
     * @private
     */
    _received(event) {

        // 1. If the readyState attribute's value is not OPEN (1), then abort these steps
        if (this._readyState !== WebSocketClient.OPEN) {
            return;
        }

        // 2. let event be an event that uses the MessageEvent interface,
        //    with the event type message, which does not bubble, is not cancelable, 
        //    and has no default action.
        // 3. initialize event's origin attribute to the Unicode serialization of the origin of the URL
        //    that was passed to the WebSocket object's constructor.
        // 4. - if type indicates that the data is Text, then initialize event's data attribute to data
        //    - if type indicates that the data is Binary, and binaryType is set to "blob", 
        //      then initialize event's data attribute to a new Blob object that represents data as its raw data
        //    - if type indicates that the data is Binary, and binaryType is set to "arraybuffer",
        //      then initialize event's data attribute to a new read-only ArrayBuffer object whose contents are data

        // 2+3+4 already done before

        let e = new MessageEventClass("message", {
            origin: this._url.href,
            data: event.data,
        });

        // 5. dispatch event at the WebSocket object.
        this.dispatchEvent(e);
    }

    /**
     * Task to run when "the WebSocket closing handshake is started"
     * @private
     */
    _closing() {
        // change the readyState attribute to CLOSING (2)
        this._readyState = WebSocketClient.CLOSING;
    }


    /**
     * Task to run when "the WebSocket connection is closed"
     * @private
     */
    _closed(wasClean, code = 1005, reason = "") {
        // 1. change the readyState attribute's value to CLOSED (3)
        this._readyState = WebSocketClient.CLOSED;

        // 2. if the user agent was required to fail the WebSocket connection 
        //    or the WebSocket connection is closed with prejudice, 
        //    fire a simple event named error at the WebSocket object

        // TODO

        // 3. Create an event that uses the CloseEvent interface,
        //    with the event type close, which does not bubble, is not cancelable, has no default action,
        //    whose wasClean attribute is initialized to true if the connection closed cleanly and false otherwise,
        //    whose code attribute is initialized to the WebSocket connection close code,
        //    and whose reason attribute is initialized to the WebSocket connection close reason decoded as UTF-8,
        //    with error handling, and dispatch the event at the WebSocket object

        const event = new CloseEventClass("close", {
            wasClean: wasClean,
            code: code,
            reason: reason,
        });

        this.dispatchEvent(event);
    }

    // Handshake helper methods

    /**
     * Perform the opening websocket handshake.
     * Non-blocking, as needed when calling the method in the constructor.
     * 
     * This method should be called by the constructor of the derived class,
     * setting the socket specific to this derived class.
     * 
     * @param socket underlying socket
     */
    _start_opening_handshake(socket) {
        // TODO: check interface
        this._socket = socket;

        // parse url
        let host, port, ressourceName, secure;
        try {
            [host, port, ressourceName, secure] = parseURL(this._url);
        } catch (err) {
            throw SyntaxError(`could not parse url: ${err}`);
        }

        // perform handshake
        this.__do_opening_handhake(host, port, ressourceName, secure).then(() => {
            this._established();
            this._socket.onmessage = handlers.onOpenMessage(this);
            this.__onopen();
        }).catch(() => {
            this._readyState = WebSocketClient.CLOSED;
            this._fail_the_websocket_connection();
        });
    }


    /**
     * Perform the WebSocket connection handshake.
     * 
     * @returns Promise that resolves when connection was successfully established,
     *  or rejects otherwise with an error message.
     * @private
     */
    __do_opening_handhake(host, port, ressourceName, secure) {
        if (secure) {
            console.error("secure websocket not yet supported");
        }

        return new Promise((resolve, reject) => {
            if (!(this._socket)) {
                reject(`Socket not initialized`);
            }

            let statusLine = "";
            let headerLines = [];

            const [clientHS, secWebSocketKey] = wspackets.clientHandshake(host, port, ressourceName);

            // change onmessage of underlying socket
            this._socket.onmessage = (pkt) => {  // TODO: refactor to avoid request ?
                let payload = naclutil.encodeUTF8(pkt);

                // parse received packet as a HTTP websocket connection response
                let lines = payload.split("\r\n");
                if (lines.length < 1) {
                    reject(`failed to connect to websocket: received empty http response`);
                }

                if (statusLine) {
                    // following message (response was fragmented)
                    headerLines = headerLines.concat(lines);
                } else {
                    // first message
                    statusLine = lines[0].split(" ");
                    headerLines = headerLines.concat(lines.slice(1));

                    // status code verification
                    if (statusLine.length < 3) {
                        reject(`failed to connect to websocket: invalid status line ${statusLine.join(" ")}`);
                        return;
                    }

                    const statusCode = statusLine[1];

                    if (statusCode != "101") {
                        reject(`failed to connect to websocket: got status code ${statusCode}`);
                        return;
                    }
                }

                if (headerLines[headerLines.length - 1] !== "") {
                    return;
                } else {
                    // last line of headers, no body expected
                    // this means that this is the last packet expected
                    let headers = httpParsing.parseHeaders(headerLines.join("\r\n"));

                    // verification of the headers

                    // check for the upgrade header field
                    if (!("upgrade" in headers) || !(headers["upgrade"].toLowerCase().split(", ").includes("websocket"))) {
                        reject(`failed to connect to websoket: server handshake response invalid, does not contain 'upgrade: websocket' header line: ${headers}`);
                        return;
                    }

                    // check for the connection header field
                    if (!("connection" in headers) || !(headers["connection"].toLowerCase().split(", ").includes("upgrade"))) {
                        reject(`failed to connect to websocket: server handshake response invalid, does not contain 'connection: upgrade' header line: ${headers}`);
                        return;
                    }

                    // check for the sec-websocket-accept header field
                    if (!("sec-websocket-accept" in headers)) {
                        reject(`failed to connect to websocket: server handshake response invalid, does not contain 'sec-websocket-accept' header line: ${headers}`);
                        return;
                    }

                    if (!wspacketsutils.verifySecWebSocketAccept(secWebSocketKey, headers["sec-websocket-accept"].trim())) {
                        reject(`failed to connect to websocket: 'sec-websocket-accept' could not be verified`);
                        return;
                    }

                    // check for the sec-websocket-extensions header field
                    if ("sec-websocket-extensions" in headers) {
                        const serverExtensions = headers["sec-websocket-extensions"].split(", ");
                        // TODO: no support for extensions
                        if (serverExtensions.length > 1 || serverExtensions[0] !== "") {
                            reject(`failed to connect to websocket: extensions are not supported: ${headers["sec-websocket-extensions"]}`);
                            return;
                        }
                    }

                    // check for the sec-websocket-protocol header field
                    if ("sec-websocket-protocol" in headers) {
                        const serverSubProtocols = headers["sec-websocket-protocol"].split(", ");
                        // TODO: no support for subprotocols
                        if (serverSubProtocols.length > 1 || serverSubProtocols[0] !== "") {
                            reject(`failed to connect to websocket: sub protocols are not supported: ${headers["sec-websocket-protocol"]}`);
                            return;
                        }
                    }

                    resolve();
                }
            };
            this._socket.send(naclutil.decodeUTF8(clientHS));
        });

    }

}
