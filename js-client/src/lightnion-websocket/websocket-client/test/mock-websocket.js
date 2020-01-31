/**
 * A mock of a client WebSocket
 */

import { WebSocketClient } from "../websocket-client.js";
import { StreamHandler } from "../stream-handler.js";

export class MockWebSocket extends WebSocketClient {

    constructor(url, protocols = []) {
        super(url, protocols);

        this._socket = new MockSocket();

        this._socket.onmessage = (event) => {
            this.onmessage(event);
        };
    }
}


/**
 * A Mock of a underlying socket for a WebSocket.
 */
class MockSocket {

    constructor() {
        this.closed = false;
        this.sentMessages = [];
        this.receivedMessages = [];
        this._streamHandler = new StreamHandler();
    }

    // Required Interface Methods

    send(data) {
        this.sentMessages.push(data);

        // execute attached callback if present,
        // this is used to ease unit testing
        if (data.callback) {
            data.callback();
        }
    }

    close() {
        if (this.closed) {
            throw Error("cannot close socket: already closed");
        }
        this.closed = true;
    }

    // set by the websocket
    onmessage() {
    }

    // for testing
    // fake reception of a message
    receive(data) {
        this.receivedMessages.push(data);
        this.onmessage(data);
    }

}