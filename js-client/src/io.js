/**
 * @module io
 */

import * as post from "./post.js";
import { enc, dec } from "./util.js";

export const polling = (endpoint, handler, success, error) => new Polling(endpoint, handler, success, error);

class Polling {
    constructor(endpoint, handler, success, error) {
        this.incoming = [];
        this.outcoming = [];
        this.pending = 0;
        this.handler = handler;
        this.success = success;
        this.error = error;
        this.cell = null;

        this.endpoint = endpoint;

        endpoint.io = this;
    }

    poll() {
        setTimeout(function () {
            post.channel(this.endpoint, this.poll);
        }, 100);
    }

    send(cell) {
        this.outcoming.push(enc.base64(cell));
    }

    recv() {
        if (this.incoming.length < 1) { return undefined; }

        this.cell = this.incoming.shift();
        return dec.base64(this.cell);
    }

    start() {
        post.channel(this.endpoint, this.poll);
    }
}

export function socket(endpoint, handler, success, error) {
    if (handler === undefined)
        handler = function (endpoint) { }
    if (success === undefined)
        success = function (endpoint) { }
    if (error === undefined)
        error = function (endpoint) { }

    var io = {
        event: null,
        socket: null,
        closed: false,
        incoming: [],
        outcoming: [],
        handler: handler,
        success: success,
        error: error,
        cell: null,
        cell_recv: 0,
        //cell_sent: 0,
        send: function (cell) {
            io.outcoming.push(cell)

            //io.cell_sent += 1
            //var cell_repr = Array.from(cell.slice(0,20)).map(function(x) {return x.toString(16).padStart(2, '0')}).join('')
            //console.log("cell ", io.cell_sent.toString(), " sent to wbskt ", cell_repr)
        },
        recv: function () {
            if (io.incoming.length < 1)
                return undefined

            io.cell = io.incoming.shift()

            io.cell_recv += 1
            var cell_repr = Array.from(io.cell.slice(0, 20)).map(function (x) { return x.toString(16).padStart(2, '0') }).join('')
            console.log("cell recv by wbskt ", cell_repr)

            return io.cell
        },
        start: function () { }
    }
    var socket = new WebSocket(endpoint.urls.socket + "/" + endpoint.id)

    socket.binaryType = "arraybuffer"
    socket.onopen = function (event) {
        io.event = event
        io.success(endpoint)

        while (io.outcoming.length > 0)
            io.socket.send(io.outcoming.shift())

        io.send = function (cell) {
            if (io.closed)
                throw "Unable to send, connection closed."
            io.socket.send(cell.buffer)

            //io.cell_sent += 1
            //var cell_repr = Array.from(cell.slice(0,20)).map(function(x) {return x.toString(16).padStart(2, '0')}).join('')
            //console.log("cell ", io.cell_sent.toString(), " sent to wbskt ", cell_repr)
        }
    }
    socket.onerror = function (event) {
        io.event = event
        io.error(endpoint)
    }
    socket.onmessage = function (event) {
        io.event = event

        var data = new Uint8Array(event.data)

        var cell_repr = Array.from(data.slice(0, 20)).map(function (x) { return x.toString(16).padStart(2, '0') }).join('')
        console.log("cell recv by wbskt ", cell_repr)

        // io.incoming.push(data)
        io.cell = data
        io.handler(endpoint, data)
    }
    socket.onclose = function (event) {
        io.event = event
        io.closed = true
        io.error(endpoint)
    }

    endpoint.io = io
    endpoint.io.socket = socket
    return io
}
