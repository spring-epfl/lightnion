/**
 * @module stream
 */

import { lnn } from "./header.js";
import * as onion from "./onion.js";
import { enc, dec } from "./util.js";
import { relay } from "./relay.js";

let stream = {};
stream.entrancy = 0;

class Backend {
    constructor(error) {
        const sendMe = function (cell, endpoint) {
            if (cell.cmd == "sendme") {
                endpoint.stream.sendme += 1;
                endpoint.stream.deliverywindow += 100;
                // flush the send queue for the circuit

                while (endpoint.stream.deliverywindow > 0 && endpoint.stream.tosend.length > 0) {
                    const ncell = endpoint.stream.tosend.shift();
                    endpoint.io.send(ncell);
                    endpoint.stream.deliverywindow -= 1;
                }
            } else {
                error(endpoint);
                throw "Got unexpected control cell.";
            }
        };

        this.id = 0;
        this.tosend = [];
        this.sendme = 0;
        this.handles = { 0: { callback: sendMe } };
        this.packagewindow = 1000; // circuit-level receiving window
        this.deliverywindow = 1000; // circuit level sending window
    }

    register(handle) {
        this.id += 1;
        handle.id = this.id;
        handle.packagewindow = 500; // stream-level receiving window
        handle.deliverywindow = 500; // stream level sending window
        this.handles[this.id] = handle;
        return this.id;
    }

    send(cell, endpoint) {
        if (this.deliverywindow > 0) {
            // if we can send
            endpoint.io.send(cell);
            this.deliverywindow -= 1;
        } else {
            // add to the send queue, will be sent when "sendme" is received. 
            this.tosend.push(cell);
        }
    }

}

class Raw {
    constructor(endpoint, handler) {
        this.id = null;
        this.data = [];
        this.cell = null;
        this.state = lnn.state.started;
        this.packagewindow = null;
        this.deliverywindow = null;
        this.tosend = [];
        this.endpoint = endpoint;
        this.handler = handler;

        // let id = endpoint.stream.register(this);
        this.handler(this);
    }

    send(cmd, data) {
        const cell = onion.build(
            this.endpoint, cmd, this.id, data);

        if (cmd != "data") {
            this.endpoint.io.send(cell); // non-data cells dont affect congestion control
            return;
        }

        if (this.deliverywindow > 0) { // send if stream level window is non zero
            this.endpoint.stream.send(cell, this.endpoint); // send thru circuit level window
            this.deliverywindow -= 1;
        } else {
            this.tosend.push(cell); // add to queue of stream level window
        }
    }

    recv() {
        const data = this.data;
        this.data = [];
        return data;
    }

    callback(cell) {
        if (cell.cmd == "connected") {
            this.state = lnn.state.created;
        }
        if (cell.cmd == "end") {
            this.state = lnn.state.success;
        }

        if (cell.cmd == "sendme") { // receive stream level sendme
            this.deliverywindow += 50;
            while (this.deliverywindow > 0 && this.tosend.length > 0) {
                const ncell = this.tosend.shift();
                this.endpoint.stream.send(ncell, this.endpoint);
                this.deliverywindow -= 1;
            }
        }

        this.data.push(cell);
        this.handler(this);

        if (cell.cmd == "connected") {
            this.state = lnn.state.pending;
        }
    }
}

class Dir {
    constructor(endpoint, path, handler) {
        this.id = null;
        this.data = "";
        this.cell = null;
        this.state = lnn.state.started;
        this.packagewindow = null;
        this.deliverywindow = null;
        this.tosend = [];
        this.endpoint = endpoint;

        this.handler = handler;
        this.path = path;

        const id = endpoint.stream.register(this);
        let cell = onion.build(endpoint, "begin_dir", id);
        endpoint.io.send(cell);

        let data = "GET " + path + " HTTP/1.0\r\n";
        data += "Accept-Encoding: identity\r\n\r\n";
        data = dec.utf8(data);

        cell = onion.build(endpoint, "data", id, data);
        this.deliverywindow -= 1;
        endpoint.stream.send(cell, endpoint);

        this.handler(this);
    }

    send() {
        throw "No send method on directory streams.";
    }

    recv() {
        const data = this.data;
        this.data = "";
        return data;
    }

    callback(cell) {
        if (cell.cmd == "connected") {
            this.state = lnn.state.created;
            this.handler(this);
            this.state = lnn.state.pending;
        }
        if (cell.cmd == "end") {
            this.state = lnn.state.success;
            this.handler(this);
        }
        if (cell.cmd == "sendme") {
            this.deliverywindow += 50;
            while (this.deliverywindow > 0 && this.tosend.length > 0) {
                const ncell = this.tosend.shift();
                this.endpoint.stream.send(ncell, this.endpoint);
                this.deliverywindow -= 1;
            }
        }

        if (cell.cmd != "data") { return; }

        this.data += enc.utf8(cell.data);
        this.handler(this);
    }
}

class TCP {
    constructor(endPoint, host, port, handler) {
        this.id = null;
        this.data = new Uint8Array(0);
        this.cell = null;
        this.cache = [];

        this.state = lnn.state.started;
        this.packagewindow = null;
        this.deliverywindow = null;
        this.tosend = [];
        this.endpoint = endPoint;
        this.retries = 0;

        this.host = host;
        this.port = port;
        this.handler = handler;

        // WL: Get new identifier for stream?
        const id = endPoint.stream.register(this);

        // WL: Create a BEGIN package containing host and port of the server?
        const data = relay.begin(host, port);

        // WL: Construct the cell around it?
        const cell = onion.build(endPoint, "begin", id, data);

        // WL: Send that sell to start the process?
        this.endpoint.io.send(cell);

        this.handler(this);

        this.send = this.send.bind(this);

    }

    send(send_data) {
        if (send_data !== undefined) {
            this.cache.push(send_data);
        }

        if (this.state == lnn.state.started) { // not yet recvd reply for relay begin
            return;
        }

        while (this.cache.length) {
            let data = this.cache.shift();

            if (typeof (data) == "string") {
                data = lnn.dec.utf8(data);
            }

            const payload = new Uint8Array(lnn.relay.data_len);

            while (data.length > payload.length) {
                payload.set(data.slice(0, payload.length), 0);
                data = data.slice(payload.length);

                const cell = lnn.onion.build(
                    this.endpoint, "data", this.id, payload);

                if (this.deliverywindow > 0) {
                    this.endpoint.stream.send(cell, this.endpoint);
                    this.deliverywindow -= 1;
                } else {
                    this.tosend.push(cell);
                }

            }

            const cell = lnn.onion.build(
                this.endpoint, "data", this.id, data);

            if (this.deliverywindow > 0) {
                this.endpoint.stream.send(cell, this.endpoint);
                this.deliverywindow -= 1;
            } else {
                this.tosend.push(cell);
            }
        }
    }



    callback(cell) {
        console.log(cell.cmd);
        if (cell.cmd == "connected") {
            this.state = lnn.state.created;
            this.retries = 0;
            this.send();
        }
        if (cell.cmd == "end") {
            if (cell.data[0] == 4) { // REASON EXIT_POLICY
                if (this.retries == 3) { // threshold for retrying
                    console.log('Retries limit exceeded. Cant connect to host. ');
                    this.state = lnn.state.success;
                    this.retries = 0;
                } else {
                    this.retries += 1;
                    console.log("Retrying to build circuit, retry#: " + this.retries);

                    let ports = [80, 443];

                    if (!ports.includes(this.port)) {
                        ports.push(this.port);
                    }

                    lnn.open(
                        this.endpoint.host,
                        this.endpoint.port,
                        this.success_on_open,
                        this.error_on_open,
                        undefined,
                        this.endpoint.fast,
                        this.endpoint.auth,
                        this.endpoint.select_path,
                        ports
                    );
                }
            } else {
                this.state = lnn.state.success;
            }
        }
        if (cell.cmd == "data") {
            const data = this.data;
            this.data = new Uint8Array(data.length + cell.data.length);
            this.data.set(data, 0);
            this.data.set(cell.data, data.length);
        }
        if (cell.cmd == "sendme") {

            this.deliverywindow += 50;
            while (this.deliverywindow > 0 && this.tosend.length > 0) {
                const ncell = this.tosend.shift();
                this.endpoint.stream.send(ncell, this.endpoint);
                this.deliverywindow -= 1;
            }
        }

        this.handler(this);
        if (cell.cmd == "connected") {
            this.state = lnn.state.pending;
        }
    }

    recv() {
        const data = this.data;
        this.data = new Uint8Array(0);
        return data;
    }

    close() {
        let data = new Uint8Array(1);
        data[0] = 6; // reason done
        const cell = onion.build(this.endpoint, "end", this.id, data);
        this.endpoint.io.send(cell);
    }

    success_on_open(endp) {
        if (endp.consensus === null)
            endp.consensus = this.endpoint.consensus;
        if (endp.descriptors === null)
            endp.descriptors = this.endpoint.descriptors;
        if (endp.consensus_raw === null)
            endp.consensus_raw = this.endpoint.consensus_raw;
        if (endp.descriptors_raw === null)
            endp.descriptors_raw = this.endpoint.descriptors_raw;
        if (endp.signing_keys === null)
            endp.signing_keys = this.endpoint.signing_keys;

        this.endpoint = endp;

        const id = this.endpoint.stream.register(this);
        const data = lnn.relay.begin(this.host, this.port);
        const cell = lnn.onion.build(this.endpoint, "begin", id, data);
        this.endpoint.io.send(cell);

        this.handler(this);
    }


    error_on_open(error_msg) {
        throw error_msg;
    }
}

stream.handler = function (endpoint, cell) {
    stream.entrancy += 1;
    if (stream.entrancy > 1) {
        console.log("ENTRANCY BUG");
    }

    if (cell[4] != 3) { // (relay cell only)
        console.log("Got non-relay cell, dropped: ", cell[4]);
        stream.entrancy -= 1;
        return;
    }

    cell = onion.peel(endpoint, cell)
    if (cell === null) {
        console.log("Got invalid cell, dropped.");
        stream.entrancy -= 1;
        return;
    }

    if (!(cell.stream_id in endpoint.stream.handles)) {
        console.log("Got cell outside stream, dropped: ", cell.stream_id);
        stream.entrancy -= 1;
        return;
    }

    let handle = endpoint.stream.handles[cell.stream_id];
    if (cell.cmd == "end")
        delete endpoint.stream.handles[cell.stream_id];

    handle.cell = cell;
    handle.callback(cell, endpoint);

    /* handle circuit-level sendme */


    if (cell.cmd == "data") {
        endpoint.stream.packagewindow -= 1;
    }
    console.log('Update window: ', endpoint.stream.packagewindow);
    if (endpoint.stream.packagewindow < 900) {
        //console.log("Circuit window is ", endpoint.stream.packagewindow)
        //console.log("Sending circuit level sendme cell now ", endpoint.io.counter)
        endpoint.io.send(onion.build(endpoint, 'sendme'));
        endpoint.stream.packagewindow += 100;
    }

    /* handle stream-level sendme */
    if (cell.cmd == "data") {
        handle.packagewindow -= 1;
    }
    if (handle.packagewindow < 450) {
        //console.log("Stream window is ", handle.packagewindow)
        //console.log("Sending stream level sendme cell now ", endpoint.io.counter)
        cell = onion.build(endpoint, 'sendme', handle.id);
        endpoint.io.send(cell);
        handle.packagewindow += 50;
    }

    stream.entrancy -= 1;
};

stream.backend = (error) => new Backend(error);
stream.raw = (endpoint, handler) => new Raw(endpoint, handler);
stream.dir = (endpoint, path, handler) => new Dir(endpoint, path, handler);
stream.tcp = (endPoint, host, port, handler) => new TCP(endPoint, host, port, handler);



export { stream };