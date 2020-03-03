/**
 * Helpers for the lightnion js-client code.
 */

import { lnn } from "../../lnn.js";

/**
 * A Lightnion tunelled TCP socket.
 * @private
 */
export class LTCP {
    // TODO: onclose
    constructor(host) {
        this.connected = false;
        // TODO: document
        // onmessage takes a UInt8Array argument
        this.onmessage = (msg) => { console.error(`LTCP received non-handled message: ${msg}`); };
        this.host = host;
    }

    send() {
        throw "LTPC: undefined send method";
    }
}

/**
 * Connect to a Lightnion Proxy.
 * @param {string} lnnHost host of the lightnion proxy
 * @param {Number} lnnPort port of the lightnion proxy
 * @returns a promise that resolves on connection success, and rejects in case of a failure;
 *  in case of success, return the lightnion endpoint, in case of failure, an error message
 * @private
 */
export function lnnOpen(lnnHost, lnnPort) {
    return new Promise((resolve, reject) => {
        lnn.open(lnnHost, lnnPort, function (endpoint) {
            if (endpoint.state != lnn.state.success) {
                console.error("lightnion proxy connection failed");
                reject(`could not connect to lightnion proxy at ${lnnHost}:${lnnPort}`);
            }
            console.debug("lightnion proxy connection established");
            resolve(endpoint);
        });
    });
}

// Connect to TCP endpoint
// return a promise that resolves on connection success, and rejects in case of failure
// in case of succes, return a TCP object, in case of failure, an error message
/**
 * Connect to a TCP endpoint through a Lightnion proxy.
 * 
 * @param lnnEndpoint the lightnion proxy endpoint object, returned by {@link lnnOpen}
 * @param host host of the TCP endpoint
 * @param port port of the TCP endpoint
 * @private
 */
export function ltcpOpen(lnnEndpoint, host, port) {

    return new Promise((resolve, reject) => {

        let ltcp = new LTCP(host);

        function handler(socket) {

            let pkt;

            switch (socket.state) {
                case lnn.state.created:
                    ltcp.connected = true;
                    ltcp.send = socket.send;
                    resolve(ltcp);
                    break;
                case lnn.state.pending:
                    pkt = socket.recv();
                    if (pkt !== undefined) {
                        ltcp.onmessage(pkt);
                    }
                    break;
                case lnn.state.success:
                    ltcp.connected = false;
                    reject(`could not connect to TCP host at ${host}:${port}`);
                    break;
                default:
                    break;
            }
        }
        lnn.stream.tcp(lnnEndpoint, host, port, handler);
    });
}

// TLS support.
// Uses forge.tls module.
// TODO: tests.
// export function ltlsOpen(lnnEndpoint, host, port) {

//     return ltcpOpen(lnnEndpoint, host, port).then(ltcp => {
//         console.debug("tcp socket connected")
//         return new Promise((resolve, reject) => {
//             let tlsSocket = new LTCP(host);

//             // create tls client working on tcp
//             let tlsClient = forge.tls.createConnection({
//                 // see: https://github.com/digitalbazaar/forge#tls
//                 server: false,
//                 verify: function (connection, verified, depth, certs) {
//                     // FIXME
//                     return true; // skip cert. verif. (testing)
//                 },
//                 connected: function (connection) {
//                     // (tls handshake finished, now ready to send)
//                     tlsSocket.onmessage = (req) => { tlsClient.process(lnn.enc.bin(req.recv())); };
//                     tlsSocket.send = tlsClient.send;
//                     resolve(tlsSocket);
//                 },
//                 tlsDataReady: function (connection) {
//                     // TLS -> TCP
//                     // (decode binary data into array before processing)
//                     ltcp.send(lnn.dec.bin(connection.tlsData.getBytes()));
//                 },
//                 dataReady: function (connection) {
//                     // TLS -> Application
//                     // (receive decrypted data from the tls transport)
//                     var data = connection.data.getBytes();
//                     onReceive(data);
//                 },
//                 closed: function (connection) {
//                     console.info("tls connection closed");
//                 },
//                 error: function (connection, err) {
//                     console.error(`tls connection error: ${err}`);
//                 }
//             });
//             console.debug("initiating tls handshake");
//             tlsClient.handshake();
//         });
//     });
// }
