/**
 * Packet crafting for the WebSocket protocol.
 * 
 *    WebSocket frame (RFC 6455):
 * 
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-------+-+-------------+-------------------------------+
 *    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 *    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 *    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 *    | |1|2|3|       |K|             |                               |
 *    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 *    |     Extended payload length continued, if payload len == 127  |
 *    + - - - - - - - - - - - - - - - +-------------------------------+
 *    |                               |Masking-key, if MASK set to 1  |
 *    +-------------------------------+-------------------------------+
 *    | Masking-key (continued)       |          Payload Data...      |
 *    +---------------------------------------------------------------|
 * 
 */

import nacl from "tweetnacl";
import naclutil from "tweetnacl-util";
import { maskWithKey, concatenate } from "./utils.js";

/**
 * Construct the HTTP packet send by the client during the WebSocket handshake.
 * @returns {Array} [pkt, nonce] the HTTP client handshake packet as a string, with the Uint8Array SecWebSocketKey nonce used in it
 * @private
 */
export function clientHandshake(host, port, resourceName, protocols = []) {
    // TODO:
    // - Sec-WebSocket-Protocol
    // - Sec-WebSocket-Extensions

    // create the nonce: base64 encoded 16 random bytes
    const nonce = nacl.randomBytes(16);
    const nonceB64 = naclutil.encodeBase64(nonce);

    // create the http packet
    let fields = [
        ["GET", `${resourceName}`, "HTTP/1.1"],
        ["Host:", `${host}:${port}`],
        ["Connection:", "Upgrade"],
        ["Upgrade:", "websocket"],
        ["Sec-WebSocket-Key:", `${nonceB64}`],
        ["Origin:", `${host}`],
        ["Sec-WebSocket-Version:", "13"],
    ];

    if (Array.isArray(protocols) && protocols.length > 0) {
        fields.push(["Sec-WebSocket-Protocol:", protocols.join(", ")]);
    }

    const pkt = fields.map(s => s.join(" ")).join("\r\n") + "\r\n\r\n";

    return [pkt, nonce];
}

/**
 * The GUID used for the Sec-WebSocket verification.
 * @private
 */
export const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/**
 * Construct a pong frame.
 * @param {Uint8Array} payload the pong payload, usually the application data of the received ping
 * @param {Uint8Array} maskingKey 4-bytes key for masking the frame, for testing purposes
 * @private
 */
export function pongFrame(payload, maskingKey = undefined) {
    return Frame._encapsulate(payload, "1000", opcodes.pong, maskingKey);
}

/**
 * Construct a ping frame.
 * @param {Uint8Array} payload the ping application data
 * @param {Uint8Array} maskingKey 4-bytes key for masking the frame, for testing purposes
 * @private
 */
export function pingFrame(payload, maskingKey = undefined) {
    return Frame._encapsulate(payload, "1000", opcodes.ping, maskingKey);
}

/**
 * Construct a close frame
 * @param {Number} code status code for closing the connection (2bytes)
 * @param {reason} string reason for closing the connection
 * @param {Uint8Array} maskingKey 4-bytes key for masking the frame, for testing purposes
 * @private
 */
export function closeFrame(code, reason = undefined, maskingKey = undefined) {
    if (code < 0 || code >= 65536) {
        throw `cannot encode int ${code} to 2 bytes`;
    }
    let payload = new Uint8Array([
        code >> 8,
        code & 255
    ]);
    if (reason) {
        payload = concatenate(concatenate, naclutil.decodeUTF8(reason));
    }

    return Frame._encapsulate(payload, "1000", opcodes.close, maskingKey);
}

/**
 * Construct a text frame.
 * @param {string} text the text to send
 * @param {Uint8Array} maskingKey 4-bytes key for masking the frame, for testing purposes
 * @private
 */
export function textFrame(text, maskingKey = undefined) {
    const payload = naclutil.decodeUTF8(text);
    return Frame._encapsulate(payload, "1000", opcodes.text, maskingKey);
}

export let opcodes = {
    continuation: 0,
    text: 1,
    binary: 2,
    // x3-7 reserved for further non-control frames
    close: 8,
    ping: 9,
    pong: 10,
    // xB-F reserved for further control frames
};

export let isControlFrame = (opcode) => (opcode & 8) === 8;

/**
 * Represent a WebSocket frame, not fragmented.
 *
 * See websocket framing protocol:
 * {@link https://tools.ietf.org/html/rfc6455#section-5.2}.
 * @private
 */
export class Frame {

    /**
     * Construct a WebSocket Frame.
     * 
     * @param {Boolean} rsv1 
     * @param {Boolean} rsv2 
     * @param {Boolean} rsv3 
     * @param {Integer} opcode 
     * @param {Uint8Array} payload 
     */
    constructor(rsv1, rsv2, rsv3, opcode, payload) {
        this.rsv1 = rsv1 ? "1" : "0";
        this.rsv2 = rsv2 ? "1" : "0";
        this.rsv3 = rsv3 ? "1" : "0";
        this.opcode = opcode;
        this.payload = payload;
    }

    // Return true if the frame represents a control frame
    isControl() {
        return isControlFrame(this.opcode);
    }

    /**
     * Encapsulate Frame into a WebSocket packet in byte array format.
     * 
     * @param {Uint8Array} maskingKey 4-bytes key for masking the frame, for testing purposes
     * @returns {Uint8Array} packet
     */
    encapsulate(maskingKey = undefined) {
        const flags = "1".concat(this.rsv1, this.rsv2, this.rsv3);
        return Frame._encapsulate(this.payload, flags, this.opcode, maskingKey);
    }

    /**
     * Fragment frame into several websocket packets.
     * To be used in place of the `encapsulate` method when fragmentation is needed.
     * 
     * @param {int} chunkSize the maximum length of a (websocket) payload, in bytes
     * @param {Uint8Array} maskingKey 4-bytes key for masking the frame, for testing purposes
     * @returns {Array} an array of Uint8Array, that contains in-order websocket-encapsulated packets
     */
    fragment(chunkSize, maskingKey = undefined) {
        // chunk payload into smaller payloads
        let payloads = [];
        for (let i = 0; i < this.payload.length; i += chunkSize) {
            payloads.push(this.payload.slice(i, i + chunkSize));
        }

        // create packets
        let packets = [];
        for (let i = 0; i < payloads.length; i++) {
            // only the last fragment has the FIN flag set
            const finFlag = (i !== (payloads.length - 1)) ? "0" : "1";
            const flags = finFlag.concat(this.rsv1, this.rsv2, this.rsv3);
            // only the first fragment has the opcode set
            const code = (i === 0) ? this.opcode : opcodes.continuation;

            packets.push(Frame._encapsulate(payloads[i], flags, code, maskingKey));
        }

        return packets;
    }

    /**
     * Encapsulate given data into a WebSocket packet in byte array format.
     * 
     * @param {Uint8Array} payload the packet payload
     * @param {string} flags the first 4 bits of the packet, FIN/RSV1/RSV2/RSV3 in bitstring format
     * @param {int} opcode the integer opcode
     * @param {Uint8Array} maskingKey 4-bytes key for masking the frame, for testing purposes
     * @returns {Uint8Array} packet
     */
    static _encapsulate(payload, flags = "1000", opcode = 1, maskingKey = undefined) {
        const opcodeBits = opcode.toString(2).padStart(4, '0');

        let payloadLen;
        if (payload.length >= 126) {
            if (payload.length < 65536) {
                // use next two bytes to encode the payload length
                let code = 126;
                payloadLen = code.toString(2).padStart(7, '0');
                payloadLen += payload.length.toString(2).padStart(16, '0');

            } else {
                if (payload.length > 2 ^ (8 * 8)) {
                    throw `Error: payload too large for the websocket protocol`;
                }
                // use next eight bytes to encode the payload length
                let code = 127;
                payloadLen = code.toString(2).padStart(7, '0');
                payloadLen += payload.length.toString(2).padStart(64, '0');
            }
        } else {
            payloadLen = payload.length.toString(2).padStart(7, '0');
        }

        let mask = '1';
        if (maskingKey === undefined) {
            // create a nonce
            maskingKey = new Uint8Array(nacl.randomBytes(4));
        }
        const maskedPayload = maskWithKey(payload, maskingKey);

        function bitstringToUint8Array(bitstring) {
            const len = Math.ceil(bitstring.length / 8);
            let out = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                out[i] = parseInt(bitstring.slice(8 * i, 8 * i + 8), 2);
            }
            return out;
        }

        let headerStart = bitstringToUint8Array(flags + opcodeBits + mask + payloadLen);

        return Uint8Array.from([...headerStart, ...maskingKey, ...maskedPayload]);
    }
}

