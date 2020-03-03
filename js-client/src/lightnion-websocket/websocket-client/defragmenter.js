import { isControlFrame, Frame, opcodes } from "./packets.js";
import { concatenate } from "./utils.js";

/**
 * Defragments WebSocket frames
 * Used when receiving websocket frames that may have been fragmented.
 * 
 * @private
 */
export class FrameDefragmenter {

    constructor() {
        this._outputQueue = [];
        this._parsed = undefined;
    }


    /**
     * Add a received frame, that may be fragmented.
     * 
     * @param {frame} Uint8Array packet received, unmasked
     * @throws error when fed out of order frames
     * @return {undefined} control frame if given packet is a control frame, undefined otherwise
     */
    add(frame) {
        let parsed = FrameDefragmenter._fields(frame);

        if (parsed === undefined) {
            console.warn("received websocket frame could not be parsed");
            return undefined;
        }

        if (isControlFrame(parsed['opcode'])) {
            this._outputQueue.push(new Frame(
                parsed["rsv1"] === 1,
                parsed["rsv2"] === 1,
                parsed["rsv3"] === 1,
                parsed["opcode"],
                parsed["payload data"],
            ));
            return;
        }

        const fin = parsed["fin"];
        const opcode = parsed["opcode"];

        if (this._parsed === undefined) {
            if (fin && opcode !== opcodes.continuation) {
                // unfragmented
                this._outputQueue.push(new Frame(
                    parsed["rsv1"] === 1,
                    parsed["rsv2"] === 1,
                    parsed["rsv3"] === 1,
                    parsed["opcode"],
                    parsed["payload data"],
                ));
                this._parsed = undefined;
                return;
            } else if (!fin && opcode !== opcodes.continuation) {
                // first fragmented frame
                this._parsed = parsed;
                return;
            } else {
                throw `Error: FrameBuilder was given an out of order frame`;
            }
        } else {
            if (!fin && opcode === opcodes.continuation) {
                // continuation frame
                // append the payload to the current fragments' payload
                this._parsed["payload data"] = concatenate(this._parsed["payload data"], parsed["payload data"]);
                return;
            } else if (fin && opcode === opcodes.continuation) {
                // last fragmented frame
                // append the payload to the current fragments' payload
                this._parsed["payload data"] = concatenate(this._parsed["payload data"], parsed["payload data"]);

                this._outputQueue.push(new Frame(
                    this._parsed["rsv1"] === 1,
                    this._parsed["rsv2"] === 1,
                    this._parsed["rsv3"] === 1,
                    this._parsed["opcode"],
                    this._parsed["payload data"],
                ));
                this._parsed = undefined;
                return;
            } else {
                throw `Error: FrameBuilder was given an out of order frame`;
            }
        }
    }

    /**
     * Return the next websocket frame.
     * @returns {Uint8Array | undefined} an unfragmented websocket frame
     *  or undefined if no frame is ready.
     */
    get() {
        return this._outputQueue.shift();
    }

    /**
     * Parse a websocket frame into key-value fields.
     * Do not decode payload if masked.
     * 
     * @private
     * @param {Uint8Array} frame an encapsulated websocket frame, or undefined if error
     * @returns dictionnary of fields and fields values of the encapsulated packet, or undefined if packet is invalid
     *      keys are a subset of ['fin', 'rsv1', 'rsv2', 'rsv3', 'opcode', 'mask', 'Payload Len', 'masking-key', 'payload data']
     *      or undefined if the frame is bogus
     */
    static _fields(frame) {
        let parsed = {};
        let restLen = frame.byteLength;
        if (restLen < 2) {
            // bogus frame
            return undefined;
        }

        let byteIterator = frame.entries();

        // first byte
        const bits0 = (byteIterator.next().value[1]).toString(2).padStart(8, '0').split('').map(c => c === "1" ? 1 : 0);
        parsed["fin"] = bits0[0];
        parsed["rsv1"] = bits0[1];
        parsed["rsv2"] = bits0[2];
        parsed["rsv3"] = bits0[3];
        parsed["opcode"] = parseInt(bits0.slice(4, 8).join(''), 2);
        restLen--;

        // second byte
        const bits1 = (byteIterator.next().value[1]).toString(2).padStart(8, '0').split('').map(c => c === "1" ? 1 : 0);
        parsed["mask"] = bits1[0];
        parsed["payload len"] = parseInt(bits1.slice(1, 8).join(''), 2);
        restLen--;

        // rest

        if (parsed["payload len"] == 126) {
            // if 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length
            if (restLen < 2) {
                console.warn("error: received websocket frame with incorrect 'payload len'");
                return undefined;
            }
            let pLen = (byteIterator.next().value[1]).toString(2).padStart(8, '0').split('');
            pLen = pLen.concat((byteIterator.next().value[1]).toString(2).padStart(8, '0').split(''));
            parsed["payload len"] = parseInt(pLen.join(""), 2);
            restLen -= 2;
        } else if (parsed["payload len"] == 127) {
            // if 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length
            if (restLen < 8) {
                console.warn("error: received websocket frame with incorrect 'payload len'");
                return undefined;
            }
            let pLenBits = [];
            for (let i = 0; i < 8; i++) {
                pLenBits = pLenBits.concat((byteIterator.next().value[1]).toString(2).padStart(8, '0').split(''));
            }
            parsed["payload len"] = parseInt(pLenBits.join(""), 2);
            restLen -= 8;
        }

        if (parsed["mask"]) {
            // next 4 bytes is the masking key
            if (restLen < 4) {
                console.warn("error: received websocket frame with masking");
                return undefined;
            }
            let maskingKeyBits = "";
            for (let i = 0; i < 4; i++) {
                maskingKeyBits += (byteIterator.next().value[1]).toString(2).padStart(8, '0');
            }
            parsed["masking-key"] = parseInt(maskingKeyBits, 2);
            restLen -= 4;
        }

        if (restLen <= 0) {
            parsed["payload data"] = new Uint8Array(0);
        } else {
            // parsed["payload data"] = frame.slice(-restLen);
            parsed["payload data"] = frame.slice(-parsed["payload len"]);
        }

        return parsed;
    }

}
