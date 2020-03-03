import { maskWithKey } from "./utils.js";

/**
 * The interface between a stream-oriented socket to a WebSocket.
 * Reconstruct websocket frames from stream messages.
 * 
 * To be used when receiving data from the TCP stream,
 * feed this data into the add() method,
 * and use get() method to poll for ready frames.
 * 
 * @private
 */
export class StreamHandler {
    constructor() {
        // the queue containing ready websocket frames
        this._outputQueue = [];
        // the buffer containing remaining bytes to be consumed
        // invariant: the start of the buffer corresponds to the start of a websocket frame
        this._buffer = [];
    }

    /**
     * Add a received packet.
     * After this call, zero, one or more frames may be used by calling get() multiple times.
     * @param {Uint8Array} data raw data taken from the streaming socket
     */
    add(data) {
        this._buffer.push(...data);

        // consume buffer to add new ready frames to the output queue
        let frame;
        while ((frame = this._consume()) !== undefined) {
            this._outputQueue.push(frame);
        }
    }

    /**
     * Return the next websocket frame.
     * @returns {Uint8Array | undefined} a raw websocket frame
     *  or undefined if no frame is ready.
     */
    get() {
        return this._outputQueue.shift();
    }


    /**
     * Try to consume buffer into a websocket frame.
     * @returns {Uint8Array} the websocket frame constructed, or undefined if not successful
     */
    _consume() {
        // check if we have a full frame header in the buffer
        const headerLen = nextHeaderLength(this._buffer);
        if (headerLen === 0) {
            return undefined;
        }

        // we have a full frame header available
        // parse it to get the payload length
        const payloadLen = headerPayloadLength(this._buffer.slice(0, headerLen));

        // check if we have the payload ready in the buffer
        if (this._buffer.length < (headerLen + payloadLen)) {
            return undefined;
        }

        // we can extract a frame from the buffer
        let rawFrame = this._buffer.splice(0, headerLen + payloadLen);

        // unmask if needed
        let frame = unmaskFrame(rawFrame, headerLen);

        return new Uint8Array(frame);
    }
}

/**
 * Unmask websocket frame if needed.
 * 
 * @param {Array} frame byte array
 * @param {number} headerLen the length of the header in the frame
 * @returns {Array} the unmasked frame
 * @private
 */
function unmaskFrame(frame, headerLen) {
    const pLen = frame[1] & 127;

    let maskIndex;
    if (pLen < 126) {
        maskIndex = 2;
    } else if (pLen === 127) {
        maskIndex = 4;
    } else {
        maskIndex = 10;
    }
    let maskingKey = frame.slice(maskIndex, maskIndex + 4);

    const payload = maskWithKey(frame.slice(headerLen), maskingKey);

    frame.slice(0, headerLen).push(...payload);

    return frame;
}

/**
 * Returns the payload length from a frame header.
 * @param {Array} header the input header, assumed valid and no extra bytes, only contains bytes
 * @returns {number} the length of the payload associated with the header
 * @private
 */
function headerPayloadLength(header) {
    const pLen = header[1] & 127; // 7 last bits of 2nd byte

    if (pLen < 126) {
        return pLen;
    } else if (pLen === 126) {
        // if 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length
        return (header[2] << 8) + header[3];
    } else if (pLen === 127) {
        // if 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length
        let len = 0;

        for (let i = 0; i < 8; i++) {
            len += (header[2 + i] << (8 * (7 - i)));
        }
        return len;
    }
}

/**
 * Try to read a header from the start of the input buffer.
 * @param {Array} data input buffer, contaning only bytes
 * @returns {boolean} the byte length of the header contained in the start of the input buffer if any, 0 otherwise
 * @private
 */
function nextHeaderLength(data) {
    // a frame header is between 2 and 12 bytes long
    if (data.length < 2) { return 0; }

    const mask = (data[1] & 128) === 128; // mask is true if mask is set in header
    const payloadLen = data[1] & 127; // 7 last bits of 2nd byte

    // now check all the cases...

    if (!mask && payloadLen < 126) {
        // header length is 2B
        return 2;
    } else if (!mask && payloadLen === 126) {
        // header length is (2 + 2) = 4B
        if (data.length < 4) { return 0; } else { return 4; }
    } else if (!mask && payloadLen === 127) {
        // header length is (2 + 8) = 10B
        if (data.length < 10) { return 0; } else { return 10; }
    } else if (mask && payloadLen < 126) {
        // header length is (2 + 4) = 6B
        if (data.length < 6) { return 0; } else { return 6; }
    } else if (mask && payloadLen === 126) {
        // header length is (2 + 2 + 4) = 8B
        if (data.length < 8) { return 0; } else { return 8; }
    } else if (mask && payloadLen === 127) {
        // header length is (2 + 8 + 4) = 14B
        if (data.length < 14) { return 0; } else { return 14; }
    }
}

