/**
 * Packet handling for WebSockets.
 */

import * as wspackets from "./packets.js";
import { binaryTypes } from "./websocket-client.js";
import { MessageEventClass } from "./mocks.js";
import naclutil from "tweetnacl-util";

/**
 * Return a handler for received websocket packets when in connecting state, for given WebSocket.
 * @param {WebSocket} ws websocket handling the packets.
 * @private
 */
export function onConnectingMessage() {
    return (request) => {
        console.warn(`received message while in connecting state: ${request}`);
    };
}

/**
 * Return a handler for recevied bwesocket packets when in closing state, for given WebSocket.
 * @param {WebSocket} ws websocket handling the packets.
 * @private
 */
export function onClosingMessage() {
    return (request) => {
        console.warn(`received message while in closing state: ${request}`);
    };
}

/**
 * Return a handler for recevied bwesocket packets when in closed state, for given WebSocket.
 * @param {WebSocket} ws websocket handling the packets.
 * @private
 */
export function onClosedMessage() {
    return (request) => {
        console.warn(`received message while in closed state: ${request}`);
    };
}

/**
 * Return a handler for received websocket packets when in open state, for given WebSocket.
 * @param {WebSocket} ws websocket handling the packets.
 * @param {Boolean} noMasking disable masking of frames sent, for testing purposes only
 * @private
 */
export function onOpenMessage(ws, noMasking = false) {
    return (pkt) => {

        // add the packet to the stream handler
        ws._streamHandler.add(pkt);

        let frame;
        // process all frames that are ready
        while ((frame = ws._streamHandler.get()) !== undefined) {
            ws._frameDefragmenter.add(frame);
        }

        while ((frame = ws._frameDefragmenter.get()) !== undefined) {
            if (wspackets.isControlFrame(frame.opcode)) {
                handleControlFrame(ws, frame, noMasking);
            } else {
                handleDataFrame(ws, frame);
            }
        }

    };
}

/**
 * Handle a data frame.
 * 
 * @param {WebSocket} ws websocket handling the frame
 * @param {Frame} dataFrame frame to handle
 * @private
 */
function handleDataFrame(ws, dataFrame) {
    if (dataFrame.payload === undefined) {
        return;
    }

    // wrap to event
    let eventData;
    try {
        if (dataFrame.opcode === wspackets.opcodes.text) {
            eventData = naclutil.encodeUTF8(dataFrame.payload);
        } else if (dataFrame.opcode === wspackets.opcodes.binary) {
            if (ws.binaryType === binaryTypes.blob) {
                eventData = new Blob([dataFrame.payload]);
            } else if (ws.binaryType === binaryTypes.arraybuffer) {
                eventData = dataFrame.payload.buffer;
            }
        } else {
            console.warn(`unknown opcode: ${dataFrame.opcode}, dropping frame`);
            return;
        }
    } catch (err) {
        console.warn(`error: tried to decode websocket data packet: ${err}`);
        return;
    }
    let event = new MessageEventClass(
        "message",
        {
            data: eventData,
            origin: ws._url.href,
            lastEventId: "", // TODO ?
            source: null, // TODO ?
            ports: [], // TODO ?
        }
    );

    ws._received(event);
    ws.__onmessage(event); // user defined handler
}

/**
 * Handle a control frame.
 * 
 * @param {WebSocket} ws websocket handling the frame
 * @param {Frame} controlFrame frame to handle
 * @param {Boolean} noMasking disable masking of frames sent, for testing purposes only
 * @private
 */
function handleControlFrame(ws, controlFrame, noMasking) {
    const payload = controlFrame.payload;
    switch (controlFrame.opcode) {
        case wspackets.opcodes.close: {
            // status and reason are parsed but not needed for now
            // the whole payload is echoed back
            let status = 1005;
            let reason = "";
            if (payload.length >= 2) {
                status = payload[0] << 8 + payload[1];
                let reasonBytes = payload.slice(2);
                if (reasonBytes.length > 0) {
                    // read reason
                    reason = naclutil.encodeUTF8(reasonBytes);
                }
            }

            if (!ws._the_websocket_closing_handshake_is_started) {
                // send back a close frame
                ws._closing();

                // if present, echo back status and reason
                // otherwise use defaults
                if (payload.length >= 2) {
                    // 2-byte unsigned integer
                    status = (payload[0] << 8) + payload[1];
                    if (payload.length > 2) {
                        reason = naclutil.encodeUTF8(payload.slice(2));
                    }
                }

                if (noMasking) {
                    ws._socket.send(wspackets.closeFrame(status, reason, new Uint8Array(4)));
                } else {
                    ws._socket.send(wspackets.closeFrame(status, reason));
                }
                // end of the closing handshake
                ws._close_the_websocket_connection();
            } else {
                // end of the closing handshake
                ws._close_the_websocket_connection();
            }
            break;
        }
        case wspackets.opcodes.ping: {
            // send back a pong frame, with received (decoded) payload if any
            if (noMasking) {
                ws._socket.send(wspackets.pongFrame(payload, new Uint8Array(4)));
            } else {
                ws._socket.send(wspackets.pongFrame(payload));
            }
            break;
        }
        case wspackets.opcodes.pong:
            break;
        default:
            // not implemented or invalid
            break;
    }
    return;
}

