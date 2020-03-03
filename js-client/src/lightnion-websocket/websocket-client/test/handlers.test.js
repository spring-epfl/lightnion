// Tests for websocket packet handlers

import { assert } from "chai";
import { MockWebSocket } from "./mock-websocket";
import * as wspackets from "../packets.js";
import { FrameDefragmenter } from "../defragmenter.js";
import { onOpenMessage } from "../handlers.js";
import naclutil from "tweetnacl-util";

describe("open message handler", function () {

    let socket;
    let ws;
    let url;
    let nullKey = new Uint8Array(4);

    this.beforeEach(function () {
        url = "ws://example.com/";
        ws = new MockWebSocket(url);
        socket = ws._socket;
        socket.onmessage = onOpenMessage(ws, true);
    });

    it('should send back a pong when a ping is received, with the same empty payload', function () {
        let defrag = new FrameDefragmenter();

        const payload = new Uint8Array(0);
        socket.receive(wspackets.pingFrame(payload));

        defrag.add(wspackets.pongFrame(payload));

        const expectedResponse = defrag.get();
        assert.exists(expectedResponse);

        assert.equal(socket.sentMessages.length, 1);

        defrag.add(socket.sentMessages[0]);
        const actualResponse = defrag.get();
        assert.exists(actualResponse);

        assert.equal(actualResponse.opcode, expectedResponse.opcode, `websocket should have sent a pong frame upon reception of a ping frame`);
        assert.deepEqual(actualResponse.payload, expectedResponse.payload, `websocket should have sent a pong frame of same payload upon reception of a ping frame`);
    });

    it('should send back a pong when a ping is received, with the same non-empty payload', function () {
        let defrag = new FrameDefragmenter();

        const payload = Uint8Array.from([1, 2, 3, 4]);
        socket.receive(wspackets.pingFrame(payload, nullKey));

        defrag.add(wspackets.pongFrame(payload, nullKey));

        const expectedResponse = defrag.get();
        assert.exists(expectedResponse);
        assert.equal(socket.sentMessages.length, 1);
        defrag.add(socket.sentMessages[0]);
        const actualResponse = defrag.get();
        assert.exists(actualResponse);

        assert.equal(actualResponse.opcode, expectedResponse.opcode, `websocket should have sent a pong frame upon reception of a ping frame`);
        assert.deepEqual(actualResponse.payload, expectedResponse.payload, `websocket should have sent a pong frame of same payload upon reception of a ping frame`);
    });

    it('should close the connection correctly when a close frame is received with no payload, while the closing handshake has not been started ', function () {
        ws._the_websocket_closing_handshake_is_started = false;
        let defrag = new FrameDefragmenter();
        const status = 1000;

        socket.receive(wspackets.closeFrame(status, undefined, nullKey));

        assert.isTrue(socket.closed, "expected websocket to close underlying socket");
        assert.equal(ws.readyState, MockWebSocket.CLOSED, "expected websocket to enter CLOSING state");
        defrag.add(wspackets.closeFrame(status, undefined, nullKey));
        const expectedResponse = defrag.get();

        assert.equal(socket.sentMessages.length, 1);
        defrag.add(socket.sentMessages[0]);
        const actualResponse = defrag.get();

        assert.exists(actualResponse);

        assert.equal(actualResponse.opcode, expectedResponse.opcode, 'websocket should have sent the same close frame upong reception of a close frame');
        assert.deepEqual(actualResponse.payload, expectedResponse.payload, 'websocket should have sent the same close frame upong reception of a close frame');
    });


    it('should close the connection correctly when a close frame is received with no payload, while the closing handshake has been started', function () {
        ws._the_websocket_closing_handshake_is_started = true;

        const status = 1000;

        socket.receive(
            wspackets.closeFrame(status)
        );

        assert.isTrue(socket.closed, "expected websocket to close underlying socket");
        assert.equal(ws.readyState, MockWebSocket.CLOSED, "expected websocket to enter CLOSING state");

        assert.isEmpty(socket.sentMessages,
            `websocket should not send packets once the closing handshake has been started  `);
    });


    it('should handle non-fragmented data frames correctly', function () {
        const text = "this is a text frame's payload";

        let received = [];
        ws.onmessage = (event) => {
            received.push(event.data);
        };

        socket.onmessage = onOpenMessage(ws);

        socket.receive(wspackets.textFrame(text, nullKey));

        assert.deepInclude(received, text);
        assert.equal(received.length, 1, "websocket should not have received more messages than sent");
    });

    it('should handle fragmented data frames correctly', function () {
        const text = "this is a text frame's payload";
        const payload = naclutil.decodeUTF8(text);
        const chunkSize = 4;

        let received = [];
        ws.onmessage = (event) => {
            received.push(event.data);
        };

        socket.onmessage = onOpenMessage(ws);

        // construct and send fragments in order
        let frame = new wspackets.Frame(false, false, false, wspackets.opcodes.text, payload);
        frame.fragment(chunkSize, nullKey).forEach((pkt) => {
            socket.receive(pkt);
        });

        // expect to have received one packet containing the whole text
        assert.deepInclude(received, text);
        assert.equal(received.length, 1, "websocket should not have received more messages than sent");
    });

    it('should handle fragmented data frames correctly with control frame received inbetween fragments', function () {
        const text = "this is a text frame's payload";
        const payload = naclutil.decodeUTF8(text);
        const chunkSize = 4;
        const chunks = Math.ceil(text.length / chunkSize);

        assert(chunks == 8);

        let received = [];
        ws.onmessage = (event) => {
            received.push(event.data);
        };

        socket.onmessage = onOpenMessage(ws, true);

        // construct and send fragments in order
        let frame = new wspackets.Frame(false, false, false, wspackets.opcodes.text, payload);
        let fragments = frame.fragment(chunkSize, nullKey);

        for (let i = 0; i < fragments.length; i++) {
            if (i == 4) {
                // send a ping frame in-between data frames
                socket.receive(wspackets.pingFrame([], nullKey));
            }
            socket.receive(fragments[i]);
        }

        // expect to have received one packet containing the whole text, and one ping packet
        // and expect to have sent a pong packet in response to the ping
        const expectedPong = wspackets.pongFrame([], nullKey);
        assert.deepInclude(received, text);
        assert.equal(received.length, 1, "websocket should have received exaclty one defragmented packets");
        assert.equal(socket.sentMessages.length, 1, "websocket should have sent only one frame");
        let sent = socket.sentMessages[0];
        assert.deepEqual(sent, expectedPong, "websocket should have sent a pong frame upong reception of a ping frame, inbetween data fragments");
    });
});