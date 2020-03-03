// Tests for stream data to websocket frames

import { assert } from "chai";
import { StreamHandler } from "../stream-handler.js";
import { Frame, opcodes } from "../packets";
import { concatenate } from "../utils.js";

describe("StreamHandler", function () {

    let streamHandler;
    const payload1 = new Uint8Array(Array.from(Array(50).keys()));
    const payload2 = new Uint8Array(Array.from(Array(20).keys()));
    const payload3 = new Uint8Array(Array.from(Array(40).keys()));
    const nullKey = new Uint8Array(4);

    beforeEach(function () {
        streamHandler = new StreamHandler();
    });

    it("should handle a single packet", function () {
        const orig = Frame._encapsulate(payload1, "1000", opcodes.binary, nullKey);

        streamHandler.add(orig);
        let frame = streamHandler.get();

        assert.ok(frame);
        assert.deepEqual(frame.payload, orig.payload);
    });


    it("should handle a packet split into two", function () {
        const orig = Frame._encapsulate(payload1, "1000", opcodes.binary, nullKey);

        let middle = Math.ceil(orig.length / 2);

        let origPart1 = orig.slice(0, middle);
        let origPart2 = orig.slice(middle);

        let frame;

        frame = streamHandler.get();
        assert.notOk(frame);

        streamHandler.add(origPart1);
        frame = streamHandler.get();
        assert.notOk(frame);

        streamHandler.add(origPart2);
        frame = streamHandler.get();
        assert.ok(frame);

        assert.deepEqual(frame.payload, orig.payload);
    });

    it("should handle packet split into three", function () {
        const orig = Frame._encapsulate(payload1, "1000", opcodes.binary, nullKey);

        let origPart1 = orig.slice(0, Math.ceil(orig.length / 3));
        let origPart2 = orig.slice(Math.ceil(orig.length / 3), Math.ceil(2 * orig.length / 3));
        let origPart3 = orig.slice(Math.ceil(2 * orig.length / 3));

        let frame;

        frame = streamHandler.get();
        assert.notOk(frame);

        streamHandler.add(origPart1);
        frame = streamHandler.get();
        assert.notOk(frame);

        streamHandler.add(origPart2);
        frame = streamHandler.get();
        assert.notOk(frame);

        streamHandler.add(origPart3);
        frame = streamHandler.get();
        assert.ok(frame);

        assert.deepEqual(frame.payload, orig.payload);

    });

    it("should handle stream of split packets one by one", function () {
        // here we send 3 packets, as 5 packets
        // payloads are split/merged approximately like this:
        // [111] | [111222] | [222] | [222222333] | [333]
        const orig1 = Frame._encapsulate(payload1, "1000", opcodes.binary, nullKey);
        const orig2 = Frame._encapsulate(payload2, "1000", opcodes.binary, nullKey);
        const orig3 = Frame._encapsulate(payload3, "1000", opcodes.binary, nullKey);

        let split1 = orig1.slice(0, Math.ceil(orig1.length / 2));
        let split2 = concatenate(
            orig1.slice(Math.ceil(orig1.length / 2)),
            orig2.slice(0, Math.ceil(orig2.length / 4)));
        let split3 = orig2.slice(Math.ceil(orig2.length / 4), Math.ceil(2 * orig2.length / 4));
        let split4 = concatenate(
            orig2.slice(Math.ceil(2 * orig2.length / 4)),
            orig3.slice(0, Math.ceil(orig3.length / 2)));
        let split5 = orig3.slice(Math.ceil(orig3.length / 2));

        let frames = [];

        streamHandler.add(split1);
        assert.notOk(streamHandler.get());
        streamHandler.add(split2);
        frames.push(streamHandler.get());
        streamHandler.add(split3);
        assert.notOk(streamHandler.get());
        streamHandler.add(split4);
        frames.push(streamHandler.get());
        streamHandler.add(split5);
        frames.push(streamHandler.get());

        assert.deepEqual(frames, [orig1, orig2, orig3]);
    });

    it("should handle stream of split packets in bulk", function () {
        const orig1 = Frame._encapsulate(payload1, "1000", opcodes.binary, nullKey);
        const orig2 = Frame._encapsulate(payload2, "1000", opcodes.binary, nullKey);
        const orig3 = Frame._encapsulate(payload3, "1000", opcodes.binary, nullKey);

        let split1 = orig1.slice(0, Math.ceil(orig1.length / 2));
        let split2 = concatenate(
            orig1.slice(Math.ceil(orig1.length / 2)),
            orig2.slice(0, Math.ceil(orig2.length / 4)));
        let split3 = orig2.slice(Math.ceil(orig2.length / 4), Math.ceil(2 * orig2.length / 4));
        let split4 = concatenate(
            orig2.slice(Math.ceil(2 * orig2.length / 4)),
            orig3.slice(0, Math.ceil(orig3.length / 2)));
        let split5 = orig3.slice(Math.ceil(orig3.length / 2));

        let splits = [split1, split2, split3, split4, split5];
        splits.forEach(s => streamHandler.add(s));

        let frames = [];
        let frame;
        while ((frame = streamHandler.get()) !== undefined) {
            frames.push(frame);
        }

        assert.deepEqual(frames, [orig1, orig2, orig3]);
    });


});