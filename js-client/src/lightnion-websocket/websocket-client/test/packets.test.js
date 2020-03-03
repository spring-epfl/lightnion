// Tests for websocket packets

import { assert } from "chai";
import { parseURL } from "../utils.js";
import { parseHeaders, parseRequestLine } from "../../http/parsing.js";
import * as wspackets from "../packets.js";
import { FrameDefragmenter } from "../defragmenter.js";
import * as http from "../../http/http.js";
import naclutil from "tweetnacl-util";

describe("clientHandshake", function () {
    /**
     * See RFC 6455 4.
     */

    it("should be a HTTP GET request of version at least 1.1", function () {
        let url = new URL("ws://example.com/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs] = wspackets.clientHandshake(host, port, resourceName);
        let [method, , version] = parseRequestLine(hs.split("\r\n")[0]);

        // check status-code
        assert.equal(method, http.methods.GET);

        // check version
        let versionFloat = parseFloat(version.replace("HTTP/", ""));
        if (isNaN(versionFloat)) {
            throw `could not parse request line from ${hs}: version is not of the form 'HTTP/...'`;
        }

        assert.isAtLeast(versionFloat, 1.1);
    });

    it("should have the request-uri match the ressource name", function () {
        let url = new URL("ws://example.com/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs] = wspackets.clientHandshake(host, port, resourceName);
        let [, requestURI] = parseRequestLine(hs.split("\r\n")[0]);

        assert.equal(requestURI, "/chat");
    });

    it("should contain a 'host' header", function () {
        let url = new URL("ws://example.com:1234/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs] = wspackets.clientHandshake(host, port, resourceName);

        let headers = hs.split("\r\n").slice(1).join("\r\n");
        let parsed = parseHeaders(headers);

        assert.equal(parsed["host"], "example.com:1234");
    });

    it("should contain contain an 'upgrade' header field with value containing 'websocket'", function () {
        let url = new URL("ws://example.com:1234/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs] = wspackets.clientHandshake(host, port, resourceName);

        let headers = hs.split("\r\n").slice(1).join("\r\n");
        let parsed = parseHeaders(headers);

        assert.include(parsed["upgrade"], "websocket");
    });

    it("shoud contain a 'connection' header field with value containing 'upgrade'", function () {
        let url = new URL("ws://example.com:1234/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs] = wspackets.clientHandshake(host, port, resourceName);

        let headers = hs.split("\r\n").slice(1).join("\r\n");
        let parsed = parseHeaders(headers);

        assert.include(parsed["upgrade"], "websocket");
    });

    it("shoud contain a 'sec-websocket-key' header field", function () {
        let url = new URL("ws://example.com:1234/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs, nonce] = wspackets.clientHandshake(host, port, resourceName);
        let nonceB64 = naclutil.encodeBase64(nonce);

        let headers = hs.split("\r\n").slice(1).join("\r\n");
        let parsed = parseHeaders(headers);

        assert.equal(parsed["sec-websocket-key"], nonceB64);
    });

    it("should contain a 'origin' header field (browser client)", function () {
        let url = new URL("ws://example.com:1234/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs] = wspackets.clientHandshake(host, port, resourceName);

        let headers = hs.split("\r\n").slice(1).join("\r\n");
        let parsed = parseHeaders(headers);

        assert.equal(parsed["origin"], "example.com");
    });

    it("should contain a 'sec-websocket-version' header field with value '13'", function () {
        let url = new URL("ws://example.com:1234/chat");
        let [host, port, resourceName] = parseURL(url);
        let [hs] = wspackets.clientHandshake(host, port, resourceName);

        let headers = hs.split("\r\n").slice(1).join("\r\n");
        let parsed = parseHeaders(headers);

        assert.equal(parsed["sec-websocket-version"], "13");
    });

    it("should contain a 'sec-websocket-protocol' field with comma separated values", function () {
        let url = new URL("ws://example.com:1234/chat");
        let [host, port, resourceName] = parseURL(url);
        let protocols = ["rfb", "sip"];
        let [hs] = wspackets.clientHandshake(host, port, resourceName, protocols);

        let headers = hs.split("\r\n").slice(1).join("\r\n");
        let parsed = parseHeaders(headers);

        assert.equal(parsed["sec-websocket-protocol"], "rfb, sip");
    });

});

describe("ws packet encapsulation", function () {
    it("import", function () {
        assert.ok(wspackets.Frame._encapsulate);
    });

    it("encapsulates small packets", function () {
        const payloads = [
            ``,
            `small`,
            new Array(1 + 1).join('#'),
            new Array(10 + 1).join('#'),
            new Array(100 + 1).join('#'),
        ];

        payloads.forEach(payload => {
            const payloadEncoded = naclutil.decodeUTF8(payload);
            const pkt = wspackets.Frame._encapsulate(payloadEncoded, "1000", 1, new Uint8Array(4));
            assert.ok(pkt);

            const defrag = new FrameDefragmenter();
            defrag.add(pkt);

            const parsed = defrag.get();

            assert.ok(parsed);
            assert.deepEqual(parsed.payload, payloadEncoded);
        });
    });

    it("encapsulates medium packets", function () {
        const payloads = [
            `this should be a payload of at least 126 bytes and less than 65536 bytes.
            ----------------------------------------------------------------------------------------`,
            new Array(200 + 1).join('#'),
            new Array(500 + 1).join('#'),
            new Array(1000 + 1).join('#'),
            new Array(5000 + 1).join('#'),
            new Array(10000 + 1).join('#'),
            new Array(50000 + 1).join('#'),
        ];

        payloads.forEach(payload => {
            const payloadEncoded = naclutil.decodeUTF8(payload);
            const pkt = wspackets.Frame._encapsulate(payloadEncoded, "1000", 1, new Uint8Array(4));
            assert.ok(pkt);
            const defrag = new FrameDefragmenter();
            defrag.add(pkt);
            const parsed = defrag.get();
            assert.ok(parsed);
            assert.deepEqual(parsed.payload, payloadEncoded);
        });
    });

    it("encapsulates large packets", function () {
        const fragmentSize = 1000;
        const payloads = [
            new Array(65536 + 1).join('#'),
            new Array(65537 + 1).join('#'),
            new Array(100000 + 1).join('#'),
        ];

        payloads.forEach(payload => {
            // create packets
            const payloadEncoded = naclutil.decodeUTF8(payload);
            const frame = new wspackets.Frame(false, false, false, wspackets.opcodes.text, payloadEncoded);
            const fragments = frame.fragment(1000, new Uint8Array(4));
            assert.equal(fragments.length, Math.ceil(payload.length / fragmentSize));

            let defrag = new FrameDefragmenter();
            // parse packets
            fragments.forEach(pkt => {
                defrag.add(pkt);
            });

            let parsed = defrag.get();
            assert.ok(parsed);
            assert.equal(parsed.opcode, frame.opcode);
            assert.deepEqual(parsed.payload, frame.payload);
        });
    });

    it("should compute the masked payload correctly for a null key", function () {
        const key = new Uint8Array(4);
        const payload = naclutil.decodeUTF8("test string");
        const pkt = wspackets.Frame._encapsulate(payload, "1000", 1, key);

        const defrag = new FrameDefragmenter();
        defrag.add(pkt);

        const parsed = defrag.get();

        assert.ok(parsed);
        assert.deepEqual(parsed.payload, payload);
    });

});

describe("isControlFrame", function () {

    it("should be correct for expected opcodes", function () {
        assert.equal(wspackets.isControlFrame(wspackets.opcodes.continuation), false);
        assert.equal(wspackets.isControlFrame(wspackets.opcodes.text), false);
        assert.equal(wspackets.isControlFrame(wspackets.opcodes.binary), false);
        assert.equal(wspackets.isControlFrame(wspackets.opcodes.close), true);
        assert.equal(wspackets.isControlFrame(wspackets.opcodes.ping), true);
        assert.equal(wspackets.isControlFrame(wspackets.opcodes.pong), true);
    });
});
