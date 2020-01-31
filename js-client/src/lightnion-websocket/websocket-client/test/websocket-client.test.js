// Tests for WebSocketClient.
// Tests ensuring that WebSocketClient implements the standardized interface.
// See: https://www.w3.org/TR/websockets/#the-websocket-interface 

import { WebSocketClient, binaryTypes } from "../websocket-client.js";
import { assert } from "chai";
import * as _ from "lodash";
import { MessageEventClass } from "../mocks.js";

const Blob = require("cross-blob");

describe("WebSocket interface", function () {

    let testUrlString;
    let testWS;
    let testHandler;

    before(function () {
        testUrlString = "ws://example.com/";
        testWS = new WebSocketClient(testUrlString);
        testHandler = () => { };
    });

    it("can be imported", function () {
        assert.exists(WebSocketClient);
    });

    it("should have a readonly DOMString attribute 'url'", function () {
        assert.property(testWS, "url");
        assert.equal(testWS.url, testUrlString);
        assert.isTrue(_.isString(testWS.url));
        assert.throws(() => { testWS.url = undefined; }, TypeError);
    });

    it("should have defined ready state constants", function () {
        assert.equal(WebSocketClient.CONNECTING, 0);
        assert.equal(WebSocketClient.OPEN, 1);
        assert.equal(WebSocketClient.CLOSING, 2);
        assert.equal(WebSocketClient.CLOSED, 3);
    });

    it("should have a readonly unsigned short attribute 'readyState'", function () {
        assert.property(testWS, "readyState");
        assert.isNumber(testWS.readyState);
        assert.oneOf(testWS.readyState, [0, 1, 2, 3]);
        assert.throws(() => { testWS.readyState = undefined; }, TypeError);
    });

    it("should have a readonly unsigned long attribute 'bufferedAmount'", function () {
        assert.property(testWS, "bufferedAmount");
        assert.isNumber(testWS.bufferedAmount);
        assert.isAtLeast(testWS.bufferedAmount, 0);
        assert.throws(() => { testWS.bufferedAmount = undefined; }, TypeError);
    });

    it("should have an EventHandler attribute 'onopen'", function () {
        assert.property(testWS, "onopen");
        assert.isTrue(_.isFunction(testWS.onopen));
        // should be able to set it
        testWS.onopen = testHandler;
        assert.equal(testWS.onopen, testHandler);
    });

    it("should have an EventHandler attribute 'onerror'", function () {
        assert.property(testWS, "onerror");
        assert.isTrue(_.isFunction(testWS.onerror));
        // should be able to set it
        testWS.onerror = testHandler;
        assert.equal(testWS.onerror, testHandler);
    });

    it("should have an EventHandler attribute 'onclose'", function () {
        assert.property(testWS, "onclose");
        assert.isTrue(_.isFunction(testWS.onclose));
        // should be able to set it
        testWS.onclose = testHandler;
        assert.equal(testWS.onclose, testHandler);
    });

    it("should have an EventHandler attribute 'onmessage'", function () {
        assert.property(testWS, "onmessage");
        assert.isTrue(_.isFunction(testWS.onmessage));
        // should be able to set it
        testWS.onmessage = testHandler;
        assert.equal(testWS.onmessage, testHandler);
    });

    it("should have a readonly DOMString attribute 'extensions'", function () {
        assert.property(testWS, "extensions");
        assert.isTrue(_.isString(testWS.extensions));
        assert.throws(() => { testWS.extensions = undefined; }, TypeError);
    });

    it("should have a readonly DOMString attribute 'protocol'", function () {
        assert.property(testWS, "protocol");
        assert.isTrue(_.isString(testWS.protocol));
        assert.throws(() => { testWS.protocol = undefined; }, TypeError);
    });

    it("should have a 'close' method", function () {
        assert.property(testWS, "close");
        assert.isTrue(_.isFunction(testWS.close));
    });

    it("should have a DOMString attribute 'binaryType'", function () {
        assert.property(testWS, "binaryType");
        assert.oneOf(testWS.binaryType, ["blob", "arraybuffer"]);

        // should be able to set it if acceptable value
        testWS.binaryType = "arraybuffer";
        assert.equal(testWS.binaryType, "arraybuffer");
        testWS.binaryType = "blob";
        assert.equal(testWS.binaryType, "blob");
        assert.throws(() => { testWS.binaryType = ""; }, SyntaxError);
    });

    it("should have a 'send' method", function () {
        assert.property(testWS, "send");
        assert.isTrue(_.isFunction(testWS.send));
    });

});


describe("WebSocket events", function () {
    let testUrlString;
    let testWS;

    beforeEach(function () {
        testUrlString = "ws://example.com/";
        testWS = new WebSocketClient(testUrlString);
    });

    it("should trigger a message event with a text data, when a message is received", function (done) {
        testWS._readyState = WebSocketClient.OPEN;
        const data = new Uint8Array(65, 66, 67, 68);
        testWS.addEventListener("message", (event) => {
            assert.deepEqual(event.data, data);
            done();
        });
        // send message to the websocket
        testWS._received(new MessageEventClass("message", { data: data }));
    });

    it("should trigger a message event with a blob data if binaryType was set to blob, when a message is received", function (done) {
        testWS._readyState = WebSocketClient.OPEN;
        testWS.binaryType = binaryTypes.blob;
        const data = new Uint8Array(65, 66, 67, 68);
        testWS.addEventListener("message", (event) => {
            assert.isTrue(event.data instanceof Blob);
            assert.deepEqual(event.data, new Blob(data));
            done();
        });
        // send message to the websocket
        testWS._received(new MessageEventClass("message", { data: new Blob([data]) }));
    });

    it("should trigger a message event with an arraybuffer data if binaryType was set to arraybuffer, when a message is received", function (done) {
        testWS._readyState = WebSocketClient.OPEN;
        testWS.binaryType = binaryTypes.arraybuffer;
        const data = new Uint8Array(65, 66, 67, 68);
        testWS.addEventListener("message", (event) => {
            assert.isTrue(event.data instanceof ArrayBuffer);
            assert.deepEqual(event.data, data.buffer);
            done();
        });
        // send message to the websocket
        testWS._received(new MessageEventClass("message", { data: data.buffer }));
    });


    it("should trigger a close event when asked to close", function (done) {
        testWS._readyState = WebSocketClient.OPEN;
        testWS.addEventListener("close", () => {
            done();
        });
        testWS._close_the_websocket_connection();
    });


});