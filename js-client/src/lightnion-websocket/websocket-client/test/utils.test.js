import { assert } from "chai";
import { parseURL, maskWithKey } from "../utils.js";

describe("maskWithKey", function () {
    it("should be involutory", function () {
        const key = new Uint8Array([5, 3, 2, 12]);

        const payloads = [
            new Uint8Array([1, 2, 3, 4, 5, 6, 7]),
            new Uint8Array([]),
            new Uint8Array([0, 0, 0]),
            new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        ];

        payloads.forEach(payload => {
            let decoded = maskWithKey(maskWithKey(payload, key), key);
            assert.deepEqual(decoded, payload);
        });
    });
});

describe("parseURL", function () {
    /**
     * See https://www.w3.org/TR/2012/CR-websockets-20120920/#parse-a-websocket-url-s-components
     */

    // it("should fail on relative url", function () {
    //     // TODO
    // });

    it("should fail if scheme is not websocket", function () {
        let url = new URL("http://127.0.0.1:8080/");
        let p = () => parseURL(url);
        assert.throws(p);
    });

    it("should fail if url has a fragment", function () {
        let url = new URL("ws://localhost:8080/that#thing");
        let p = () => parseURL(url);
        assert.throws(p);
    });

    it("should set secure to false for ws: scheme", function () {
        let url = new URL("ws://localhost:443/");
        let secure = parseURL(url)[3];
        assert.isFalse(secure);
    });

    it("should set secure to true for wss: scheme", function () {
        let url = new URL("wss://localhost/");
        let secure = parseURL(url)[3];
        assert.isTrue(secure);
    });

    it("should set host as the url host in lowercase", function () {
        let url = new URL("wss://MY.HOST.COM/path");
        let host = parseURL(url)[0];
        assert.equal("my.host.com", host);
    });

    it("should set port as the url port", function () {
        let url = new URL("ws://localhost:443/");
        let port = parseURL(url)[1];
        assert.equal(port, 443);
    });


    it("should set port implicitely according to scheme", function () {
        let url = new URL("ws://localhost/");
        let port = parseURL(url)[1];
        assert.equal(port, 80);
    });

    it("should set port implicitely according to scheme", function () {
        let url = new URL("wss://localhost/");
        let port = parseURL(url)[1];
        assert.equal(port, 443);
    });

    it("should set ressourceName as the path of url", function () {
        let url = new URL("ws://localhost/this/is/the/path");
        let ressourceName = parseURL(url)[2];
        assert.equal(ressourceName, "/this/is/the/path");
    });

    it("should set ressourceName to default if url path is empty", function () {
        let url = new URL("ws://localhost");
        let ressourceName = parseURL(url)[2];
        assert.equal(ressourceName, "/");
    });

    it("should have a single question mark followed by the query component in ressourceName if the url has a query component", function () {
        // FIXME
        let url = new URL("ws://localhost/?this=that&other=it");
        let ressourceName = parseURL(url)[2];
        assert.equal(ressourceName, "/?this=that&other=it");
    });
});

