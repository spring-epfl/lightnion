// Tests for HTTP parsing functions.

import { assert } from "chai";
import { parseHeaders, parseStatusLine, parseRequestLine } from "../parsing.js";

describe("parseRequestLine", function () {
    it("should throw error on incorrect request lines", function () {
        let wrongStatus = [
            "MethodNotExisting / HTTP/1.1",
            "NoVersion /",
        ];

        wrongStatus.forEach(s => {
            assert.throws(() => parseStatusLine(s), ``,
                `incorrect request line '${s}' should have raised an error while parsing`);
        });

    });

    it("should parse correct request lines correctly", function () {
        let tt = new Map([
            ["GET / HTTP/1.1", ["GET", "/", "HTTP/1.1"]],
            ["POST /post.html HTTP/1.1", ["POST", "/post.html", "HTTP/1.1"]],
            ["GET / HTTP/1.1", ["GET", "/", "HTTP/1.1"]],
            ["PUT / HTTP/1.1", ["PUT", "/", "HTTP/1.1"]],
            ["DELETE / HTTP/1.1", ["DELETE", "/", "HTTP/1.1"]],
        ]);

        for (const [requestLine, expected] of tt.entries()) {
            let got = parseRequestLine(requestLine);
            assert.deepEqual(got, expected, "wrong parsed status line");
        }
    });
});

describe("parseStatusLine", function () {
    it("sould throw error on incorrect status line", function () {
        let wrongHeaders = [
            "HTTP/1.1 NOT-AN-INT REASOn",
            "",
            "HTTP/1.1",
            "HTTP/1.1 404",
            "404 NOT-FOUND",
        ];

        wrongHeaders.forEach(h => {
            assert.throws(() => parseStatusLine(h), ``,
                `incorrect status line '${h}' should have raised an error while parsing`);
        });
    });

    it("should parse correct status lines correctly", function () {
        let tt = new Map([
            ["HTTP/1.1 100 MESSAGE", ["HTTP/1.1", 100, "MESSAGE"]],
            ["HTTP/2 404 NOT-FOUND", ["HTTP/2", 404, "NOT-FOUND"]],
            ["HTTP/1 404 NOT-FOUND something-more", ["HTTP/1", 404, "NOT-FOUND something-more"]],
        ]);

        for (const [statusLine, expected] of tt.entries()) {
            let got = parseStatusLine(statusLine);
            assert.deepEqual(got, expected, "wrong parsed status line");
        }
    });



});

describe("parseHeaders", function () {
    it("should parse no headers", function () {
        let httpHeaders = "";
        let parsed = parseHeaders(httpHeaders);
        assert.isEmpty(parsed, "parsing no headers should output an empty object");
    });

    it("should parse host", function () {
        let httpHeaders = "Host: localhost:1234";
        let parsed = parseHeaders(httpHeaders);
        assert.equal(parsed["host"], "localhost:1234");
    });

    it("should parse multiple headers", function () {
        let httpHeaders = `Host: localhost:1234\r\n
            Content-Language: en\r\n
            Content-Length: 3495`;
        let parsed = parseHeaders(httpHeaders);
        assert.deepEqual(parsed, { "host": "localhost:1234", "content-language": "en", "content-length": "3495" });
    });
});
