// Tests for websocket packets utilities

import { assert } from "chai";
import naclutil from "tweetnacl-util";
import { verifySecWebSocketAccept } from "../packets-utils.js";

describe("verifySecWebSocketAccept", function () {

    it("should work on rfc example", function () {
        const key = naclutil.decodeBase64("dGhlIHNhbXBsZSBub25jZQ==");
        const resp = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert.isTrue(verifySecWebSocketAccept(key, resp));
    });

    it("should not work on bad inputs", function () {
        const key = naclutil.decodeBase64("dGhlIHNhsXBsZSBub25jZQ==");
        const resp = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert.isFalse(verifySecWebSocketAccept(key, resp));
    });
});


