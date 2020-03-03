// Tests for util functions.

import { assert } from "chai";
import { enc, dec } from "../util.js";

describe("string char codes encoding and decoding", function () {
    it("should encode then decode to the same string", function () {
        let tt = [
            "", "non empty", "unicode ☑️"
        ]

        for (const tc in tt) {
            assert.equal(enc.bin(dec.bin(tc)), tc);
        }
    });
});