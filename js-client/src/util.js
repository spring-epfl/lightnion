/**
 * @module utils
 * Utility functions used in the lightnion js-client module.
 */

import { sjcl } from "../vendor/sjcl.js";
import naclutil from "tweetnacl-util";

/**
 * Encoding functions.
 */
export class enc {
    static get bits() { return sjcl.codec.bytes.toBits; }
    static get utf8() { return naclutil.encodeUTF8; }
    static get base64() { return naclutil.encodeBase64; }

    /**
     * Return a function transforming an array of char codes to its string.
     */
    static get bin() {
        return function (data) {
            var str = ""
            for (var idx = 0; idx < data.length; idx++)
                str += String.fromCharCode(data[idx])
            return str
        }
    }
}

/**
 * Decoding functions.
 */
export class dec {
    static get bits() {
        return function (data) {
            return new Uint8Array(sjcl.codec.bytes.fromBits(data));
        }
    }
    static get utf8() { return naclutil.decodeUTF8; }
    static get base64() { return naclutil.decodeBase64; }

    /**
     * Return a function transforming a string to its array of char codes.
     */
    static get bin() {
        return function (str) {
            var data = new Uint8Array(str.length)
            for (var idx = 0; idx < str.length; idx++)
                data[idx] = str.charCodeAt(idx)
            return data
        }
    }
}
