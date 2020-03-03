
import forge from "node-forge";
import naclutil from "tweetnacl-util";
import { GUID } from "./packets.js";

/**
 * Verify the Sec-WebSocket-Accept header field by computing its expected value.
 * @param {Uint8Array} key 4-bytes sec-websocket-key used for client handshake
 * @param {string} resp received header field value string
 * @returns boolean true if the received value is the expected
 * @private
 */
export function verifySecWebSocketAccept(key, resp) {
    const fromHexString = hexString =>
        new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const keyb64 = naclutil.encodeBase64(key);
    let hashed = forge.md.sha1.create();
    hashed.update(keyb64 + GUID);
    const hashedBytes = fromHexString(hashed.digest().toHex());
    const expected = naclutil.encodeBase64(hashedBytes);
    return resp === expected;
}