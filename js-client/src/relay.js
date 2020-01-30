/**
 * @module relay
 */

import { dec } from "./util.js";

let relay = {}
relay.payload_len = 509
relay.data_len = relay.payload_len - 11
relay.full_len = 5 + relay.payload_len
relay.cmd = {
    "begin": 1, 1: "begin",
    "data": 2, 2: "data",
    "end": 3, 3: "end",
    "connected": 4, 4: "connected",
    "sendme": 5, 5: "sendme",
    "extend": 6, 6: "extend",
    "extended": 7, 7: "extended",
    "truncate": 8, 8: "truncate",
    "truncated": 9, 9: "truncated",
    "drop": 10, 10: "drop",
    "resolve": 11, 11: "resolve",
    "resolved": 12, 12: "resolved",
    "begin_dir": 13, 13: "begin_dir",
    "extend2": 14, 14: "extend2",
    "extended2": 15, 15: "extended2"
}

relay.pack = function (cmd, stream_id, data) {
    if (data === undefined)
        data = new Uint8Array(0)
    if (stream_id === undefined)
        stream_id = 0

    if (typeof (data) == "string")
        data = dec.utf8(data)

    var cell = new Uint8Array(relay.full_len) /* padded with \x00 */
    var view = new DataView(cell.buffer)

    view.setUint32(0, 2147483648 /* fake circuit_id */, false)
    view.setUint8(4, 3 /* RELAY CELL */, false)
    view.setUint8(5, relay.cmd[cmd], false)
    view.setUint16(6, 0 /* recognized */, false)
    view.setUint16(8, stream_id, false)
    // (implicit 4-bytes zeroed digest at offset 10)
    view.setUint16(14, data.length, false)
    cell.set(data, 16)

    return cell
}

relay.extend = function (handshake, host, port, identity, eidentity) {
    // (assuming that host is an IPv4)
    var addr = new Uint8Array(host.split("."))
    if (addr.join(".") != host)
        throw "Invalid extend IPv4 address, fatal."

    port = parseInt(port)
    if (typeof (identity) == "string")
        identity = dec.base64(identity)
    if (typeof (eidentity) == "string")
        eidentity = dec.base64(eidentity + "=")

    var nspec = 2
    if (eidentity !== undefined)
        nspec += 1

    var length = (1                     // Number of link specifiers
        + 1 + 1 + 6                         // 1. IPv4 addr+port
        + 1 + 1 + identity.length           // 2. Legacy identity
        + 2                             // Client handshake type (0x00002 ntor)
        + 2                             // Client handshake length
        + handshake.length)             // Actual handshake content

    if (nspec == 3)
        length += 1 + 1 + eidentity.length  // 3. Ed25519 identity

    var off = 0
    var data = new Uint8Array(length)
    var view = new DataView(data.buffer)
    view.setUint8(off, nspec /* nb of specifiers */, false); off += 1

    view.setUint8(off, 0 /* TLS-over-TCP IPv4 specifier */, false); off += 1
    view.setUint8(off, 6, false); off += 1      /* length   1 byte  */
    data.set(addr, off); off += 4        /* address  4 bytes */
    view.setUint16(off, port, false); off += 2  /* port     2 bytes */

    view.setUint8(off, 2 /* Legacy identity specifier */, false); off += 1
    view.setUint8(off, identity.length, false); off += 1
    data.set(identity, off); off += identity.length

    if (nspec == 3) {
        view.setUint8(off, 3 /* Ed25519 identity specifier */, false); off += 1
        view.setUint8(off, eidentity.length, false); off += 1
        data.set(eidentity, off); off += eidentity.length
    }

    view.setUint16(off, 2 /* handshake: 0x00002 ntor */, false); off += 2
    view.setUint16(off, handshake.length, false); off += 2
    data.set(handshake, off)

    return data
}

relay.begin = function (host, port) {
    let valid = false
    if (host.match("(\\d\+\\.){3}\\d\+"))
        valid = true
    if (host.match("^\\[[\\d:]*\\]$"))
        valid = true
    if (!valid && host.slice(-1) != ".")
        host = host + "."
    if (host.match("^([a-zA-Z0-9][a-zA-Z0-9\\-]*\\.)*$"))
        valid = true
    if (host.slice(-1) == ".")
        host = host.slice(0, -1)

    if (!valid)
        throw "Invalid host provided?"
    var address = dec.utf8(host + ":" + port)

    var data = new Uint8Array(address.length + 1 + 4) // (1o null, 4o flags)
    data.set(address, 0)
    data[address.length + 1 + 3] = 5 // flags IPv6 okay+preferred and IPv4 okay

    return data
}

export { relay }