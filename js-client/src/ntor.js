
/**
 * Cryptographic operations related to ntor handshakes.
 * @module ntor
 * @namespace
 * @see ntor.hand
 * @see ntor.shake
 */

import { enc, dec } from "./util.js";
import { sjcl } from "../vendor/sjcl.js";
import nacl from "tweetnacl";

let ntor = {}

/**
 * Number of bytes to derive from successful ntor handshakes.
 * @readonly
 * @default
 */
ntor.keybytes = 92

/**
 * Protocol identifier, prefix tweaks used in ntor handshakes various hashes.
 * @readonly
 * @default
 *
 * @see ntor.tweaks
 */
ntor.protoid = "ntor-curve25519-sha256-1"

/**
 * Tweaks used in ntor handshakes for various hashes and key derivation.
 * @enum
 * @readonly
 *
 * @see ntor.hash
 */
ntor.tweaks = {
    /**
     * rfc5869 Expand {info}
     * @type kdf
     */
    expand: ntor.protoid + ":key_expand",
    /**
     * rfc5869 Extract {salt}
     * @type kdf
     */
    key: ntor.protoid + ":key_extract",
    /**
     * H({secret_input}, t_verify)
     * @type ntor
     */
    verify: ntor.protoid + ":verify",
    /**
     * suffix of {auth_input}
     * @type ntor
     */
    server: ntor.protoid + "Server",
    /**
     * H({auth_input}, t_mac)
     * @type ntor
     */
    mac: ntor.protoid + ":mac"
}

/**
 * Tweaked pseudo-random function factory, see {@link ntor.hash}.
 *
 * @param {ntor.tweaks} tweak      tweak to use
 * @return {hash_t}
 *
 * @see ntor.hash
 */
ntor.hash_factory = function (tweak) {
    tweak = ntor.tweaks[tweak]
    tweak = sjcl.codec.utf8String.toBits(tweak)

    /**
     * Tweaked pseudo-random function used by {@link ntor}, returned
     * by {@link ntor.hash_factory}.
     *
     * @interface hash_t
     * @see ntor.hash
     *
     * @property {Object} hmac      underlying hmac provider
     */
    var hash = {
        hmac: new sjcl.misc.hmac(tweak),
        /**
         * Compute parent tweaked pseudo-random function on provided data.
         *
         * @function
         * @name hash_t#encrypt
         * @param {Uint8Array} data     input data
         */
        encrypt: function (data) {
            data = enc.bits(data)
            data = hash.hmac.encrypt(data)
            return dec.bits(data)
        }
    }
    return hash
}

/**
 * Tweaked pseudo-random functions used in ntor handshakes.
 * @enum
 * @type hash_t
 *
 * @see ntor.tweaks
 */
ntor.hash = {
    /**
     * used for H({secret_input}, t_verify) during ntor handshakes
     */
    verify: ntor.hash_factory("verify"),
    /**
     * used for H({auth_input}, t_mac) during ntor handshakes
     */
    mac: ntor.hash_factory("mac"),
    /**
     * used for extraction during ntor handshakes key derivation
     */
    prk: ntor.hash_factory("key")
}

/**
 * Compute ntor key derivation from given material to n bytes.
 *
 * @param {Uint8Array} material     ntor {secret_input} handshake
 * @param {int} n                   number of bytes to output
 * @return {Uint8Array}
 */
ntor.kdf = function (material, n) {
    material = ntor.hash.prk.encrypt(material)
    var hash = new sjcl.misc.hmac(enc.bits(material))

    var tweak = ntor.tweaks["expand"]
    tweak = sjcl.codec.utf8String.toBits(tweak)

    var idx = 1
    var out = enc.bits([])
    var last = enc.bits([])
    while (sjcl.bitArray.bitLength(out) < n * 8) {
        var idxbits = enc.bits([idx])
        var current = sjcl.bitArray.concat(tweak, idxbits)

        last = hash.encrypt(sjcl.bitArray.concat(last, current))
        out = sjcl.bitArray.concat(out, last)
        idx = idx + 1
    }

    return dec.bits(sjcl.bitArray.clamp(out, n * 8))
}


/**
 * Compute the first part of a ntor handshake,
 * writes a {@link half_t} in {@link endpoint_t#material}.
 *
 * @param {endpoint_t} endpoint     state where to store half-finished material
 * @param {Object} descriptor       node descriptor to handshake with
 * @param {Boolean} encode          if true, returns base64 (default: true)
 * @return {Uint8Array|string}
 *
 * @see ntor.shake
 */
ntor.hand = function (endpoint, descriptor, encode) {
    if (encode === undefined)
        encode = true
    if (descriptor === undefined)
        descriptor = endpoint.guard

    var identity = dec.base64(descriptor.router.identity + "=")
    var onionkey = dec.base64(descriptor["ntor-onion-key"])

    /**
    * Internal object, half-finished ntor handshake state in {@link
    * endpoint_t#material}, created by:
    * <ul>
    *   <li> {@link ntor.hand}
    *   <li> {@link ntor.fast}
    *   <li> {@link lnn.auth}
    * </ul>
    * Captures cryptographic state required to finish the handshake.
    *
    * @interface half_t
    *
    * @property {Object} ntor key pair
    * @property {Uint8Array} identity node identity
    * @property {Uint8Array} onionkey node public key
    */
    endpoint.material = {
        ntor: nacl.box.keyPair(),
        identity: identity,
        onionkey: onionkey
    }

    var pubkey = endpoint.material.ntor.publicKey
    var length = identity.length + onionkey.length + pubkey.length

    var payload = new Uint8Array(length)
    payload.set(identity, 0)
    payload.set(onionkey, identity.length)
    payload.set(pubkey, identity.length + onionkey.length)

    if (encode)
        return enc.base64(payload)
    return payload
}

/**
 * Just as {@link ntor.hand} but without node identity and onion key – used
 * by {@link lnn.fast}, writes a {@link half_t} in {@link endpoint_t#material}.
 *
 * <pre>Note: always returns base64-encoded handshake.</pre>
 *
 * @param {endpoint_t} endpoint     state where to store half-finished material
 * @return {string}
 *
 * @see lnn.fast
 */
ntor.fast = function (endpoint) {
    endpoint.material = {}
    endpoint.material.ntor = nacl.box.keyPair()
    endpoint.material.identity = null
    endpoint.material.onionkey = null
    return enc.base64(endpoint.material.ntor.publicKey)
}

/**
 * Compute the second part of a ntor handshake read
 * from {@link endpoint_t#material}, returns derived bytes suitable as
 * {@link ntor.slice} input.
 *
 * <pre>Note: returns null if handshake is invalid.</pre>
 *
 * @param {endpoint_t} endpoint     state where to read half-finished material
 * @param {Uint8Array|string} data  server part of the handshake
 * @param {boolean} encoded         if true, decode data as base64
 *                                  (default: true)
 * @return {Uint8Array|null}
 *
 * @see ntor.hand
 */
ntor.shake = function (endpoint, data, encoded) {
    if (encoded === undefined)
        encoded = true
    if (encoded)
        data = dec.base64(data)

    var client_pubkey = endpoint.material.ntor.publicKey
    var client_secret = endpoint.material.ntor.secretKey
    var server_pubkey = data.slice(0, nacl.scalarMult.scalarLength)
    var server_auth = data.slice(nacl.scalarMult.scalarLength)

    var identity = endpoint.material.identity
    var onionkey = endpoint.material.onionkey

    var exp_share = nacl.scalarMult(client_secret, server_pubkey)
    var exp_onion = nacl.scalarMult(client_secret, onionkey)

    var protoid = dec.utf8(ntor.protoid)
    var length = exp_share.length * 2 + identity.length + onionkey.length * 3
    var off = 0

    var secret_input = new Uint8Array(length + protoid.length)
    secret_input.set(exp_share, off); off += exp_share.length
    secret_input.set(exp_onion, off); off += exp_onion.length
    secret_input.set(identity, off); off += identity.length
    secret_input.set(onionkey, off); off += onionkey.length
    secret_input.set(client_pubkey, off); off += client_pubkey.length
    secret_input.set(server_pubkey, off); off += server_pubkey.length
    secret_input.set(protoid, off)
    var verify = ntor.hash.verify.encrypt(secret_input)

    var server = dec.utf8(ntor.tweaks["server"])
    var length = verify.length + identity.length + onionkey.length * 3
    var off = 0

    var auth_input = new Uint8Array(length + server.length)
    auth_input.set(verify, off); off += verify.length
    auth_input.set(identity, off); off += identity.length
    auth_input.set(onionkey, off); off += onionkey.length
    auth_input.set(server_pubkey, off); off += server_pubkey.length
    auth_input.set(client_pubkey, off); off += client_pubkey.length
    auth_input.set(server, off)
    var client_auth = ntor.hash.mac.encrypt(auth_input)

    var valid = true
    length = client_auth.length
    for (var i = 0; i < length; i++) {
        if (client_auth[i] != server_auth[i])
            valid = false
    }

    var zero_onion = 0
    var zero_share = 0
    length = exp_onion.length
    for (var i = 0; i < length; i++) {
        if (exp_onion[i] == 0)
            zero_onion = zero_onion + 1
        if (exp_share[i] == 0)
            zero_share = zero_share + 1
    }

    if (zero_onion == exp_onion.length || zero_share == exp_share.length)
        valid = false

    if (valid) {
        return ntor.kdf(secret_input, ntor.keybytes)
    }
    return null
}

/**
 * Build a shared cryptographic {@link material_t} for
 * {@link endpoint_t#material} from the output of {@link ntor.shake}.
 *
 * <pre>
 * Note: assume KEY_LEN == 16 (aes256) and HASH_LEN == 20 (sha1) internally.
 * </pre>
 *
 * @param {Uint8Array} material     exactly {@link ntor.keybytes}
 *                                  bytes
 * @return {material_t}
 */
ntor.slice = function (material) {
    var k = 16 // KEY_LEN
    var h = 20 // HASH_LEN

    /**
     * Internal object, stores shared cryptographic material
     * as {@link endpoint_t#material}, returned by {@link ntor.slice}.
     *
     * @interface material_t
     * @see ntor.slice
     *
     * @property {Uint8Array} key_hash          unused
     * @property {Uint8Array} forward_key       used in {@link forward_t}
     * @property {Uint8Array} forward_digest    used in {@link forward_t}
     * @property {Uint8Array} backward_key      used in {@link backward_t}
     * @property {Uint8Array} backward_digest   used in {@link backward_t}
     */
    var material = {
        key_hash: material.slice(h * 2 + k * 2),
        forward_digest: material.slice(0, h),
        backward_digest: material.slice(h, h * 2),
        forward_key: material.slice(h * 2, h * 2 + k),
        backward_key: material.slice(h * 2 + k, h * 2 + k * 2)
    }
    return material
}

// (function only used for proxy auth, not a part of regular ntor handshake)

/**
 * <pre>
 * Note: this function is used for proxy-server authentication and is not a
 * part of regular ntor handshakes nor the Tor specification.
 * </pre>
 *
 * Take an endpoint that uses the proxy-server authentication API (such as one
 * configured through {@link lnn.auth}) and the base64-encoded fields "auth"
 * and "data" as returned by the proxy-server, then returns the decoded data
 * if and only if the authentication succeeded.
 *
 */
ntor.auth = function (endpoint, client, data) {
    var pending_material = endpoint.material
    endpoint.material = endpoint.auth

    var data = dec.base64(data)
    var material = ntor.shake(endpoint, client)
    if (material == null)
        throw "Invalid auth."
    endpoint.material = pending_material

    var key = material.slice(0, 32)
    var nonce = material.slice(32, 32 + 24)
    data = nacl.secretbox.open(data, nonce, key)
    return JSON.parse(enc.utf8(data))
}


export { ntor }