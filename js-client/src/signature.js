/**
 * @module signature
 */

import bigInt from "big-integer";
import { sjcl } from "../vendor/sjcl.js";
import { lnn } from "./header.js";

/**
 *  This function verifies the given raw consensus
 *
 *   Note 1: TOR does not perform a full PKCS#1 v1.5 signature (RFC 2313) as mentioned in the TOR's reference.
 *           The padding of the data that must be signed is done following the reference (see subsection 8.1 of the
 *           RFC 2313 for more details), however the digest is not wrapped into the data structure described in the
 *           subsection 10.1.2. This is the reason why RSA is performed manually.
 * 
 *   Note 2: <script src="http://peterolson.github.com/BigInteger.js/BigInteger.min.js"></script> must be included in the HTML file using this function.
 * 
 * @param {String} raw_cons the consensus we want to verify
 * @param {Object} keys object mapping the authorities' fingerprint to their key with the following format:
 *                  fingerprint:{
 *                       pem: key_pem            //the key in pem format
 *                       modulus: modulus        //the modulus of the key as a string
 *                       exponent: exponent      //the exponent of the key as a string
 *                   }
 * @param {Number} minimal the minimal percentage of the signatures that must be verified in order to verify the consensus
 * @returns {Boolean} the result of the verification
 */
export function verify(raw_cons, keys, minimal, flavor = 'microdesc') {
    if (minimal === undefined) {
        minimal = 0.5
    } else if (minimal <= 0 || minimal > 1) {
        throw 'The minimal percentage must be between 0 (not included) and 1'
    }

    //keys = process_raw_keys(keys)

    let nbr_verified = 0
    let total = 0

    //get the hash of the consensus
    let split_cons = raw_cons.split('directory-signature ')
    raw_cons = split_cons[0] + "directory-signature "

    let hash = (flavor == 'unflavored') ? sjcl.hash.sha1.hash(raw_cons) : sjcl.hash.sha256.hash(raw_cons)
    hash = sjcl.codec.hex.fromBits(hash)

    // Get the signatures and the signing keys
    let sig_and_keys_digests = get_sig_and_keys_digests(split_cons.splice(1))

    for (let fingerprint in sig_and_keys_digests) {
        total++

        let key = keys[fingerprint]
        let e = bigInt(key["exponent"])
        let n = bigInt(key["modulus"])
        let key_digest = sig_and_keys_digests[fingerprint]["signing-key-digest"]

        if (key === undefined || !verify_key(key["pem"], key_digest)) continue

        let signature = sig_and_keys_digests[fingerprint]["signature"]
        let sig_big_int = get_signature_big_int(signature)
        let padded_hash = get_hash(sig_big_int, e, n)
        let recovered_hash = get_hash_from_rsa_cipher(padded_hash)

        nbr_verified = (recovered_hash === undefined || recovered_hash !== hash) ? nbr_verified : nbr_verified + 1
    }
    console.log(nbr_verified + " " + total)
    return nbr_verified > minimal * total
}

export function process_raw_keys(raw_keys) {
    var keys = {}
    var real_tor = true //keep false for chutney!!

    raw_keys = raw_keys.split('\n')
    for(i = 0; i < raw_keys.length; i++) {
        if(raw_keys[i] == "") continue

        if(!raw_keys[i].startsWith("dir-key-certificate-version")) continue

        var sti = i
        while(!raw_keys[i].startsWith("fingerprint")) i++

        var fingerprint = raw_keys[i].split(" ")[1]
        
        while(!raw_keys[i].startsWith("dir-identity-key"))
            i++
        i++
        var auth_id_key = ""
        while(raw_keys[i] != "-----END RSA PUBLIC KEY-----") {
            auth_id_key += raw_keys[i] + "\n"
            i++
        }
        auth_id_key += "-----END RSA PUBLIC KEY-----"
        i++

        if(!raw_keys[i].startsWith("dir-signing-key")) {
            throw 'Unexpected key certificate document format'
        }
        i++
        var signing_key = ""
        while(raw_keys[i] != "-----END RSA PUBLIC KEY-----") {
            signing_key += raw_keys[i] + "\n"
            i++
        }
        signing_key += "-----END RSA PUBLIC KEY-----"
        i++

        if(!raw_keys[i].startsWith("dir-key-crosscert")) {
            throw 'Unexpected key certificate document format'
        }
        i++
        var cross_cert = ""
        while(raw_keys[i] != "-----END ID SIGNATURE-----" && raw_keys[i] != "-----END SIGNATURE-----") {
            cross_cert += raw_keys[i] + "\n"
            i++
        }
        cross_cert += raw_keys[i]
        i++

        if(!raw_keys[i].startsWith("dir-key-certification")) {
            throw 'Unexpected key certificate document format'
        }
        var eni = i

        i++ //skip dir-key-certification
        i++ //skip begin signature
        var cert = ""
        while(raw_keys[i] != "-----END SIGNATURE-----") {
            cert += raw_keys[i]
            i++
        }
    
        if(!lnn.signature.verify_key(auth_id_key,fingerprint)) {
            throw 'authority identity key' + fingerprint + ' digest verification failed'
        }
        
        if(real_tor) {
            if(lnn.root_keys[fingerprint] === undefined) {
                throw 'Root key not found ' + fingerprint
            }
        }

        var auth_key_pki = forge.pki.publicKeyFromPem(auth_id_key);
        var auth_mod = auth_key_pki.n.toString()
        var auth_exp = auth_key_pki.e.toString()

        if(real_tor) {
            if(lnn.root_keys[fingerprint]["pem"] != auth_id_key || 
                lnn.root_keys[fingerprint]["modulus"] != auth_mod || 
                lnn.root_keys[fingerprint]["exponent"] != auth_exp 
                )  {
                throw 'Root key ' + fingerprint + ' digest mismatch'
            }
        }


        var raw_key_doc = ""
        for(j = sti; j < eni; j++) raw_key_doc += raw_keys[j] + "\n"
        raw_key_doc += "dir-key-certification\n"
        
        var hash_key_doc = sjcl.hash.sha1.hash(raw_key_doc)
        hash_key_doc = sjcl.codec.hex.fromBits(hash_key_doc)


        var e = bigInt(auth_exp)
        var n = bigInt(auth_mod)

        var sig_big_int = lnn.signature.get_signature_big_int(cert)
        var padded_hash = lnn.signature.get_hash(sig_big_int, e, n)
        var recovered_hash = lnn.signature.get_hash_from_rsa_cipher(padded_hash) 


        if(recovered_hash === undefined || recovered_hash !== hash_key_doc) {
            throw( 'Signature document invalid, root key verification failed' )
        }

        var sg_digest = lnn.signature.compute_digest(signing_key)
        var signing_key_pki = forge.pki.publicKeyFromPem(signing_key);

        if(keys[fingerprint] === undefined) 
            keys[fingerprint] = {}
        keys[fingerprint][sg_digest] = {
            "pem":signing_key,
            "modulus":signing_key_pki.n.toString(),
            "exponent":signing_key_pki.e.toString()
        }

    }
    return keys
}

/**
 * This function get the digest encrypted by the RSA corresponding to given the exponent and modulus
 *
 * @param {BigInteger} signature the encrypted signature
 * @param {BigInteger} exponent the exponent of the key
 * @param {BigInteger} modulus the modulus of the key
 * @returns {String} the padded hash 
 */
export function get_hash(signature, exponent, modulus) {
    let padded_hash = signature.modPow(exponent, modulus).toString(16)
    let size = modulus.toString(16).length
    let offset = size - padded_hash.length
    for (let i = 0; i < offset; i++) {
        padded_hash = "0" + padded_hash
    }
    return padded_hash
}

/**
 * This function verifies that the key corresponds to one that signed the consensus
 * 
 * @param {string} key the key with the format pem
 * @param {string} key_digest the hex digest extracted from the consensus
 */
export function verify_key(key, key_digest) {
    let raw_key = key.split('\n')
    let b_index = raw_key.indexOf("-----BEGIN RSA PUBLIC KEY-----")
    let e_index = raw_key.indexOf("-----END RSA PUBLIC KEY-----")

    raw_key = raw_key.splice(b_index + 1, e_index - b_index - 1).join("")
    raw_key = sjcl.codec.base64.toBits(raw_key)
    let hash = sjcl.hash.sha1.hash(raw_key)
    hash = sjcl.codec.hex.fromBits(hash)
    return hash.toUpperCase() === key_digest.toUpperCase()
}

export function compute_digest(key) {
    let raw_key = key.split('\n')
    let b_index = raw_key.indexOf("-----BEGIN RSA PUBLIC KEY-----")
    let e_index = raw_key.indexOf("-----END RSA PUBLIC KEY-----")

    raw_key = raw_key.splice(b_index + 1, e_index - b_index - 1).join("")
    raw_key = sjcl.codec.base64.toBits(raw_key)
    let hash = sjcl.hash.sha1.hash(raw_key)
    hash = sjcl.codec.hex.fromBits(hash)
    return hash.toUpperCase()
}


/**
 * This function gets the signatures and the signing key digests from the authority section of the consensus
 *
 * @param {Array} remaining the remaining part of the consensus after the split by "directory-signature "
 * @returns {object} the following mapping:
 *      fingerprint:{
 *          signature-key-digest
 *          signature
 *      }
 */
export function get_sig_and_keys_digests(remaining) {
    let sign_and_digests = {}
    for (let r of remaining) {
        if (r !== '') {
            let split = r.split('\n')
            let b_index = split.indexOf("-----BEGIN SIGNATURE-----")
            let e_index = split.indexOf("-----END SIGNATURE-----")
            let sign = split.splice(b_index + 1, e_index - b_index - 1).join("")
            let digests = split[0].split(" ")

            let [fingerprint, key_hex_digest] = (digests.length == 2) ? digests : digests.splice(1)

            sign_and_digests[fingerprint] = {
                "signing-key-digest": key_hex_digest,
                "signature": sign
            }
        }
    }
    return sign_and_digests
}

/**
 * 
 * This function transforms a signature in base64 into a bigInteger
 * @param {string} signature the signature encoded in base64
 * @returns {BigInteger} the integer corresponding to the signature
 */
export function get_signature_big_int(signature) {
    let sig_hex = sjcl.codec.hex.fromBits(sjcl.codec.base64.toBits(signature))
    let sig = bigInt(sig_hex, 16)
    return sig
}

/**
 * Verifies that the cipher has the required format and extract the substring corresponding to the hash of the consensus
 *
 * @param {string} cipher the padded hash of the consensus
 * @returns {string} the hash of the consensus
 */
export function get_hash_from_rsa_cipher(padded_hash) {

    if (!padded_hash.startsWith("0001")) return undefined
    padded_hash = padded_hash.substring(4)
    let sep_index = padded_hash.indexOf("00")

    for (let i = 1; i < sep_index; i++) {
        if (padded_hash.charAt(i) !== "f") return undefined
    }

    return padded_hash.substring(sep_index + 2)
}
