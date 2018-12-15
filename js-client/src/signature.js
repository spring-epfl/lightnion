lnn.signature = {}

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
lnn.signature.verify = function (raw_cons, keys, minimal) {
    if (minimal === undefined) {
        minimal = 0.5
    } else if (minimal <= 0 || minimal > 1) {
        throw 'The minimal percentage must be between 0 (not included) and 1'
    }

    let nbr_verified = 0
    let total = 0

    //get the hash of the consensus
    let split_cons = raw_cons.split('directory-signature ')
    raw_cons = split_cons[0] + "directory-signature "
    let hash = sjcl.hash.sha1.hash(raw_cons)
    hash = sjcl.codec.hex.fromBits(hash)

    // Get the signatures and the signing keys
    let sig_and_keys_digests = lnn.signature.get_sig_and_keys_digests(split_cons.splice(1))

    for (let fingerprint in sig_and_keys_digests) {
        total++
        
        let key = keys[fingerprint]
        let e = bigInt(key["exponent"])
        let n = bigInt(key["modulus"])
        let key_digest = sig_and_keys_digests[fingerprint]["signing-key-digest"]

        if (key === undefined || !lnn.signature.verify_key(key["pem"], key_digest)) continue

        let signature = sig_and_keys_digests[fingerprint]["signature"]
        let sig_big_int = lnn.signature.get_signature_big_int(signature)
        let padded_hash = lnn.signature.get_hash(sig_big_int, e, n)
        let recovered_hash = lnn.signature.get_hash_from_rsa_cipher(padded_hash)

        nbr_verified = (recovered_hash === undefined || recovered_hash !== hash) ? nbr_verified : nbr_verified + 1
    }

    return nbr_verified > minimal * total
}

/**
 * This function get the digest encrypted by the RSA corresponding to given the exponent and modulus
 *
 * @param {BigInteger} signature the encrypted signature
 * @param {BigInteger} exponent the exponent of the key
 * @param {BigInteger} modulus the modulus of the key
 * @returns {String} the padded hash 
 */
lnn.signature.get_hash = function (signature, exponent, modulus) {
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
lnn.signature.verify_key = function (key, key_digest) {
    let raw_key = key.split('\n')
    let b_index = raw_key.indexOf("-----BEGIN RSA PUBLIC KEY-----")
    let e_index = raw_key.indexOf("-----END RSA PUBLIC KEY-----")

    raw_key = raw_key.splice(b_index + 1, e_index - b_index - 1).join("")
    raw_key = sjcl.codec.base64.toBits(raw_key)
    let hash = sjcl.hash.sha1.hash(raw_key)
    hash = sjcl.codec.hex.fromBits(hash)
    return hash.toUpperCase() === key_digest.toUpperCase()
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
lnn.signature.get_sig_and_keys_digests = function (remaining) {
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
lnn.signature.get_signature_big_int = function (signature) {
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
lnn.signature.get_hash_from_rsa_cipher = function (padded_hash) {

    if (!padded_hash.startsWith("0001")) return undefined
    padded_hash = padded_hash.substring(4)
    let sep_index = padded_hash.indexOf("00")

    for (let i = 1; i < sep_index; i++) {
        if (padded_hash.charAt(i) !== "f") return undefined
    }

    return padded_hash.substring(sep_index + 2)
}