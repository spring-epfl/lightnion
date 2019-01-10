parser = {}

parser.descriptors = {
    line_count: 0,
    total_lines: -1,
    lines: undefined,
    valid_bridge_distribution: ["none", "any", "https", "email", "moat", "hyphae"],
    exactly_once: ["router", "bandwidth", "published", "onion-key", "signing-key", "router-signatures"],

    parse: function (raw_descriptors, endpoint) {
        let descriptors = []
        parser.descriptors.lines = raw_descriptors.split('\n')
        parser.descriptors.total_lines = parser.descriptors.lines.length
        parser.descriptors.line_count = 0
        while (parser.descriptors.line_count < parser.descriptors.total_lines) {
            if (parser.descriptors.lines[parser.descriptors.line_count] === "") {
                parser.descriptors.line_count++
                continue
            }
            let descriptor = parser.descriptors.consume_one_node()
            descriptors.push(descriptor)
        }
        return descriptors
    }
}

/**
 * Parse one node in the raw data file
 * @returns {object} the descriptor of the parsed node
 */
parser.descriptors.consume_one_node = function () {

    if (parser.descriptors.lines[parser.descriptors.line_count].startsWith('@type')) parser.descriptors.line_count++
    if (parser.descriptors.lines[parser.descriptors.line_count] === "") {
        parser.descriptors.line_count++
    }
    let descriptor = {}
    descriptor = parser.descriptors.consume_router(descriptor)
    descriptor = parser.descriptors.try_consume_identity_ed25519(descriptor)

    let line = parser.descriptors.lines[parser.descriptors.line_count]

    while (!line.startsWith("router-signature")) {
        let index_sp = line.indexOf(" ")
        let first_word = (index_sp === -1) ? line : line.substring(0, index_sp)
        switch (first_word) {
            case "master-key-ed25519":
                descriptor = parser.descriptors.consume_master_key_ed25519(descriptor)
                break
            case "platform":
                descriptor = parser.descriptors.consume_platform(descriptor)
                break
            case "published":
                descriptor = parser.descriptors.consume_published(descriptor)
                break
            case "bandwidth":
                descriptor = parser.descriptors.consume_bandwidth(descriptor)
                break
            case "fingerprint":
                descriptor = parser.descriptors.consume_fingerprint(descriptor)
                break
            case "hibernating":
                descriptor = parser.descriptors.consume_hibernating(descriptor)
                break
            case "uptime":
                descriptor = parser.descriptors.consume_uptime(descriptor)
                break
            case "extra-info-digest":
                descriptor = parser.descriptors.consume_extra_info_digest(descriptor)
                break
            case "caches-extra-info":
                descriptor = parser.descriptors.consume_single_word_line("caches-extra-info", descriptor)
                break
            case "onion-key":
                descriptor = parser.descriptors.consume_onion_key(descriptor)
                break
            case "onion-key-crosscert":
                descriptor = parser.descriptors.consume_onion_key_crosscert(descriptor)
                break
            case "ntor-onion-key":
                descriptor = parser.descriptors.consume_base64_digest('ntor-onion-key', descriptor)
                break
            case "ntor-onion-key-crosscert":
                descriptor = parser.descriptors.consume_ntor_onion_key_crosscert(descriptor)
                break
            case "accept":
                descriptor = parser.descriptors.consume_exit_policy("accept", descriptor)
                break
            case "reject":
                descriptor = parser.descriptors.consume_exit_policy("reject", descriptor)
                break
            case "signing-key":
                descriptor = parser.descriptors.consume_signing_key(descriptor)
                break
            case "ipv6-policy":
                descriptor = parser.consume_exit_policy('ipv6-policy', parser.descriptors.lines, parser.descriptors.line_count++, descriptor)
                break
            case "router-sig-ed25519":
                descriptor = parser.descriptors.consume_router_sig_ed25519(descriptor)
                break
            case "contact":
                descriptor = parser.consume_contact(parser.descriptors.lines, parser.descriptors.line_count++, descriptor)
                break
            case "bridge-distribution":
                descriptor = parser.descriptors.consume_bridge_distribution(descriptor)
                break
            case "family":
                descriptor = parser.descriptors.consume_family(descriptor)
                break
            case "read-history":
                descriptor = parser.descriptors.consume_history("read", descriptor)
                break
            case "write-history":
                descriptor = parser.descriptors.consume_history("write", descriptor)
                break
            case "eventdns":
                descriptor = parser.descriptors.consume_eventdns(descriptor)
                break
            case "hidden-service-dir":
                descriptor = parser.descriptors.consume_single_word_line("hidden-service-dir", descriptor)
                break
            case "allow-single-hop-exits":
                descriptor = parser.descriptors.consume_single_word_line("allow-single-hop-exits", descriptor)
                break
            case "tunnelled-dir-server":
                descriptor = parser.descriptors.consume_single_word_line("tunnelled-dir-server", descriptor)
                break
            case "proto":
                descriptor = parser.consume_proto("proto", parser.descriptors.lines, parser.descriptors.line_count++, descriptor)
                break
            default:
                ++parser.descriptors.line_count
                break
        }
        line = parser.descriptors.lines[parser.descriptors.line_count]

    }

    descriptor = parser.descriptors.consume_router_signature(descriptor)

    if (descriptor['ipv6-policy'] === undefined) descriptor['ipv6-policy'] = {
        "type": "reject",
        "PortList": [[1, 65535]]
    }

    if (!parser.descriptors.check_exactly_once(descriptor)) throw "Invalid descriptor: some mandatory fields are not present"

    return descriptor
}

/**
 * Checks that all mandatory fields of the descriptor were parsed
 */
parser.descriptors.check_exactly_once = function (descriptor) {

    if (descriptor['ipv6-policy'] === undefined) descriptor

    let parsed = true
    if (descriptor['identity-ed25519'] !== undefined) {
        parsed = descriptor["ntor-onion-key-crosscert"] !== undefined && descriptor["onion-key-crosscert"] !== undefined && descriptor["router-sig-ed25519"] !== undefined
    } else {
        parsed = descriptor["router-sig-ed25519"] === undefined
    }

    return parsed && parser.descriptors.exactly_once.every(field => descriptor[field] !== undefined)
}

/**
 * Consume the field router of the descriptor
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_router = function (descriptor) {
    let words = parser.descriptors.lines[parser.descriptors.line_count].split(' ')
    parser.check_format(6, 'router', words)

    if (!parser.is_valid_nickname(words[1])) throw `Invalid nickname: ${words[1]} contains non-alphanumeric characters`
    if (!parser.is_valid_ipv4(words[2])) throw `Invalid address: ${words[2]} is not a valid iPv4 address`
    if (!parser.is_valid_port(words[3])) throw `Invalid port: ${words[3]} is not a valid port (0 to 65535)`
    if (!parser.is_valid_port(words[4])) throw `Invalid port: ${words[4]} is not a valid port (0 to 65535)`
    if (!parser.is_valid_port(words[5])) throw `Invalid port: ${words[5]} is not a valid port (0 to 65535)`

    descriptor['router'] = {
        "nickname": words[1],
        "address": words[2],
        "orport": Number(words[3]),
        "socksport": Number(words[4]),
        "dirport": Number(words[5])
    }

    ++parser.descriptors.line_count

    return descriptor
}
/**
 * Consume try to consume the idendtity ed25519 certificate and its master key
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.try_consume_identity_ed25519 = function (descriptor) {
    let words = parser.descriptors.lines[parser.descriptors.line_count].split(' ')
    if (words[0] === 'identity-ed25519') {
        parser.check_format(1, 'identity-ed25519', words)
        ++parser.descriptors.line_count

        let [offset, certificate] = parser.consume_pem(parser.descriptors.lines, parser.descriptors.line_count)
        parser.descriptors.line_count += offset + 1
        descriptor['identity'] = {
            "type": "ed25519",
            "cert": certificate
        }

        return descriptor
    }

    return descriptor
}

/**
 * Parse the master-key-ed25519
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_master_key_ed25519 = function (descriptor) {

    let words = parser.descriptors.lines[parser.descriptors.line_count].split(' ')
    parser.check_format(2, 'master-key-ed25519', words)
    parser.check_reused('master-key-ed25519', descriptor)
    let key = words[1]
    if (!parser.is_valid_base64(parser.add_ending(key))) throw `Invalid master key: the master key ${words[1]} must be in base64`
    descriptor['identity']['master-key'] = key
    parser.descriptors.line_count++

    return descriptor
}

/**
 * Consume the line if it starts with platform
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_platform = function (descriptor) {
    parser.check_reused("platform", descriptor)
    let line = parser.descriptors.lines[parser.descriptors.line_count]
    let platform = line.substring("platform".length + 1)
    descriptor['platform'] = platform
    parser.descriptors.line_count++
    return descriptor
}

/**
 * Consume the time of the published field
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_published = function (descriptor) {
    parser.check_reused('published', descriptor)
    descriptor['published'] = parser.consume_date('published', parser.descriptors.lines[parser.descriptors.line_count])
    ++parser.descriptors.line_count
    return descriptor
}

/**
 * Consume the bandwidth fields 
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_bandwidth = function (descriptor) {
    parser.check_reused('bandwidth', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(4, 'bandwidth', words)

    let avg = Number(words[1])
    let burst = Number(words[2])
    let obs = Number(words[3])

    if (avg < 0 || burst < 0 || obs < 0) throw `Invalid bandwidth: must be non-negative`

    descriptor['bandwidth'] = {
        "avg": avg,
        "burst": burst,
        "observed": obs
    }

    return descriptor
}

/**
 * Consume the fingerprint field
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_fingerprint = function (descriptor) {
    parser.check_reused('fingerprint', descriptor)
    let line = parser.descriptors.lines[parser.descriptors.line_count++]
    let index_sp = line.indexOf(" ")
    let fingerprint = line.substring(index_sp + 1)

    let bytes = fingerprint.split(" ")
    let join_bytes = bytes.join("")
    if (bytes.length != 10) throw `Invalid fingerprint: wrong size`
    if (!parser.is_valid_hex(join_bytes)) throw `Invalid fingerprint: not a hex string`

    let identity = sjcl.codec.hex.toBits(join_bytes)
    identity = sjcl.codec.base64.fromBits(identity).replace("=", "")

    descriptor['fingerprint'] = fingerprint
    descriptor['router']['identity'] = identity

    return descriptor
}

/**
 * Consume the hibernating field
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_hibernating = function (descriptor) {
    parser.check_reused('hibernating', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, 'hibernating', words)

    let b = Number(words[1])
    if (b !== 0 && b !== 1) throw `Invalid boolean`
    descriptor['hibernating'] = b
    return descriptor
}

/**
 * Consume the uptime field
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_uptime = function (descriptor) {
    parser.check_reused('uptime', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, 'uptime', words)

    let uptime = Number(words[1])

    if (uptime < 0) throw `Invalid uptime: uptime must be non-negative`

    descriptor['uptime'] = uptime

    return descriptor
}

/**
 * Consume the onion key
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_onion_key = function (descriptor) {
    parser.check_reused('onion-key', descriptor)
    return parser.descriptors.consume_key('onion-key', descriptor)
}

/**
 * Consume the extra info digest
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_extra_info_digest = function (descriptor) {
    parser.check_reused('extra-info-digest', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    if (words.length != 2 && words.length != 3) throw `Invalid format: 1 or 2 fields are expected`

    let sha1 = words[1]
    if (!parser.is_valid_hex(sha1)) throw `Invalid encoding: the sha1 digest must be in hexadecimal`
    descriptor["extra-info-digest"] = {
        "sha1": sha1
    }

    if (words.length === 3) {
        let sha256 = words[2]
        if (!parser.is_valid_base64(parser.add_ending(sha256))) throw `Invalid encoding: the sha256 digest must base 64`
        descriptor['extra-info-digest']['sha256'] = sha256
    }

    return descriptor
}

/**
 * Consume the single word line
 * @param {string} type the field
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_single_word_line = function (type, descriptor) {
    parser.check_reused(type, descriptor)
    descriptor[type] = 'true'
    ++parser.descriptors.line_count

    return descriptor
}

/**
 * Consume the RSA signature generated using the onion-key
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_onion_key_crosscert = function (descriptor) {
    parser.check_reused('onion-key-crosscert', descriptor)
    return parser.descriptors.consume_key('onion-key-crosscert', descriptor)
}

/**
 * Consume the ntor onion key  of the descriptor
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_ntor_onion_key_crosscert = function (descriptor) {

    parser.check_reused('ntor-onion-key-crosscert', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count].split(" ")
    parser.check_format(2, 'ntor-onion-key-crosscert', words)

    let bit = Number(words[1])
    if (bit != 0 && bit != 1) throw "Invalid bit for ntor-onion-key-crosscert"

    let [offset, cert] = parser.consume_pem(parser.descriptors.lines, ++parser.descriptors.line_count)
    parser.descriptors.line_count += offset + 1

    descriptor['ntor-onion-key-crosscert'] = {
        "bit": bit,
        "cert": cert
    }

    return descriptor

}

/**
 * Consume the ED25519 signature
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_router_sig_ed25519 = function (descriptor) {
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, "router-sig-ed25519", words)
    parser.check_reused("router-signatures", descriptor)

    let signature = words[1]

    if (!parser.is_valid_base64(parser.add_ending(signature))) throw "Invalid digest: must be a base 64 string"

    descriptor["router-signatures"] = {
        "ed25519": signature,
    }

    return descriptor
}

/**
 * Consume the PKCS1 padded signature of the descriptor
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_router_signature = function (descriptor) {
    let words = parser.descriptors.lines[parser.descriptors.line_count].split(' ')
    if (words[0] === 'router-signature') {
        parser.check_format(1, 'router-signature', words)
        ++parser.descriptors.line_count

        let [offset, signature] = parser.consume_pem(parser.descriptors.lines, parser.descriptors.line_count)
        parser.descriptors.line_count += offset + 1

        if (descriptor["router-signatures"] === undefined) {
            descriptor["router-signatures"] = {}
        }

        descriptor["router-signatures"]["rsa"] = signature

        return descriptor
    }
}

/**
 * Consume the field bridge-distribution
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_bridge_distribution = function (descriptor) {
    parser.check_reused('bridge-distribution', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, 'bridge-distribution', words)
    let dist = words[1]
    if (!parser.descriptors.valid_bridge_distribution.includes(dist)) dist = "none"

    descriptor['bridge-distribution'] = dist

    return descriptor

}

/**
 * Consume the field family
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_family = function (descriptor) {
    parser.check_reused("family", descriptor)

    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    let family = words.splice(1)

    descriptor['family'] = family

    return descriptor
}
/**
 * Consume the history fields
 * @param {string} type the type of history
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_history = function (type, descriptor) {
    let field = type + "-history"
    parser.check_reused(field, descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(6, type + "-history", words)

    let date = words[1]
    if (!parser.is_valid_date(date)) throw "Invalid date"

    let time = words[2]
    if (!parser.is_valid_time(time)) throw "Invalid time"

    let interval = Number(words[3].substring(1))
    let bytes = words[5].split(",").map(x => Number(x))

    descriptor[field] = {
        "date": date,
        "time": time,
        "interval": interval,
        "bytes": bytes
    }

    return descriptor
}

/**
 * Consume the field eventdns
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_eventdns = function (descriptor) {
    parser.check_reused("eventdns", descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, "eventdns", words)

    let bool = Number(words[1])

    if (bool != 0 && bool != 1) throw "Invalid boolean"

    decriptor["eventdns"] = bool
    return descriptor
}

/**
 * Consume field with a base 64 digest
 * @param {String} field the field we want to parse
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_base64_digest = function (field, descriptor) {
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, field, words)
    parser.check_reused(field, descriptor)

    let key = words[1]

    if (!parser.is_valid_base64(parser.add_ending(key))) throw "Invalid digest: must be a base 64 string"

    descriptor[field] = key

    return descriptor
}

/**
 * Consume the signing keys
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_signing_key = function (descriptor) {
    parser.check_reused('signing-key', descriptor)
    return parser.descriptors.consume_key('signing-key', descriptor)
}

/**
 * Parse the accept and reject exit policies and their exitpattern
 * @param {string} type either reject or accept
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_exit_policy = function (type, descriptor) {
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, type, words)

    if (descriptor['policy'] === undefined) {
        descriptor['policy'] = {
            "type": "exitpattern",
            "rules": []
        }
    }

    let rule = {
        "type": type,
        "pattern": words[1]
    }

    descriptor['policy']["rules"].push(rule)

    return descriptor
}

/**
 * Consume the key of the given field and update the descriptor
 * @param {string} field the field of the descriptor
 * @param {object} descriptor the currently being built decriptors object
 * @returns {Object} the updated descriptor
 */
parser.descriptors.consume_key = function (field, descriptor) {
    [offset, key] = parser.consume_pem(parser.descriptors.lines, ++parser.descriptors.line_count)
    parser.descriptors.line_count += offset + 1
    descriptor[field] = key
    return descriptor
}

/**
* Checks if words has the expected size and that the first word of the line is equal to a given word
* @param {number} expected_length the expected length of the line
* @param {string} expected_word the expected word
* @param {Array} words the line splitted into words
*/
parser.check_format = function (expected_length, expected_word, words) {
    if (words.length != expected_length) {
        console.log(words)
        throw `wrong_format_exception: ${expected_length} fields are expected`
    } else if (words[0] !== expected_word) {
        console.log(words)
        throw `not_equal_exception: ${expected_word} is not equal to ${words[0]}`
    }
}

/**
* Check if the IP is an IPv4 address
* @param {string} IP 
*/
parser.is_valid_ipv4 = function (IP) {
    let regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return regex.test(IP)
}

/**
 * Check if the given port is valid
 * @param {number} port
 */
parser.is_valid_port = function (port) {
    if (isNaN(port)) return false
    return port >= 0 && port <= 65535
}

/**
 * Check if the given nickname is valid
 * @param {string} nickname the nickname we want to verify
 * @returns {boolean} the validity of the nickname 
 */
parser.is_valid_nickname = function (nickname) {
    let regex = /^[a-z0-9]+$/i
    return regex.test(nickname)
}

/**
* Check if the given string is in base 64
* @param {string} str 
*/
parser.is_valid_base64 = function (str) {
    let regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
    return regex.test(str)
}
/**
 * Check if the given string is in hexadecimal
 * @param {string} str 
 */
parser.is_valid_hex = function (str) {
    let regex = /^[a-fA-F0-9]+$/
    return regex.test(str)
}

/**
 * Consume a PEM format field
 * @param {Array} lines the splitted textfield
 * @param {Number} start where the pem starts
 * @param {function} base_function optional function to verifiy the base
 * @returns {Array} tuple containing the parsed pem and the offset
 */
parser.consume_pem = function (lines, start) {
    let offset = 0;
    let content = ''
    if (!lines[start].startsWith('-----BEGIN')) throw `Invalid signature, certificate or key: must begin with "-----BEGIN"`
    offset++
    while (!lines[start + offset].startsWith("-----END")) {
        content += lines[start + offset]
        offset++
    }

    if (!parser.is_valid_base64(content)) throw "Invalid PEM: must be in base 64"

    return [offset, content]
}

/**
 * Parse ranges
 * @param {string} ranges format: Keyword=Values...
 * @returns {object} the parsed ranges
 */
parser.parse_range = function (ranges) {
    let content = {}
    for (let pair of ranges) {
        if (pair.includes("=")) {
            let tmp = pair.split("=")
            content[tmp[0]] = parser.parse_range_once(tmp[1])
        }
    }
    return content
}

/**
 * This function parses ranges with the format nbr,nbr,.. where nbr is either an integer or 2 integers separated by a comma
 * @param {string} value the sting we want to parse
 * @returns {Array} a list containing the ranges 
 */
parser.parse_range_once = function (value) {
    value = value.split(',')
    let subvalues = []

    for (let subvalue of value) {
        if (subvalue.includes('-')) {
            let lowHigh = subvalue.split('-')
            let low = Number(lowHigh[0])
            let high = Number(lowHigh[1])

            if (low === high - 1) {
                subvalues.push([low, high])
            } else {
                subvalues.push([[low, high]])
            }
        } else {
            subvalues.push([Number(subvalue)])
        }
    }
    return subvalues
}

/**
 * This function parses the exit policies formatted as: field (accept/reject) PortList
 * @param {string} field the field we want to parse
 * @param {Array} lines the raw file split by '\n'
 * @param {Number} index the index of the line
 * @param {object} node the node we want to update
 * @returns the updated node
 */
parser.consume_exit_policy = function (field, lines, index, node) {
    parser.check_reused(field, node)
    let words = lines[index].split(" ")
    parser.check_format(3, field, words)

    let policy = words[1]
    if (policy !== 'accept' && policy !== 'reject') throw "Invalid policy: policy must either be accept or reject"

    let ranges = parser.parse_range_once(words[2])

    node[field] = {
        'type': policy,
        'PortList': ranges
    }

    return node
}

/**
 * This function parses the contacts
 * @param {string} field the field we want to parse
 * @param {Array} lines the raw file split by '\n'
 * @param {Number} index the index of the line
 * @param {object} node the node we want to update
 * @returns the updated node
 */
parser.consume_contact = function (lines, index, node) {
    parser.check_reused("contact", node)
    let contact = lines[index].substring("contact".length + 1)
    node["contact"] = contact

    return node
}


/**
* Check if the string in date has the format YYYY-MM-DD
* @param {string} time String representing the date
*/
parser.is_valid_date = function (date) {
    if (typeof date !== 'string') return false
    let regex = /^\d{4}[-](0[1-9]|1[012])[-](0[1-9]|[12][0-9]|3[01])$/
    return regex.test(date)
}

/**Check if the string time has the format HH:MM:SS
 * @param {string} time String representing the time
 */
parser.is_valid_time = function (time) {
    if (typeof time !== 'string') return false
    let regex = /^(0[0-9]|1[0-9]|2[0-3])[:][0-5][0-9][:][0-5][0-9]$/
    return regex.test(time)
}

/**
 * Consume the line containing a date with the format field YYYY-MM-DD HH:MM:SS
 * @param {string} field the field we are consuming
 * @param {string} line the line we are consuming
 * @returns {object} object containing both the date and the time 
 */
parser.consume_date = function (field, line) {
    let words = line.split(" ")
    parser.check_format(3, field, words)

    if (!parser.is_valid_date(words[1])) throw `Invalid date: ${words[1]} is not a valid date`
    if (!parser.is_valid_time(words[2])) throw `Invalid time: ${words[2]} is not a valid time`

    return {
        "date": words[1],
        "time": words[2]
    }
}

/**
* Consume the lines of protocols composed by ranges
* @param {string} type either protocols or proto
* @param {Array} lines the raw file split by '\n'
* @param {Number} index the index of the line
* @param {object} node the node we want to update
* @returns the updated node
*/
parser.consume_proto = function (type, lines, index, node) {
    parser.check_reused(type, node)
    let ranges = lines[index].split(" ").splice(1)
    node[type] = parser.parse_range(ranges)
    return node
}

/**
 * Check if the field has already been parsed for the descriptor
 * @param {string} field the field we want to verify
 * @param {object} node the node for which we don't want a repetition of field
 */
parser.check_reused = function (field, node) {
    if (node[field] !== undefined) throw `The field ${field} appears more than once`
}

/**
 * Add the ending = for a base64 string
 * @param {string} str the string we want to modify
 * @returns {string} base 64 string with correct ending = 
 */
parser.add_ending = function (str) {
    if (str.length % 4 !== 0) {
        let rem = str.length % 4
        for (let i = 0; i < 4 - rem; i++) str += '='
    }
    return str
}





