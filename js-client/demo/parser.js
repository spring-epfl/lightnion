//TODO: add lnn in front of all functions!
parser = {}

parser.descriptors = {
    line_count: 0,
    lines: undefined,

    parse: function (raw_descriptors, endpoint) {
        let descriptors = []
        parser.descriptors.lines = raw_descriptors.split('\n')
        if (parser.descriptors.lines[0].startsWith('@')) parser.descriptors.line_count++
        let descriptor = parser.descriptors.consume_one_node()
        descriptors.push(descriptor)
        return descriptors
    }
}

/**
 * Parse one node in the raw data file
 * @returns {object} the descriptor of the parsed node
 */
parser.descriptors.consume_one_node = function () {
    let descriptor = {}
    descriptor = parser.descriptors.consume_router(descriptor)
    descriptor = parser.descriptors.try_consume_identity_ed25519(descriptor)

    let line = parser.descriptors.lines[parser.descriptors.line_count]

    while (!line.startsWith("router-signature")) {
        let index_sp = line.indexOf(" ")
        let first_word = line.substring(0, index_sp)
        console.log(first_word)
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
            case "uptime":
                descriptor = parser.descriptors.consume_uptime(descriptor)
                break
            case "onion-key":
                descriptor = parser.descriptors.consume_onion_key(descriptor)
                break
            default:
                ++parser.descriptors.line_count
                break
        }
        line = parser.descriptors.lines[parser.descriptors.line_count]

    }

    //TODO: Check the exactly once!
    return descriptor
}

/**
 * Consume the field router of the descriptor
 * @param{Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
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
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.try_consume_identity_ed25519 = function (descriptor) {
    let words = parser.descriptors.lines[parser.descriptors.line_count].split(' ')
    if (words[0] === 'identity-ed25519') {
        parser.check_format(1, 'identity-ed25519', words)
        ++parser.descriptors.line_count

        let [offset, certificate] = parser.consume_pem(parser.descriptors.lines, parser.descriptors.line_count, parser.is_valid_base64)
        parser.descriptors.line_count += offset + 1
        descriptor['identity'] = {
            "type": "ed25519",
            "cert": certificate
        }

        return descriptor
    }
}

/**
 * Parse the master-key-ed25519
 * param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_master_key_ed25519 = function (descriptor) {

    let words = parser.descriptors.lines[parser.descriptors.line_count].split(' ')
    parser.check_format(2, 'master-key-ed25519', words)
    parser.check_reused('master-key-ed25519', descriptor)

    //TODO: find out why oQmcJgMFqDbPKU4O7FXCbfAuvvP/CEJLiZhQPTXVYqE is not valid with the regex
    //if(!parser.is_valid_base64(words[1])) throw `Invalid master key: the master key ${words[1]} must be in base64`
    descriptor['identity']['master-key'] = words[1]
    parser.descriptors.line_count++

    return descriptor
}

/**
 * Consume the line if it starts with platform
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
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
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_published = function (descriptor) {
    parser.check_reused('published', descriptor)
    descriptor['published'] = parser.consume_date('published', parser.descriptors.lines[parser.descriptors.line_count])
    ++parser.descriptors.line_count
    return descriptor
}

/**
 * Consume the bandwidth fields 
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_bandwidth = function (descriptor) {
    parser.check_reused('bandwidth', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(4, 'bandwidth', words)

    let avg = Number(words[1])
    let burst = Number(words[2])
    let obs = Number(words[3])

    if(avg < 0 || burst < 0 || obs < 0) throw `Invalid bandwidth: must be non-negative`

    descriptor['bandwidth'] = {
        "avg": avg,
        "burst": burst ,
        "observed": obs
    }

    return descriptor
}

/**
 * Consume the fingerprint field
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_fingerprint = function (descriptor) {
    parser.check_reused('fingerprint', descriptor)
    let line = parser.descriptors.lines[parser.descriptors.line_count++]
    let index_sp = line.indexOf(" ")
    let fingerprint = line.substring(index_sp + 1)

    let bytes = fingerprint.split(" ")

    if (bytes.length != 10) throw `Invalid fingerprint: wrong size`
    if (!parser.is_valid_hex(bytes.join(""))) throw `Invalid fingerprint: not a hex string`


    descriptor['fingerprint'] = fingerprint

    return descriptor
}

/**
 * Consume the hibernating field
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_hibernating = function(descriptor){
    parser.check_reused('hibernating', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, 'hibernating', words)

    let b = Number(words[1])
    if(b !== 0 && b !== 1) throw `Invalid boolean`
    descriptor['hibernating'] = b
    return descriptor
}

/**
 * Consume the uptime field
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_uptime = function(descriptor){
    parser.check_reused('uptime', descriptor)
    let words = parser.descriptors.lines[parser.descriptors.line_count++].split(" ")
    parser.check_format(2, 'uptime', words)

    let uptime = Number(words[1])

    if(uptime < 0) throw `Invalid uptime: uptime must be non-negative`

    descriptor['uptime'] = uptime

    return descriptor
}

/**
 * Consume the onion key
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_onion_key = function(descriptor){
    console.log("\n\n hey \n\n")
    [offset, key] = parser.consume_pem(parser.descriptors.lines, ++parser.descriptors.line_count, is_valid_base64)
    parser.descriptors.line_count += offset+1
    descriptor['onion-key'] = key
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
parser.consume_pem = function (lines, start, base_function) {
    let offset = 0;
    let content = ''
    if (!lines[start].startsWith('-----BEGIN')) throw `Invalid signature, certificate or key: must begin with "-----BEGIN"`
    offset++
    while (!lines[start + offset].startsWith("-----END")) {
        content += lines[start + offset]
        offset++
    }

    if (base_function !== undefined) base_function(content)

    return [offset, content]
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
 * Check if the field has already been parsed for the descriptor
 * @param {string} field the field we want to verify
 * @param {object} decriptors the descriptor we are building
 */
parser.check_reused = function (field, descriptor) {
    if (descriptor[field] != undefined) throw `The field ${field} appearts more than once`
}





