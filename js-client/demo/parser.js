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
    descriptor = parser.descriptors.try_consume_platform(descriptor)
    descriptor = parser.descriptors.consume_published(descriptor)

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

        let [offset, certificate] = parser.consume_sign_cert_key(parser.descriptors.lines, parser.descriptors.line_count, parser.is_valid_base64)
        parser.descriptors.line_count += offset + 1
        descriptor['identity'] = {
            "type": "ed25519",
            "cert": certificate
        }

        words = parser.descriptors.lines[parser.descriptors.line_count].split(' ')
    }

    if (words[0] === 'master-key-ed25519') {
        parser.check_format(2, 'master-key-ed25519', words)
        //TODO: find out why oQmcJgMFqDbPKU4O7FXCbfAuvvP/CEJLiZhQPTXVYqE is not valid with the regex
        //if(!parser.is_valid_base64(words[1])) throw `Invalid master key: the master key ${words[1]} must be in base64`
        descriptor['identity']['master-key'] = words[1]
        parser.descriptors.line_count++
    }

    return descriptor
}

/**
 * Consume the line if it starts with platform
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.try_consume_platform = function (descriptor) {
    let line = parser.descriptors.lines[parser.descriptors.line_count]
    if (line.startsWith("platform")) {
        let platform = line.substring("platform".length + 1, line.length)
        descriptor['platform'] = platform
        parser.descriptors.line_count++
    }

    return descriptor
}

/**
 * Consume the time of the published field
 * @param {Object} descriptors the currently being built decriptors object
 * @returns {Object} descriptors the currently being built decriptors object
 */
parser.descriptors.consume_published = function (descriptor) {
    descriptor['published'] = parser.consume_date('published', parser.descriptors.lines[parser.descriptors.line_count])
    ++parser.descriptors.line_count
    return descriptor
}

/**
* Checks if words has the expected size and that the first word of the line is equal to a given word
* @param {number} expected_length the expected length of the line
* @param {string} expected_word the expected word
* @param {Array} words the line splitted into words
*/
parser.check_format = function (expected_length, expected_word, words) {
    if (words.length != expected_length) throw `wrong_format_exception: ${expected_length} fields are expected`
    if (words[0] !== expected_word) throw `not_equal_exception: ${expected_word} is not equal to ${words[0]}`
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

parser.consume_sign_cert_key = function (lines, start, base_function) {
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





