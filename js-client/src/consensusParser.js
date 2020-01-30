/**
 * @module consensusParser
 */

let consensusParser = {};

consensusParser.parse = function (rawText, flavor = 'microdesc') {
    if (typeof rawText !== 'string') throw `Error: the consensus must be given as a string`
    consensusParser.lines = rawText.split('\n')
    consensusParser.words = consensusParser.lines[0].split(' ')
    consensusParser.consensus = {}
    consensusParser.validFlags = ['Authority', 'BadExit', 'Exit', 'Fast', 'Guard', 'HSDir', 'NoEdConsensus', 'Stable', 'StaleDesc', 'Running', 'Valid', 'V2Dir']
    consensusParser.index = 0
    consensusParser.totalLines = consensusParser.lines.length

    if (flavor != 'unflavored' && flavor != 'microdesc') {
        throw 'Error: Unexpected flavor'
    }
    consensusParser.consensus['flavor'] = flavor

    consensusParser.consumeHeaders()
    consensusParser.consumeAuthority()
    consensusParser.consumeRouters()
    consensusParser.consumeFooter()

    return consensusParser.consensus
}

//----------------------------------HEADERS PARSER--------------------------------

/**
 * Function that parses the headers
 */
consensusParser.consumeHeaders = function () {
    consensusParser.consumeNetworkStatusVersion()
    consensusParser.consumeVoteStatus()
    consensusParser.consumeConsensusMethod()
    consensusParser.consumeDate('valid-after')
    consensusParser.consumeDate('fresh-until')
    consensusParser.consumeDate('valid-until')
    consensusParser.consumeVotingDelay()
    consensusParser.tryConsumeVersions('client-versions')
    consensusParser.tryConsumeVersions('server-versions')

    while (consensusParser.words[0] === 'package') {
        consensusParser.consumePackage()
    }

    consensusParser.consumeKnownFlags()
    consensusParser.tryConsumeProtocols('recommended-client-protocols')
    consensusParser.tryConsumeProtocols('recommended-relay-protocols')
    consensusParser.tryConsumeProtocols('required-client-protocols')
    consensusParser.tryConsumeProtocols('required-relay-protocols')
    consensusParser.tryConsumeParams()
    consensusParser.tryConsumeShareRand('shared-rand-previous-value')
    consensusParser.tryConsumeShareRand('shared-rand-current-value')

}

/**
 * Parse the field network-status-version
 */
consensusParser.consumeNetworkStatusVersion = function () {
    let expectedLength = 2
    if (consensusParser.consensus.flavor == 'microdesc') {
        expectedLength = 3
        if (consensusParser.words[2] != 'microdesc')
            throw 'Error: Flavor mismatch in header.'
    }

    let version = consensusParser.tryParseKeyValueInteger('network-status-version', expectedLength)
    consensusParser.consensus['headers'] = {
        'network-status-version': {
            'version': version,
            'flavor': consensusParser.consensus.flavor
        }
    }

    consensusParser.nextLine()
}

/**
 * Parse the field vote-status
 * @throws WrongParameterException if status is not consensus
 */
consensusParser.consumeVoteStatus = function () {
    let status = consensusParser.tryParseKeyValueString('vote-status')
    if (status !== 'consensus') throw `WrongParameterException: vote-status must be consensus`
    consensusParser.consensus['headers']['vote-status'] = status
    consensusParser.nextLine()
}

/**
 * Parse the field consensus-method
 */
consensusParser.consumeConsensusMethod = function () {
    consensusParser.consensus['headers']['consensus-method'] = consensusParser.tryParseKeyValueInteger('consensus-method')
    consensusParser.nextLine()
}

/**
 * Parse the fields valid-after, fresh-until and valid-until
 * @param {strin} word 
 */
consensusParser.consumeDate = function (word) {
    consensusParser.consensus['headers'][word] = consensusParser.tryParseDate(word)
    consensusParser.nextLine()
}

/**
 * Parse the field voting-delay
 * @throws NotEqualException if consensusParser.words[0] != word
 * @throws WrongParameterException if consensusParser.words[1] or consensusParser.words[2] is not a number
 * @throws WrongFormatException if consensusParser.words.length is not 3
 */
consensusParser.consumeVotingDelay = function () {
    consensusParser.checkFormat(3, 'voting-delay')
    if (isNaN(consensusParser.words[1])) throw `WrongParameterException: ${words[1]} is not a number`
    if (isNaN(consensusParser.words[2])) throw `WrongParameterException: ${words[2]} is not a number`

    consensusParser.consensus['headers']['voting-delay'] = {
        'vote': Number(consensusParser.words[1]),
        'dist': Number(consensusParser.words[2])
    }

    consensusParser.nextLine()
}

/**
 * Try to parse the fields client-versions or server-versions if they are present
 * @param {string} word either client-versions or server-versions
 */
consensusParser.tryConsumeVersions = function (word) {

    if (consensusParser.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
    if (consensusParser.words[0] === word) {
        consensusParser.consensus['headers'][word] = consensusParser.tryParseCommaSeparatedList(word)
        consensusParser.nextLine()
    }
}

/**
 * Parses the field package
 * @throws WrongFormatException if consensusParser.words.length is smaller than 5
 */
consensusParser.consumePackage = function () {

    if (consensusParser.words.length < 5) throw `WrongFormatException: at least 5 fields are expected`
    if (consensusParser.consensus['headers']['package'] === undefined) consensusParser.consensus['headers']['package'] = []

    let pack = {
        'name': consensusParser.words[1],
        'version': consensusParser.words[2],
        'url': consensusParser.words[3]
    }
    let remaining = consensusParser.words.splice(4, consensusParser.words.length)
    let digests = {}

    for (let digest of remaining) {
        let tmp = digest.split('=')
        digests[tmp[0]] = tmp[1]
    }

    pack['digests'] = digests
    consensusParser.consensus['headers']['package'].push(pack)
    consensusParser.nextLine()
}

/**
 * Parses the field package
 * @throws NotValidFlagException if one of the flags is not in the valid flag list
 */
consensusParser.consumeKnownFlags = function () {
    consensusParser.consensus['headers']['flags'] = consensusParser.tryParseFlags()
    consensusParser.nextLine()
}

/**
 * Try to parse the fields recommended-client-protocols, recommended-relay-protocols, required-client-protocols and required-client-protocols if they are present
 * @param {string} word either client-versions or server-versions
 */
consensusParser.tryConsumeProtocols = function (word) {
    if (consensusParser.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
    if (consensusParser.words[0] === word) {
        consensusParser.consensus['headers'][word] = consensusParser.tryParseRanges(consensusParser.words.splice(1, consensusParser.words.length))
        consensusParser.nextLine()
    }

}
/**
 * Try to parse the field params if it is present
 */
consensusParser.tryConsumeParams = function () {
    if (consensusParser.words[0] === 'params') {
        consensusParser.consensus['headers']['params'] = consensusParser.tryParseParams()
        consensusParser.nextLine()
    }
}

/**
 * Try to parse the fields shared-rand-previous-value and shared-rand-current-value if they are present
 * @param {string} word specify the field 
 */
consensusParser.tryConsumeShareRand = function (word) {
    if (consensusParser.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
    if (consensusParser.words[0] === word) {
        let reveals = Number(consensusParser.words[1])
        let value = consensusParser.words[2]

        if (!consensusParser.isBase64(value)) throw `InvalidParameterException: value ${value} must be in hexadecimal`

        consensusParser.consensus['headers'][word] = {
            'NumReveals': reveals,
            'Value': value
        }

        consensusParser.nextLine()
    }
}

//-------------------AUTHORITY PARSER--------------------------------
/**
 * Parses the authority part of the consensus
 * @throws InvalidIPException if address or IP are not valid IP addresses
 * @throws InvalidPortException if dirport or orport are not valid ports
 */
consensusParser.consumeAuthority = function () {
    if (consensusParser.words[0] !== 'dir-source') throw `WrongFieldException: there must be at least one dir-source`
    consensusParser.consensus['dir-sources'] = []

    while (consensusParser.words[0] === 'dir-source') {
        consensusParser.consumeDirSource()
    }
}

/**
 * Parse a dir-source
 * @throws InvalidIPException if the IP-address is not valid
 * @throws InvalidPortException if dirport or orport are not valid
 * @throws InvalidParameterException if the vote-digest is not in hexadecimal
 */
consensusParser.consumeDirSource = function () {
    let dirSource = {}
    consensusParser.checkFormat(7, 'dir-source')

    dirSource['nickname'] = consensusParser.words[1]

    if (!consensusParser.isHex(consensusParser.words[2])) throw `InvalidParameterException: vote-digest ${consensusParser.words[2]} must be in hexadecimal`
    dirSource['identity'] = consensusParser.words[2].toUpperCase()

    dirSource['hostname'] = consensusParser.words[3]

    if (!consensusParser.isValidIP(consensusParser.words[4])) throw `InvalidIPException: ${consensusParser.words[4]} is not a valid IP`

    dirSource['address'] = consensusParser.words[4]

    if (!consensusParser.isValidPort(Number(consensusParser.words[5])) || !consensusParser.isValidPort(Number(consensusParser.words[6]))) throw `InvalidPortException`

    dirSource['dirport'] = Number(consensusParser.words[5])
    dirSource['orport'] = Number(consensusParser.words[6])

    consensusParser.nextLine()
    dirSource['contact'] = consensusParser.words.splice(1, consensusParser.words.length).join(' ')
    consensusParser.nextLine()
    let digest = consensusParser.tryParseKeyValueString('vote-digest').toUpperCase()

    if (!consensusParser.isHex(digest)) throw `InvalidParameterException: vote-digest ${digest} must be in hexadecimal`

    dirSource['vote-digest'] = digest
    consensusParser.consensus['dir-sources'].push(dirSource)
    consensusParser.nextLine()


}

//-------------------ROUTER PARSER-----------------------------------
/**
 * Consume each router status entry
 * @throws WrongFieldException if there is no router entry
 */
consensusParser.consumeRouters = function () {
    if (consensusParser.words[0] !== 'r') throw `WrongFieldException: there must be at least one router`
    consensusParser.consensus['routers'] = []

    while (consensusParser.words[0] === 'r') {
        let router = {}
        consensusParser.consumeRfield(router)

        if (consensusParser.words[0] === 'a') router['a'] = []
        while (consensusParser.words[0] === 'a') {
            consensusParser.consumeAfield(router)
        }

        if (consensusParser.consensus.flavor == 'microdesc') {
            consensusParser.consumeMfield(router)
        }

        consensusParser.consumeSfield(router)
        consensusParser.tryConsumeVfield(router)
        consensusParser.tryConsumePrField(router)
        consensusParser.tryConsumeWfield(router)
        consensusParser.tryConsumePfield(router)

        consensusParser.consensus['routers'].push(router)
    }

}

/**
 * Parses the field 'r' of the router status entry
 * @param {} router 
 * @throws InvalidParameterException if the fields are not valid
 */
consensusParser.consumeRfield = function (router) {
    let len = 9
    if (consensusParser.consensus.flavor == 'microdesc') len = 8
    consensusParser.checkFormat(len, 'r')

    router['nickname'] = consensusParser.words[1]

    if (!consensusParser.isBase64(consensusParser.words[2] + "=")) throw `InvalidParameterException: identity ${consensusParser.words[2]} must be in base64`
    router['identity'] = consensusParser.words[2]

    let nxt = 3
    if (consensusParser.consensus.flavor == 'unflavored') {
        if (!consensusParser.isBase64(consensusParser.words[3] + "=")) throw `InvalidParameterException: digest ${consensusParser.words[3]} must be in base64`
        router['digest'] = consensusParser.words[3]
        nxt += 1
    }

    if (!consensusParser.isValidDate(consensusParser.words[nxt])) throw `InvalidParameterException: date ${consensusParser.words[nxt]} must have the format YYYY-MM-DD`
    router['date'] = consensusParser.words[nxt]

    if (!consensusParser.isValidTime(consensusParser.words[nxt + 1])) throw `InvalidParameterException: time ${consensusParser.words[nxt + 1]} must have the format HH:MM:SS`
    router['time'] = consensusParser.words[nxt + 1]

    if (!consensusParser.isValidIP(consensusParser.words[nxt + 2])) throw `InvalidParameterException: IP ${consensusParser.words[nxt + 2]} must be a valid IP address`
    router['address'] = consensusParser.words[nxt + 2]

    if (!consensusParser.isValidPort(Number(consensusParser.words[nxt + 3]))) throw `InvalidParameterException: ORPort ${consensusParser.words[nxt + 3]} must be a valid port`
    router['orport'] = Number(consensusParser.words[nxt + 3])

    if (!consensusParser.isValidPort(Number(consensusParser.words[nxt + 4]))) throw `InvalidParameterException: DirPort ${consensusParser.words[nxt + 4]} must be a valid port`
    router['dirport'] = Number(consensusParser.words[nxt + 4])

    consensusParser.nextLine()
}

/**
 * Parses the field 'a' of the router status entry
 * @param {} router 
 * @throws InvalidParameterException if the fields are not valid
 */
consensusParser.consumeAfield = function (router) {
    let i = consensusParser.words[1].indexOf("]")
    let address = consensusParser.words[1].slice(1, i)
    if (!consensusParser.isValidIP(address)) throw `InvalidParameterException: IP ${address} must be a valid IP address`

    let guessedType = 'IPv6'
    if (consensusParser.isIPv4(address)) {
        guessedType = 'IPv4'
    }

    let port = Number(consensusParser.words[1].slice(address.length + 3, consensusParser.words[1].length))

    if (!consensusParser.isValidPort(port)) throw `InvalidParameterException: port ${port} must be a valid port`

    router['a'].push({
        'ip': address,
        'port': port,
        'type': guessedType
    })

    consensusParser.nextLine()

}

/**
 * Parses the field 's' of the router status entry
 * @param {} router 
 */
consensusParser.consumeSfield = function (router) {
    router['flags'] = consensusParser.tryParseFlags()
    consensusParser.nextLine()
}

/**
 * Tries to parse the field 'v' of the router status entry
 * @param {} router 
 */
consensusParser.tryConsumeVfield = function (router) {
    if (consensusParser.words[0] === 'v') {
        consensusParser.checkFormat(3, 'v')
        router['version'] = consensusParser.words.splice(1, consensusParser.words.length).join(' ')
        consensusParser.nextLine()
    }
}
/**
 * Tries to parse the field 'v' of the router status entry
 * @param {} router 
 */
consensusParser.tryConsumePrField = function (router) {
    if (consensusParser.words[0] === 'pr') {
        router['protocols'] = consensusParser.tryParseRanges(consensusParser.words.splice(1, consensusParser.words.length))
        consensusParser.nextLine()
    }
}
/**
 * Tries to parse the field 'w' of the router status entry
 * @param {} router 
 */
consensusParser.tryConsumeWfield = function (router) {
    if (consensusParser.words[0] === 'w') {
        router['w'] = consensusParser.tryParseParams()
        consensusParser.nextLine()
    }
}
/**
 * Tries to parse the field 'p' of the router status entry
 * @param {} router 
 */
consensusParser.tryConsumePfield = function (router) {
    if (consensusParser.words[0] === 'p') {
        consensusParser.checkFormat(3, 'p')
        if (consensusParser.words[1] !== 'accept' && consensusParser.words[1] !== 'reject') throw `WrongParameterException: ${consensusParser.words[1]} must be either accept or reject`


        let portList = consensusParser.parse_range_once(consensusParser.words[2])

        router['exit-policy'] = {
            'type': consensusParser.words[1],
            'PortList': portList
        }
        consensusParser.nextLine()
    }
}

/**
 * Parses the field 'm' of the router status entry (for microdesc flavor)
 * @param {} router 
 */
consensusParser.consumeMfield = function (router) {
    consensusParser.checkFormat(2, 'm')

    if (!consensusParser.isBase64(consensusParser.words[1] + "=")) throw `InvalidParameterException: digest ${consensusParser.words[1]} must be in base64`
    router['micro-digest'] = consensusParser.words[1]

    consensusParser.nextLine()
}


//-------------------FOOTER PARSER ----------------------------------

/**
 * Consume the footer
 * @throws WrongFieldException if there is no footer or no signature
 */
consensusParser.consumeFooter = function () {
    if (consensusParser.words[0] !== 'directory-footer') throw `WrongFieldException: there must be a footer`
    consensusParser.nextLine()
    consensusParser.consensus['footer'] = {}
    consensusParser.tryConsumeBandwidthWeights()

    if (consensusParser.words[0] !== 'directory-signature') throw `WrongFieldException: there must be at least one signature`
    consensusParser.consensus['footer']['directory-signatures'] = []

    while (consensusParser.words[0] === 'directory-signature') {
        consensusParser.consensus['footer']['directory-signatures'].push(consensusParser.consumeSignature());
    }

}

/**
 * Tries to consume the bandwidth weights
 */
consensusParser.tryConsumeBandwidthWeights = function () {
    if (consensusParser.words[0] === 'bandwidth-weights') {
        consensusParser.consensus['footer']['bandwidth-weights'] = consensusParser.tryParseParams()
        consensusParser.nextLine()
    }
}

/**
 * Consumes the signature
 * @throws WrongFieldException if the first field is not directory-signature
 * @throws InvalidParameterException if either the identity or the signing-key-digest are not in hexadecimal
 */
consensusParser.consumeSignature = function () {
    if (consensusParser.words[0] !== 'directory-signature') throw `WrongFieldException: next field must be directory-signature`
    let length = consensusParser.words.length

    let algo
    let remaining
    if (length === 4) {
        algo = consensusParser.words[1]
        remaining = consensusParser.words.splice(2, length)
    } else if (length === 3) {
        algo = 'sha1'
        remaining = consensusParser.words.splice(1, length)
    }
    else throw `WrongParameterException: directory-signature has 3 or 4 arguments`

    let identity = remaining[0]
    if (!consensusParser.isHex(identity)) throw `InvalidParameterException: the identity ${identity} must be in hexadecimal`

    let digest = remaining[1]
    if (!consensusParser.isHex(digest)) throw `InvalidParameterException: the signing-key-digest ${digest} must be in hexadecimal`

    consensusParser.nextLine()

    let signature = consensusParser.parseSignature()
    if (consensusParser.index < consensusParser.totalLines - 1) consensusParser.nextLine()

    return {
        'Algorithm': algo,
        'identity': identity,
        'signing-key-digest': digest,
        'signature': signature
    }
}
//-------------------GENERAL PARSER-----------------------------------

/**
* Parses lines with the format "field value" where value is an integer and field must be equal to word and return value. 
* @param {string} word indicates to which field we are adding the newly parsed line
* @throws NotEqualException if consensusParser.words[0] != word
* @throws WrongParameterException if consensusParser.words[1] is not a number
* @throws WrongFormatException if consensusParser.words.length is not 2
*/
consensusParser.tryParseKeyValueInteger = function (word, expectedLength = 2) {
    consensusParser.checkFormat(expectedLength, word)
    if (isNaN(consensusParser.words[1])) throw `WrongParameterException: ${consensusParser.words[1]} is not a number`

    return Math.floor(consensusParser.words[1])
}

/**
 * Parses lines with the format "field value" where value is a string and field must be equal to word and return value. 
 * @param {string} word indicates to which field we are adding the newly parsed line
 * @throws NotEqualException if consensusParser.words[0] != word
 * @throws WrongFormatException if consensusParser.words.length is not 2
 */
consensusParser.tryParseKeyValueString = function (word) {
    consensusParser.checkFormat(2, word)
    return consensusParser.words[1]
}

/**
 * Parses lines with the format "field YYYY-MM-DD HH:MM:SS" where field must be equal to word and return a date object
 * @param {string} word indicates to which field we are adding the newly parsed line
 * @throws NotEqualException if consensusParser.words[0] != word
 * @throws WrongFormatException if consensusParser.words.length is not 2
 * @throws NonValidDateException if the date is not valid
 * @throws NonValidTimeException if the time is not valid
 */
consensusParser.tryParseDate = function (word) {
    consensusParser.checkFormat(3, word)
    if (!consensusParser.isValidDate(consensusParser.words[1])) throw `NonValidDateException: ${consensusParser.words[1]} is not a valid date`
    if (!consensusParser.isValidTime(consensusParser.words[2])) throw `NonValidTimeException: ${consensusParser.words[2]} is not a valid time`

    return {
        "date": consensusParser.words[1],
        "time": consensusParser.words[2]
    }
}

/**
 * Parses lines with the format "field list" where list is a comma separated list, returns the list as an array
 * @param {string} word indicates to which field we are adding the newly parsed line
 * @throws NotEqualException if consensusParser.words[0] != word
 * @throws WrongFormatException if consensusParser.words.length is not 2
 */
consensusParser.tryParseCommaSeparatedList = function (word) {
    consensusParser.checkFormat(2, word)
    return consensusParser.words[1].split(",")
}

/**
* Parse the ranges of the protocols
* @param pairs Array of entries => Keyword=Values where values is the range
*/
consensusParser.tryParseRanges = function (pairs) {
    let content = {}

    for (let pair of pairs) {
        if (pair.includes("=")) {
            let tmp = pair.split("=")
            content[tmp[0]] = consensusParser.parse_range_once(tmp[1])
        }
    }

    return content
}

/**
* Helper function to parse the ranges of the protocols
* @param value the range we want to parse
*/
consensusParser.parse_range_once = function (value) {
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
 * Parse the flags
 * @throws NotValidFlagException if one of the flags is not valid
 */
consensusParser.tryParseFlags = function () {
    let flags = consensusParser.words.splice(1, consensusParser.words.length)

    for (let f of flags) {
        if (!consensusParser.validFlags.includes(f)) throw `NotValidFlagException: ${f} is not a valid flag`
    }

    return flags
}

/**
 * Parse signature 
 * @throws WrongFormatException if the line does not start with ----BEGIN
 */
consensusParser.parseSignature = function () {
    if (consensusParser.words[0] !== '-----BEGIN') throw `WrongFormatException`
    consensusParser.nextLine()
    let signature = ''
    while (consensusParser.lines[consensusParser.index] !== "-----END SIGNATURE-----") {
        signature += consensusParser.lines[consensusParser.index]
        consensusParser.nextLine()
    }
    return signature
}


/**
 * parase parameters
 */
consensusParser.tryParseParams = function () {
    let content = {}
    for (let param of consensusParser.words.splice(1, consensusParser.words.length)) {
        let tmp = param.split('=')
        content[tmp[0]] = Number(tmp[1])
    }
    return content
}

/**
* Check if the string in date has the format YYYY-MM-DD
* @param {string} time String representing the date
*/
consensusParser.isValidDate = function (date) {
    if (typeof date !== 'string') return false
    let regex = /^\d{4}[-](0[1-9]|1[012])[-](0[1-9]|[12][0-9]|3[01])$/
    return regex.test(date)
}

/**Check if the string time has the format HH:MM:SS
 * @param {string} time String representing the time
 */
consensusParser.isValidTime = function (time) {
    if (typeof time !== 'string') return false
    let regex = /^(0[0-9]|1[0-9]|2[0-3])[:][0-5][0-9][:][0-5][0-9]$/
    return regex.test(time)
}

/**
 * Check if the IP address is valid (either IPv4 or IPv6)
 * @param {string} IP the address we want to check
 */
consensusParser.isValidIP = function (IP) {
    let regex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/
    return regex.test(IP)
}

/**
 * Check if the IP is an IPv4 address
 * @param {string} IP 
 */
consensusParser.isIPv4 = function (IP) {
    let regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return regex.test(IP)
}

/**
 * Check if the given port is valid
 * @param {number} port
 */
consensusParser.isValidPort = function (port) {
    if (isNaN(port)) return false
    //TODO: < or <= ?
    return port >= 0 && port <= 65535
}

/**
 * Check if the given string is in hexadecimal
 * @param {string} str 
 */
consensusParser.isHex = function (str) {
    let regex = /^[a-fA-F0-9]+$/
    return regex.test(str)
}

/**
 * Check if the given string is in base 64
 * @param {string} str 
 */
consensusParser.isBase64 = function (str) {
    let regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
    return regex.test(str)
}

/**
 * Updates consensusParser.index and consensusParser.words
 * @throws EndOfFileException if the end of the file has already been reached
 */
consensusParser.nextLine = function () {
    if (consensusParser.index >= consensusParser.totalLines) throw `EndOfFileException: there are no lines to parse`
    consensusParser.words = consensusParser.lines[++consensusParser.index].split(" ")
}

/**
 * Checks if words has the expected size and that words[0] is equal to word
 * @param {number} expectedLength the expected length of words
 * @param {string} expectedWord the expected word[0]
 */
consensusParser.checkFormat = function (expectedLength, expectedWord) {
    if (consensusParser.words.length != expectedLength) throw `WrongFormatException: ${expectedLength} fields are expected`
    if (consensusParser.words[0] != expectedWord) throw `NotEqualException:b ${expectedWord} is not equal to ${consensusParser.words[0]}`
}

export { consensusParser };