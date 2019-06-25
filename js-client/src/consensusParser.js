lnn.consensusParser = {} 
lnn.consensusParser.parse = function(rawText,flavor = 'unflavored') {
    if (typeof rawText !== 'string') throw `Error: the consensus must be given as a string`
    lnn.consensusParser.lines = rawText.split('\n')
    lnn.consensusParser.words = lnn.consensusParser.lines[0].split(' ')
    lnn.consensusParser.consensus = {}
    lnn.consensusParser.validFlags = ['Authority', 'BadExit', 'Exit', 'Fast', 'Guard', 'HSDir', 'NoEdConsensus', 'Stable', 'StaleDesc', 'Running', 'Valid', 'V2Dir']
    lnn.consensusParser.index = 0
    lnn.consensusParser.totalLines = lnn.consensusParser.lines.length

    if(flavor != 'unflavored' && flavor != 'microdesc') {
        throw 'Error: Unexpected flavor'
    }
    lnn.consensusParser.consensus['flavor'] = flavor

    lnn.consensusParser.consumeHeaders()
    lnn.consensusParser.consumeAuthority()
    lnn.consensusParser.consumeRouters()
    lnn.consensusParser.consumeFooter()

    return lnn.consensusParser.consensus
}

//----------------------------------HEADERS PARSER--------------------------------

/**
 * Function that parses the headers
 */
lnn.consensusParser.consumeHeaders = function() {
    lnn.consensusParser.consumeNetworkStatusVersion()
    lnn.consensusParser.consumeVoteStatus()
    lnn.consensusParser.consumeConsensusMethod()
    lnn.consensusParser.consumeDate('valid-after')
    lnn.consensusParser.consumeDate('fresh-until')
    lnn.consensusParser.consumeDate('valid-until')
    lnn.consensusParser.consumeVotingDelay()
    lnn.consensusParser.tryConsumeVersions('client-versions')
    lnn.consensusParser.tryConsumeVersions('server-versions')

    while (lnn.consensusParser.words[0] === 'package') {
        lnn.consensusParser.consumePackage()
    }

    lnn.consensusParser.consumeKnownFlags()
    lnn.consensusParser.tryConsumeProtocols('recommended-client-protocols')
    lnn.consensusParser.tryConsumeProtocols('recommended-relay-protocols')
    lnn.consensusParser.tryConsumeProtocols('required-client-protocols')
    lnn.consensusParser.tryConsumeProtocols('required-relay-protocols')
    lnn.consensusParser.tryConsumeParams()
    lnn.consensusParser.tryConsumeShareRand('shared-rand-previous-value')
    lnn.consensusParser.tryConsumeShareRand('shared-rand-current-value')

}

/**
 * Parse the field network-status-version
 */
lnn.consensusParser.consumeNetworkStatusVersion = function() {
    let expectedLength = 2
    if(lnn.consensusParser.consensus.flavor == 'microdesc') {
        expectedLength = 3
        if(lnn.consensusParser.words[2] != 'microdesc')
            throw 'Error: Flavor mismatch in header.'
    }

    let version = lnn.consensusParser.tryParseKeyValueInteger('network-status-version',expectedLength)
    lnn.consensusParser.consensus['headers'] = {
        'network-status-version': {
            'version': version,
            'flavor': lnn.consensusParser.consensus.flavor
        }
    }

    lnn.consensusParser.nextLine()
}

/**
 * Parse the field vote-status
 * @throws WrongParameterException if status is not consensus
 */
lnn.consensusParser.consumeVoteStatus = function() {
    let status = lnn.consensusParser.tryParseKeyValueString('vote-status')
    if (status !== 'consensus') throw `WrongParameterException: vote-status must be consensus`
    lnn.consensusParser.consensus['headers']['vote-status'] = status
    lnn.consensusParser.nextLine()
}

/**
 * Parse the field consensus-method
 */
lnn.consensusParser.consumeConsensusMethod = function() {
    lnn.consensusParser.consensus['headers']['consensus-method'] = lnn.consensusParser.tryParseKeyValueInteger('consensus-method')
    lnn.consensusParser.nextLine()
}

/**
 * Parse the fields valid-after, fresh-until and valid-until
 * @param {strin} word 
 */
lnn.consensusParser.consumeDate = function(word) {
    lnn.consensusParser.consensus['headers'][word] = lnn.consensusParser.tryParseDate(word)
    lnn.consensusParser.nextLine()
}

/**
 * Parse the field voting-delay
 * @throws NotEqualException if lnn.consensusParser.words[0] != word
 * @throws WrongParameterException if lnn.consensusParser.words[1] or lnn.consensusParser.words[2] is not a number
 * @throws WrongFormatException if lnn.consensusParser.words.length is not 3
 */
lnn.consensusParser.consumeVotingDelay = function() {
    lnn.consensusParser.checkFormat(3, 'voting-delay')
    if (isNaN(lnn.consensusParser.words[1])) throw `WrongParameterException: ${words[1]} is not a number`
    if (isNaN(lnn.consensusParser.words[2])) throw `WrongParameterException: ${words[2]} is not a number`

    lnn.consensusParser.consensus['headers']['voting-delay'] = {
        'vote': Number(lnn.consensusParser.words[1]),
        'dist': Number(lnn.consensusParser.words[2])
    }

    lnn.consensusParser.nextLine()
}

/**
 * Try to parse the fields client-versions or server-versions if they are present
 * @param {string} word either client-versions or server-versions
 */
lnn.consensusParser.tryConsumeVersions = function(word) {

    if (lnn.consensusParser.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
    if (lnn.consensusParser.words[0] === word) {
        lnn.consensusParser.consensus['headers'][word] = lnn.consensusParser.tryParseCommaSeparatedList(word)
        lnn.consensusParser.nextLine()
    }
}

/**
 * Parses the field package
 * @throws WrongFormatException if lnn.consensusParser.words.length is smaller than 5
 */
lnn.consensusParser.consumePackage = function() {

    if (lnn.consensusParser.words.length < 5) throw `WrongFormatException: at least 5 fields are expected`
    if (lnn.consensusParser.consensus['headers']['package'] === undefined) lnn.consensusParser.consensus['headers']['package'] = []

    let pack = {
        'name': lnn.consensusParser.words[1],
        'version': lnn.consensusParser.words[2],
        'url': lnn.consensusParser.words[3]
    }
    let remaining = lnn.consensusParser.words.splice(4, lnn.consensusParser.words.length)
    let digests = {}

    for (let digest of remaining) {
        let tmp = digest.split('=')
        digests[tmp[0]] = tmp[1]
    }

    pack['digests'] = digests
    lnn.consensusParser.consensus['headers']['package'].push(pack)
    lnn.consensusParser.nextLine()
}

/**
 * Parses the field package
 * @throws NotValidFlagException if one of the flags is not in the valid flag list
 */
lnn.consensusParser.consumeKnownFlags = function() {
    lnn.consensusParser.consensus['headers']['flags'] = lnn.consensusParser.tryParseFlags()
    lnn.consensusParser.nextLine()
}

/**
 * Try to parse the fields recommended-client-protocols, recommended-relay-protocols, required-client-protocols and required-client-protocols if they are present
 * @param {string} word either client-versions or server-versions
 */
lnn.consensusParser.tryConsumeProtocols = function(word) {
    if (lnn.consensusParser.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
    if (lnn.consensusParser.words[0] === word) {
        lnn.consensusParser.consensus['headers'][word] = lnn.consensusParser.tryParseRanges(lnn.consensusParser.words.splice(1, lnn.consensusParser.words.length))
        lnn.consensusParser.nextLine()
    }

}
/**
 * Try to parse the field params if it is present
 */
lnn.consensusParser.tryConsumeParams = function() {
    if (lnn.consensusParser.words[0] === 'params') {
        lnn.consensusParser.consensus['headers']['params'] = lnn.consensusParser.tryParseParams()
        lnn.consensusParser.nextLine()
    }
}

/**
 * Try to parse the fields shared-rand-previous-value and shared-rand-current-value if they are present
 * @param {string} word specify the field 
 */
lnn.consensusParser.tryConsumeShareRand = function(word) {
    if (lnn.consensusParser.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
    if (lnn.consensusParser.words[0] === word) {
        let reveals = Number(lnn.consensusParser.words[1])
        let value = lnn.consensusParser.words[2]

        if (!lnn.consensusParser.isBase64(value)) throw `InvalidParameterException: value ${value} must be in hexadecimal`

        lnn.consensusParser.consensus['headers'][word] = {
            'NumReveals': reveals,
            'Value': value
        }

        lnn.consensusParser.nextLine()
    }
}

//-------------------AUTHORITY PARSER--------------------------------
/**
 * Parses the authority part of the consensus
 * @throws InvalidIPException if address or IP are not valid IP addresses
 * @throws InvalidPortException if dirport or orport are not valid ports
 */
lnn.consensusParser.consumeAuthority = function() {
    if (lnn.consensusParser.words[0] !== 'dir-source') throw `WrongFieldException: there must be at least one dir-source`
    lnn.consensusParser.consensus['dir-sources'] = []

    while (lnn.consensusParser.words[0] === 'dir-source') {
        lnn.consensusParser.consumeDirSource()
    }
}

/**
 * Parse a dir-source
 * @throws InvalidIPException if the IP-address is not valid
 * @throws InvalidPortException if dirport or orport are not valid
 * @throws InvalidParameterException if the vote-digest is not in hexadecimal
 */
lnn.consensusParser.consumeDirSource = function() {
    let dirSource = {}
    lnn.consensusParser.checkFormat(7, 'dir-source')

    dirSource['nickname'] = lnn.consensusParser.words[1]

    if (!lnn.consensusParser.isHex(lnn.consensusParser.words[2])) throw `InvalidParameterException: vote-digest ${lnn.consensusParser.words[2]} must be in hexadecimal`
    dirSource['identity'] = lnn.consensusParser.words[2].toUpperCase()

    dirSource['hostname'] = lnn.consensusParser.words[3]

    if (!lnn.consensusParser.isValidIP(lnn.consensusParser.words[4])) throw `InvalidIPException: ${lnn.consensusParser.words[4]} is not a valid IP`

    dirSource['address'] = lnn.consensusParser.words[4]

    if (!lnn.consensusParser.isValidPort(Number(lnn.consensusParser.words[5])) || !lnn.consensusParser.isValidPort(Number(lnn.consensusParser.words[6]))) throw `InvalidPortException`

    dirSource['dirport'] = Number(lnn.consensusParser.words[5])
    dirSource['orport'] = Number(lnn.consensusParser.words[6])

    lnn.consensusParser.nextLine()
    dirSource['contact'] = lnn.consensusParser.words.splice(1, lnn.consensusParser.words.length).join(' ')
    lnn.consensusParser.nextLine()
    let digest = lnn.consensusParser.tryParseKeyValueString('vote-digest').toUpperCase()

    if (!lnn.consensusParser.isHex(digest)) throw `InvalidParameterException: vote-digest ${digest} must be in hexadecimal`

    dirSource['vote-digest'] = digest
    lnn.consensusParser.consensus['dir-sources'].push(dirSource)
    lnn.consensusParser.nextLine()


}

//-------------------ROUTER PARSER-----------------------------------
/**
 * Consume each router status entry
 * @throws WrongFieldException if there is no router entry
 */
lnn.consensusParser.consumeRouters = function() {
    if (lnn.consensusParser.words[0] !== 'r') throw `WrongFieldException: there must be at least one router`
    lnn.consensusParser.consensus['routers'] = []

    while (lnn.consensusParser.words[0] === 'r') {
        let router = {}
        lnn.consensusParser.consumeRfield(router)

        if (lnn.consensusParser.words[0] === 'a') router['a'] = []
        while (lnn.consensusParser.words[0] === 'a') {
            lnn.consensusParser.consumeAfield(router)
        }

        if(lnn.consensusParser.consensus.flavor == 'microdesc') {
            lnn.consensusParser.consumeMfield(router)
        }

        lnn.consensusParser.consumeSfield(router)
        lnn.consensusParser.tryConsumeVfield(router)
        lnn.consensusParser.tryConsumePrField(router)
        lnn.consensusParser.tryConsumeWfield(router)
        lnn.consensusParser.tryConsumePfield(router)

        lnn.consensusParser.consensus['routers'].push(router)
    }

}

/**
 * Parses the field 'r' of the router status entry
 * @param {} router 
 * @throws InvalidParameterException if the fields are not valid
 */
lnn.consensusParser.consumeRfield = function(router) {
    let len = 9
    if(lnn.consensusParser.consensus.flavor == 'microdesc') len = 8
    lnn.consensusParser.checkFormat(len, 'r')

    router['nickname'] = lnn.consensusParser.words[1]

    if (!lnn.consensusParser.isBase64(lnn.consensusParser.words[2] + "=")) throw `InvalidParameterException: identity ${lnn.consensusParser.words[2]} must be in base64`
    router['identity'] = lnn.consensusParser.words[2]
    
    let nxt = 3
    if(lnn.consensusParser.consensus.flavor == 'unflavored') {
        if (!lnn.consensusParser.isBase64(lnn.consensusParser.words[3] + "=")) throw `InvalidParameterException: digest ${lnn.consensusParser.words[3]} must be in base64`
        router['digest'] = lnn.consensusParser.words[3]
        nxt += 1
    }

    if (!lnn.consensusParser.isValidDate(lnn.consensusParser.words[nxt])) throw `InvalidParameterException: date ${lnn.consensusParser.words[nxt]} must have the format YYYY-MM-DD`
    router['date'] = lnn.consensusParser.words[nxt]

    if (!lnn.consensusParser.isValidTime(lnn.consensusParser.words[nxt + 1])) throw `InvalidParameterException: time ${lnn.consensusParser.words[nxt + 1]} must have the format HH:MM:SS`
    router['time'] = lnn.consensusParser.words[nxt + 1]

    if (!lnn.consensusParser.isValidIP(lnn.consensusParser.words[nxt + 2])) throw `InvalidParameterException: IP ${lnn.consensusParser.words[nxt + 2]} must be a valid IP address`
    router['address'] = lnn.consensusParser.words[nxt + 2]

    if (!lnn.consensusParser.isValidPort(Number(lnn.consensusParser.words[nxt + 3]))) throw `InvalidParameterException: ORPort ${lnn.consensusParser.words[nxt + 3]} must be a valid port`
    router['orport'] = Number(lnn.consensusParser.words[nxt + 3])

    if (!lnn.consensusParser.isValidPort(Number(lnn.consensusParser.words[nxt + 4]))) throw `InvalidParameterException: DirPort ${lnn.consensusParser.words[nxt + 4]} must be a valid port`
    router['dirport'] = Number(lnn.consensusParser.words[nxt + 4])

    lnn.consensusParser.nextLine()
}

/**
 * Parses the field 'a' of the router status entry
 * @param {} router 
 * @throws InvalidParameterException if the fields are not valid
 */
lnn.consensusParser.consumeAfield = function(router) {
    let i = lnn.consensusParser.words[1].indexOf("]")
    let address = lnn.consensusParser.words[1].slice(1, i)
    if (!lnn.consensusParser.isValidIP(address)) throw `InvalidParameterException: IP ${address} must be a valid IP address`

    let guessedType = 'IPv6'
    if (lnn.consensusParser.isIPv4(address)) {
        guessedType = 'IPv4'
    }

    let port = Number(lnn.consensusParser.words[1].slice(address.length + 3, lnn.consensusParser.words[1].length))

    if (!lnn.consensusParser.isValidPort(port)) throw `InvalidParameterException: port ${port} must be a valid port`

    router['a'].push({
        'ip': address,
        'port': port,
        'type': guessedType
    })

    lnn.consensusParser.nextLine()

}

/**
 * Parses the field 's' of the router status entry
 * @param {} router 
 */
lnn.consensusParser.consumeSfield = function(router) {
    router['flags'] = lnn.consensusParser.tryParseFlags()
    lnn.consensusParser.nextLine()
}

/**
 * Tries to parse the field 'v' of the router status entry
 * @param {} router 
 */
lnn.consensusParser.tryConsumeVfield = function(router) {
    if (lnn.consensusParser.words[0] === 'v') {
        lnn.consensusParser.checkFormat(3, 'v')
        router['version'] = lnn.consensusParser.words.splice(1, lnn.consensusParser.words.length).join(' ')
        lnn.consensusParser.nextLine()
    }
}
/**
 * Tries to parse the field 'v' of the router status entry
 * @param {} router 
 */
lnn.consensusParser.tryConsumePrField = function(router) {
    if (lnn.consensusParser.words[0] === 'pr') {
        router['protocols'] = lnn.consensusParser.tryParseRanges(lnn.consensusParser.words.splice(1, lnn.consensusParser.words.length))
        lnn.consensusParser.nextLine()
    }
}
/**
 * Tries to parse the field 'w' of the router status entry
 * @param {} router 
 */
lnn.consensusParser.tryConsumeWfield = function(router) {
    if (lnn.consensusParser.words[0] === 'w') {
        router['w'] = lnn.consensusParser.tryParseParams()
        lnn.consensusParser.nextLine()
    }
}
/**
 * Tries to parse the field 'p' of the router status entry
 * @param {} router 
 */
lnn.consensusParser.tryConsumePfield = function(router) {
    if (lnn.consensusParser.words[0] === 'p') {
        lnn.consensusParser.checkFormat(3, 'p')
        if (lnn.consensusParser.words[1] !== 'accept' && lnn.consensusParser.words[1] !== 'reject') throw `WrongParameterException: ${lnn.consensusParser.words[1]} must be either accept or reject`


        let portList = lnn.consensusParser.parse_range_once(lnn.consensusParser.words[2])

        router['exit-policy'] = {
            'type': lnn.consensusParser.words[1],
            'PortList': portList
        }
        lnn.consensusParser.nextLine()
    }
}

/**
 * Parses the field 'm' of the router status entry (for microdesc flavor)
 * @param {} router 
 */
lnn.consensusParser.consumeMfield = function(router) {
    lnn.consensusParser.checkFormat(2, 'm')
    
    if (!lnn.consensusParser.isBase64(lnn.consensusParser.words[1] + "=")) throw `InvalidParameterException: digest ${lnn.consensusParser.words[1]} must be in base64`
        router['micro-digest'] = lnn.consensusParser.words[1]
    
    lnn.consensusParser.nextLine()
}


//-------------------FOOTER PARSER ----------------------------------

/**
 * Consume the footer
 * @throws WrongFieldException if there is no footer or no signature
 */
lnn.consensusParser.consumeFooter = function() {
    if (lnn.consensusParser.words[0] !== 'directory-footer') throw `WrongFieldException: there must be a footer`
    lnn.consensusParser.nextLine()
    lnn.consensusParser.consensus['footer'] = {}
    lnn.consensusParser.tryConsumeBandwidthWeights()

    if (lnn.consensusParser.words[0] !== 'directory-signature') throw `WrongFieldException: there must be at least one signature`
    lnn.consensusParser.consensus['footer']['directory-signatures'] = []

    while (lnn.consensusParser.words[0] === 'directory-signature') {
        lnn.consensusParser.consensus['footer']['directory-signatures'].push(lnn.consensusParser.consumeSignature());
    }

}

/**
 * Tries to consume the bandwidth weights
 */
lnn.consensusParser.tryConsumeBandwidthWeights = function() {
    if (lnn.consensusParser.words[0] === 'bandwidth-weights') {
        lnn.consensusParser.consensus['footer']['bandwidth-weights'] = lnn.consensusParser.tryParseParams()
        lnn.consensusParser.nextLine()
    }
}

/**
 * Consumes the signature
 * @throws WrongFieldException if the first field is not directory-signature
 * @throws InvalidParameterException if either the identity or the signing-key-digest are not in hexadecimal
 */
lnn.consensusParser.consumeSignature = function() {
    if (lnn.consensusParser.words[0] !== 'directory-signature') throw `WrongFieldException: next field must be directory-signature`
    let length = lnn.consensusParser.words.length

    let algo
    let remaining
    if (length === 4) {
        algo = lnn.consensusParser.words[1]
        remaining = lnn.consensusParser.words.splice(2, length)
    } else if (length === 3) {
        algo = 'sha1'
        remaining = lnn.consensusParser.words.splice(1, length)
    }
    else throw `WrongParameterException: directory-signature has 3 or 4 arguments`

    let identity = remaining[0]
    if (!lnn.consensusParser.isHex(identity)) throw `InvalidParameterException: the identity ${identity} must be in hexadecimal`

    let digest = remaining[1]
    if (!lnn.consensusParser.isHex(digest)) throw `InvalidParameterException: the signing-key-digest ${digest} must be in hexadecimal`

    lnn.consensusParser.nextLine()

    let signature = lnn.consensusParser.parseSignature()
    if (lnn.consensusParser.index < lnn.consensusParser.totalLines - 1) lnn.consensusParser.nextLine()

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
* @throws NotEqualException if lnn.consensusParser.words[0] != word
* @throws WrongParameterException if lnn.consensusParser.words[1] is not a number
* @throws WrongFormatException if lnn.consensusParser.words.length is not 2
*/
lnn.consensusParser.tryParseKeyValueInteger = function(word,expectedLength = 2) {
    lnn.consensusParser.checkFormat(expectedLength, word)
    if (isNaN(lnn.consensusParser.words[1])) throw `WrongParameterException: ${lnn.consensusParser.words[1]} is not a number`

    return Math.floor(lnn.consensusParser.words[1])
}

/**
 * Parses lines with the format "field value" where value is a string and field must be equal to word and return value. 
 * @param {string} word indicates to which field we are adding the newly parsed line
 * @throws NotEqualException if lnn.consensusParser.words[0] != word
 * @throws WrongFormatException if lnn.consensusParser.words.length is not 2
 */
lnn.consensusParser.tryParseKeyValueString = function(word) {
    lnn.consensusParser.checkFormat(2, word)
    return lnn.consensusParser.words[1]
}

/**
 * Parses lines with the format "field YYYY-MM-DD HH:MM:SS" where field must be equal to word and return a date object
 * @param {string} word indicates to which field we are adding the newly parsed line
 * @throws NotEqualException if lnn.consensusParser.words[0] != word
 * @throws WrongFormatException if lnn.consensusParser.words.length is not 2
 * @throws NonValidDateException if the date is not valid
 * @throws NonValidTimeException if the time is not valid
 */
lnn.consensusParser.tryParseDate = function(word) {
    lnn.consensusParser.checkFormat(3, word)
    if (!lnn.consensusParser.isValidDate(lnn.consensusParser.words[1])) throw `NonValidDateException: ${lnn.consensusParser.words[1]} is not a valid date`
    if (!lnn.consensusParser.isValidTime(lnn.consensusParser.words[2])) throw `NonValidTimeException: ${lnn.consensusParser.words[2]} is not a valid time`

    return {
        "date": lnn.consensusParser.words[1],
        "time": lnn.consensusParser.words[2]
    }
}

/**
 * Parses lines with the format "field list" where list is a comma separated list, returns the list as an array
 * @param {string} word indicates to which field we are adding the newly parsed line
 * @throws NotEqualException if lnn.consensusParser.words[0] != word
 * @throws WrongFormatException if lnn.consensusParser.words.length is not 2
 */
lnn.consensusParser.tryParseCommaSeparatedList = function(word) {
    lnn.consensusParser.checkFormat(2, word)
    return lnn.consensusParser.words[1].split(",")
}

/**
* Parse the ranges of the protocols
* @param pairs Array of entries => Keyword=Values where values is the range
*/
lnn.consensusParser.tryParseRanges = function(pairs) {
    let content = {}

    for (let pair of pairs) {
        if (pair.includes("=")) {
            let tmp = pair.split("=")
            content[tmp[0]] = lnn.consensusParser.parse_range_once(tmp[1])
        }
    }

    return content
}

/**
* Helper function to parse the ranges of the protocols
* @param value the range we want to parse
*/
lnn.consensusParser.parse_range_once = function(value) {
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
lnn.consensusParser.tryParseFlags = function() {
    let flags = lnn.consensusParser.words.splice(1, lnn.consensusParser.words.length)
    
    for (let f of flags) {
        if (!lnn.consensusParser.validFlags.includes(f)) throw `NotValidFlagException: ${f} is not a valid flag`
    }

    return flags
}

/**
 * Parse signature 
 * @throws WrongFormatException if the line does not start with ----BEGIN
 */
lnn.consensusParser.parseSignature = function() {
    if (lnn.consensusParser.words[0] !== '-----BEGIN') throw `WrongFormatException`
    lnn.consensusParser.nextLine()
    let signature = ''
    while (lnn.consensusParser.lines[lnn.consensusParser.index] !== "-----END SIGNATURE-----") {
        signature += lnn.consensusParser.lines[lnn.consensusParser.index]
        lnn.consensusParser.nextLine()
    }
    return signature
}


/**
 * parase parameters
 */
lnn.consensusParser.tryParseParams = function() {
    let content = {}
    for (let param of lnn.consensusParser.words.splice(1, lnn.consensusParser.words.length)) {
        let tmp = param.split('=')
        content[tmp[0]] = Number(tmp[1])
    }
    return content
}

/**
* Check if the string in date has the format YYYY-MM-DD
* @param {string} time String representing the date
*/
lnn.consensusParser.isValidDate = function(date) {
    if (typeof date !== 'string') return false
    let regex = /^\d{4}[-](0[1-9]|1[012])[-](0[1-9]|[12][0-9]|3[01])$/
    return regex.test(date)
}

/**Check if the string time has the format HH:MM:SS
 * @param {string} time String representing the time
 */
lnn.consensusParser.isValidTime = function(time) {
    if (typeof time !== 'string') return false
    let regex = /^(0[0-9]|1[0-9]|2[0-3])[:][0-5][0-9][:][0-5][0-9]$/
    return regex.test(time)
}

/**
 * Check if the IP address is valid (either IPv4 or IPv6)
 * @param {string} IP the address we want to check
 */
lnn.consensusParser.isValidIP = function(IP) {
    let regex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/
    return regex.test(IP)
}

/**
 * Check if the IP is an IPv4 address
 * @param {string} IP 
 */
lnn.consensusParser.isIPv4 = function(IP) {
    let regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return regex.test(IP)
}

/**
 * Check if the given port is valid
 * @param {number} port
 */
lnn.consensusParser.isValidPort = function(port) {
    if (isNaN(port)) return false
    //TODO: < or <= ?
    return port >= 0 && port <= 65535
}

/**
 * Check if the given string is in hexadecimal
 * @param {string} str 
 */
lnn.consensusParser.isHex = function(str) {
    let regex = /^[a-fA-F0-9]+$/
    return regex.test(str)
}

/**
 * Check if the given string is in base 64
 * @param {string} str 
 */
lnn.consensusParser.isBase64 = function(str) {
    let regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
    return regex.test(str)
}

/**
 * Updates lnn.consensusParser.index and lnn.consensusParser.words
 * @throws EndOfFileException if the end of the file has already been reached
 */
lnn.consensusParser.nextLine = function() {
    if (lnn.consensusParser.index >= lnn.consensusParser.totalLines) throw `EndOfFileException: there are no lines to parse`
    lnn.consensusParser.words = lnn.consensusParser.lines[++lnn.consensusParser.index].split(" ")
}

/**
 * Checks if words has the expected size and that words[0] is equal to word
 * @param {number} expectedLength the expected length of words
 * @param {string} expectedWord the expected word[0]
 */
lnn.consensusParser.checkFormat = function(expectedLength, expectedWord) {
    if (lnn.consensusParser.words.length != expectedLength) throw `WrongFormatException: ${expectedLength} fields are expected`
    if (lnn.consensusParser.words[0] != expectedWord) throw `NotEqualException:b ${expectedWord} is not equal to ${lnn.consensusParser.words[0]}`
}

