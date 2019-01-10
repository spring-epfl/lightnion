class ConsensusParser {

    /**
     * Constructor for the class ConsensusParser.
     * Defines the fields:
     * - lines: the consensus splitted by '\n'
     * - words: the first line of lines splitted by spaces
     * - consensus: the consensus we are building from rawText
     * @param {string} rawText the raw consensus
     */
    constructor(rawText) {
        if (typeof rawText !== 'string') throw `Error: the consensus must be given as a string`
        this.lines = rawText.split('\n')
        this.words = this.lines[0].split(' ')
        this.consensus = {}
        this.validFlags = ['Authority', 'BadExit', 'Exit', 'Fast', 'Guard', 'HSDir', 'NoEdConsensus', 'Stable', 'StaleDesc', 'Running', 'Valid', 'V2Dir']
        this.index = 0
        this.totalLines = this.lines.length
    }

    /**
     * Function that parse the consensus
     */
    parse() {
        this.consumeHeaders()
        this.consumeAuthority()
        this.consumeRouters()
        this.consumeFooter()

        return this.consensus

    }

    //----------------------------------HEADERS PARSER--------------------------------

    /**
     * Function that parses the headers
     */
    consumeHeaders() {
        this.consumeNetworkStatusVersion()
        this.consumeVoteStatus()
        this.consumeConsensusMethod()
        this.consumeDate('valid-after')
        this.consumeDate('fresh-until')
        this.consumeDate('valid-until')
        this.consumeVotingDelay()
        this.tryConsumeVersions('client-versions')
        this.tryConsumeVersions('server-versions')

        while (this.words[0] === 'package') {
            this.consumePackage()
        }

        this.consumeKnownFlags()
        this.tryConsumeProtocols('recommended-client-protocols')
        this.tryConsumeProtocols('recommended-relay-protocols')
        this.tryConsumeProtocols('required-client-protocols')
        this.tryConsumeProtocols('required-relay-protocols')
        this.tryConsumeParams()
        this.tryConsumeShareRand('shared-rand-previous-value')
        this.tryConsumeShareRand('shared-rand-current-value')

    }

    /**
     * Parse the field network-status-version
     */
    consumeNetworkStatusVersion() {
        let version = this.tryParseKeyValueInteger('network-status-version')
        this.consensus['headers'] = {
            'network-status-version': {
                'version': version
            }
        }

        this.nextLine()
    }

    /**
     * Parse the field vote-status
     * @throws WrongParameterException if status is not consensus
     */
    consumeVoteStatus() {
        let status = this.tryParseKeyValueString('vote-status')
        if (status !== 'consensus') throw `WrongParameterException: vote-status must be consensus`
        this.consensus['headers']['vote-status'] = status
        this.nextLine()
    }

    /**
     * Parse the field consensus-method
     */
    consumeConsensusMethod() {
        this.consensus['headers']['consensus-method'] = this.tryParseKeyValueInteger('consensus-method')
        this.nextLine()
    }

    /**
     * Parse the fields valid-after, fresh-until and valid-until
     * @param {strin} word 
     */
    consumeDate(word) {
        this.consensus['headers'][word] = this.tryParseDate(word)
        this.nextLine()
    }

    /**
     * Parse the field voting-delay
     * @throws NotEqualException if this.words[0] != word
     * @throws WrongParameterException if this.words[1] or this.words[2] is not a number
     * @throws WrongFormatException if this.words.length is not 3
     */
    consumeVotingDelay() {
        this.checkFormat(3, 'voting-delay')
        if (isNaN(this.words[1])) throw `WrongParameterException: ${words[1]} is not a number`
        if (isNaN(this.words[2])) throw `WrongParameterException: ${words[2]} is not a number`

        this.consensus['headers']['voting-delay'] = {
            'vote': Number(this.words[1]),
            'dist': Number(this.words[2])
        }

        this.nextLine()
    }

    /**
     * Try to parse the fields client-versions or server-versions if they are present
     * @param {string} word either client-versions or server-versions
     */
    tryConsumeVersions(word) {

        if (this.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
        if (this.words[0] === word) {
            this.consensus['headers'][word] = this.tryParseCommaSeparatedList(word)
            this.nextLine()
        }
    }

    /**
     * Parses the field package
     * @throws WrongFormatException if this.words.length is smaller than 5
     */
    consumePackage() {

        if (this.words.length < 5) throw `WrongFormatException: at least 5 fields are expected`
        if (this.consensus['headers']['package'] === undefined) this.consensus['headers']['package'] = []

        let pack = {
            'name': this.words[1],
            'version': this.words[2],
            'url': this.words[3]
        }
        let remaining = this.words.splice(4, this.words.length)
        let digests = {}

        for (let digest of remaining) {
            let tmp = digest.split('=')
            digests[tmp[0]] = tmp[1]
        }

        pack['digests'] = digests
        this.consensus['headers']['package'].push(pack)
        this.nextLine()
    }

    /**
     * Parses the field package
     * @throws NotValidFlagException if one of the flags is not in the valid flag list
     */
    consumeKnownFlags() {
        this.consensus['headers']['flags'] = this.tryParseFlags()
        this.nextLine()
    }

    /**
     * Try to parse the fields recommended-client-protocols, recommended-relay-protocols, required-client-protocols and required-client-protocols if they are present
     * @param {string} word either client-versions or server-versions
     */
    tryConsumeProtocols(word) {
        if (this.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
        if (this.words[0] === word) {
            this.consensus['headers'][word] = this.tryParseRanges(this.words.splice(1, this.words.length))
            this.nextLine()
        }

    }
    /**
     * Try to parse the field params if it is present
     */
    tryConsumeParams() {
        if (this.words[0] === 'params') {
            this.consensus['headers']['params'] = this.tryParseParams()
            this.nextLine()
        }
    }

    /**
     * Try to parse the fields shared-rand-previous-value and shared-rand-current-value if they are present
     * @param {string} word specify the field 
     */
    tryConsumeShareRand(word) {
        if (this.consensus['headers'][word] !== undefined) throw `AlreadyPresentException: ${word} can only appear once`
        if (this.words[0] === word) {
            let reveals = Number(this.words[1])
            let value = this.words[2]

            if (!this.isBase64(value)) throw `InvalidParameterException: value ${value} must be in hexadecimal`

            this.consensus['headers'][word] = {
                'NumReveals': reveals,
                'Value': value
            }

            this.nextLine()
        }
    }

    //-------------------AUTHORITY PARSER--------------------------------
    /**
     * Parses the authority part of the consensus
     * @throws InvalidIPException if address or IP are not valid IP addresses
     * @throws InvalidPortException if dirport or orport are not valid ports
     */
    consumeAuthority() {
        if (this.words[0] !== 'dir-source') throw `WrongFieldException: there must be at least one dir-source`
        this.consensus['dir-sources'] = []

        while (this.words[0] === 'dir-source') {
            this.consumeDirSource()
        }
    }

    /**
     * Parse a dir-source
     * @throws InvalidIPException if the IP-address is not valid
     * @throws InvalidPortException if dirport or orport are not valid
     * @throws InvalidParameterException if the vote-digest is not in hexadecimal
     */
    consumeDirSource() {
        let dirSource = {}
        this.checkFormat(7, 'dir-source')

        dirSource['nickname'] = this.words[1]

        if (!this.isHex(this.words[2])) throw `InvalidParameterException: vote-digest ${this.words[2]} must be in hexadecimal`
        dirSource['identity'] = this.words[2].toUpperCase()

        dirSource['hostname'] = this.words[3]

        if (!this.isValidIP(this.words[4])) throw `InvalidIPException: ${this.words[4]} is not a valid IP`

        dirSource['address'] = this.words[4]

        if (!this.isValidPort(Number(this.words[5])) || !this.isValidPort(Number(this.words[6]))) throw `InvalidPortException`

        dirSource['dirport'] = Number(this.words[5])
        dirSource['orport'] = Number(this.words[6])

        this.nextLine()
        dirSource['contact'] = this.words.splice(1, this.words.length).join(' ')
        this.nextLine()
        let digest = this.tryParseKeyValueString('vote-digest').toUpperCase()

        if (!this.isHex(digest)) throw `InvalidParameterException: vote-digest ${digest} must be in hexadecimal`

        dirSource['vote-digest'] = digest
        this.consensus['dir-sources'].push(dirSource)
        this.nextLine()


    }

    //-------------------ROUTER PARSER-----------------------------------
    /**
     * Consume each router status entry
     * @throws WrongFieldException if there is no router entry
     */
    consumeRouters() {
        if (this.words[0] !== 'r') throw `WrongFieldException: there must be at least one router`
        this.consensus['routers'] = []

        while (this.words[0] === 'r') {
            let router = {}
            this.consumeRfield(router)

            if (this.words[0] === 'a') router['a'] = []
            while (this.words[0] === 'a') {
                this.consumeAfield(router)
            }

            this.consumeSfield(router)
            this.tryConsumeVfield(router)
            this.tryConsumePrField(router)
            this.tryConsumeWfield(router)
            this.tryConsumePfield(router)

            this.consensus['routers'].push(router)
        }

    }

    /**
     * Parses the field 'r' of the router status entry
     * @param {} router 
     * @throws InvalidParameterException if the fields are not valid
     */
    consumeRfield(router) {
        this.checkFormat(9, 'r')
        router['nickname'] = this.words[1]

        if (!this.isBase64(this.words[2] + "=")) throw `InvalidParameterException: identity ${this.words[2]} must be in base64`
        router['identity'] = this.words[2]

        if (!this.isBase64(this.words[3] + "=")) throw `InvalidParameterException: digest ${this.words[3]} must be in base64`
        router['digest'] = this.words[3]

        if (!this.isValidDate(this.words[4])) throw `InvalidParameterException: date ${this.words[4]} must have the format YYYY-MM-DD`
        router['date'] = this.words[4]

        if (!this.isValidTime(this.words[5])) throw `InvalidParameterException: time ${this.words[5]} must have the format HH:MM:SS`
        router['time'] = this.words[5]

        if (!this.isValidIP(this.words[6])) throw `InvalidParameterException: IP ${this.words[6]} must be a valid IP address`
        router['address'] = this.words[6]

        if (!this.isValidPort(Number(this.words[7]))) throw `InvalidParameterException: ORPort ${this.words[7]} must be a valid port`
        router['orport'] = Number(this.words[7])

        if (!this.isValidPort(Number(this.words[8]))) throw `InvalidParameterException: DirPort ${this.words[8]} must be a valid port`
        router['dirport'] = Number(this.words[8])

        this.nextLine()
    }

    /**
     * Parses the field 'a' of the router status entry
     * @param {} router 
     * @throws InvalidParameterException if the fields are not valid
     */
    consumeAfield(router) {
        let i = this.words[1].indexOf("]")
        let address = this.words[1].slice(1, i)
        if (!this.isValidIP(address)) throw `InvalidParameterException: IP ${address} must be a valid IP address`

        let guessedType = 'IPv6'
        if (this.isIPv4(address)) {
            guessedType = 'IPv4'
        }

        let port = Number(this.words[1].slice(address.length + 3, this.words[1].length))

        if (!this.isValidPort(port)) throw `InvalidParameterException: port ${port} must be a valid port`

        router['a'].push({
            'ip': address,
            'port': port,
            'type': guessedType
        })

        this.nextLine()

    }

    /**
     * Parses the field 's' of the router status entry
     * @param {} router 
     */
    consumeSfield(router) {
        router['flags'] = this.tryParseFlags()
        this.nextLine()
    }

    /**
     * Tries to parse the field 'v' of the router status entry
     * @param {} router 
     */
    tryConsumeVfield(router) {
        if (this.words[0] === 'v') {
            this.checkFormat(3, 'v')
            router['version'] = this.words.splice(1, this.words.length).join(' ')
            this.nextLine()
        }
    }
    /**
     * Tries to parse the field 'v' of the router status entry
     * @param {} router 
     */
    tryConsumePrField(router) {
        if (this.words[0] === 'pr') {
            router['protocols'] = this.tryParseRanges(this.words.splice(1, this.words.length))
            this.nextLine()
        }
    }
    /**
     * Tries to parse the field 'w' of the router status entry
     * @param {} router 
     */
    tryConsumeWfield(router) {
        if (this.words[0] === 'w') {
            router['w'] = this.tryParseParams()
            this.nextLine()
        }
    }
    /**
     * Tries to parse the field 'p' of the router status entry
     * @param {} router 
     */
    tryConsumePfield(router) {
        if (this.words[0] === 'p') {
            this.checkFormat(3, 'p')
            if (this.words[1] !== 'accept' && this.words[1] !== 'reject') throw `WrongParameterException: ${this.words[1]} must be either accept or reject`


            let portList = this.parse_range_once(this.words[2])

            router['exit-policy'] = {
                'type': this.words[1],
                'PortList': portList
            }
            this.nextLine()
        }
    }


    //-------------------FOOTER PARSER ----------------------------------

    /**
     * Consume the footer
     * @throws WrongFieldException if there is no footer or no signature
     */
    consumeFooter() {
        if (this.words[0] !== 'directory-footer') throw `WrongFieldException: there must be a footer`
        this.nextLine()
        this.consensus['footer'] = {}
        this.tryConsumeBandwidthWeights()

        if (this.words[0] !== 'directory-signature') throw `WrongFieldException: there must be at least one signature`
        this.consensus['footer']['directory-signatures'] = []

        while (this.words[0] === 'directory-signature') {
            this.consensus['footer']['directory-signatures'].push(this.consumeSignature());
        }

    }

    /**
     * Tries to consume the bandwidth weights
     */
    tryConsumeBandwidthWeights() {
        if (this.words[0] === 'bandwidth-weights') {
            this.consensus['footer']['bandwidth-weights'] = this.tryParseParams()
            this.nextLine()
        }
    }

    /**
     * Consumes the signature
     * @throws WrongFieldException if the first field is not directory-signature
     * @throws InvalidParameterException if either the identity or the signing-key-digest are not in hexadecimal
     */
    consumeSignature() {
        if (this.words[0] !== 'directory-signature') throw `WrongFieldException: next field must be directory-signature`
        let length = this.words.length

        let algo
        let remaining
        if (length === 4) {
            algo = this.words[1]
            remaining = this.words.splice(2, length)
        } else if (length === 3) {
            algo = 'sha1'
            remaining = this.words.splice(1, length)
        }
        else throw `WrongParameterException: directory-signature has 3 or 4 arguments`

        let identity = remaining[0]
        if (!this.isHex(identity)) throw `InvalidParameterException: the identity ${identity} must be in hexadecimal`

        let digest = remaining[1]
        if (!this.isHex(digest)) throw `InvalidParameterException: the signing-key-digest ${digest} must be in hexadecimal`

        this.nextLine()

        let signature = this.parseSignature()
        if (this.index < this.totalLines - 1) this.nextLine()

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
    * @throws NotEqualException if this.words[0] != word
    * @throws WrongParameterException if this.words[1] is not a number
    * @throws WrongFormatException if this.words.length is not 2
    */
    tryParseKeyValueInteger(word) {
        this.checkFormat(2, word)
        if (isNaN(this.words[1])) throw `WrongParameterException: ${this.words[1]} is not a number`

        return Math.floor(this.words[1])
    }

    /**
     * Parses lines with the format "field value" where value is a string and field must be equal to word and return value. 
     * @param {string} word indicates to which field we are adding the newly parsed line
     * @throws NotEqualException if this.words[0] != word
     * @throws WrongFormatException if this.words.length is not 2
     */
    tryParseKeyValueString(word) {
        this.checkFormat(2, word)
        return this.words[1]
    }

    /**
     * Parses lines with the format "field YYYY-MM-DD HH:MM:SS" where field must be equal to word and return a date object
     * @param {string} word indicates to which field we are adding the newly parsed line
     * @throws NotEqualException if this.words[0] != word
     * @throws WrongFormatException if this.words.length is not 2
     * @throws NonValidDateException if the date is not valid
     * @throws NonValidTimeException if the time is not valid
     */
    tryParseDate(word) {
        this.checkFormat(3, word)
        if (!this.isValidDate(this.words[1])) throw `NonValidDateException: ${this.words[1]} is not a valid date`
        if (!this.isValidTime(this.words[2])) throw `NonValidTimeException: ${this.words[2]} is not a valid time`

        return {
            "date": this.words[1],
            "time": this.words[2]
        }
    }

    /**
     * Parses lines with the format "field list" where list is a comma separated list, returns the list as an array
     * @param {string} word indicates to which field we are adding the newly parsed line
     * @throws NotEqualException if this.words[0] != word
     * @throws WrongFormatException if this.words.length is not 2
     */
    tryParseCommaSeparatedList(word) {
        this.checkFormat(2, word)
        return this.words[1].split(",")
    }

    /**
    * Parse the ranges of the protocols
    * @param pairs Array of entries => Keyword=Values where values is the range
    */
    tryParseRanges(pairs) {
        let content = {}

        for (let pair of pairs) {
            if (pair.includes("=")) {
                let tmp = pair.split("=")
                content[tmp[0]] = this.parse_range_once(tmp[1])
            }
        }

        return content
    }

    /**
    * Helper function to parse the ranges of the protocols
    * @param value the range we want to parse
    */
    parse_range_once(value) {
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
    tryParseFlags() {
        let flags = this.words.splice(1, this.words.length)

        for (let f of flags) {
            if (!this.validFlags.includes(f)) throw `NotValidFlagException: ${f} is not a valid flag`
        }

        return flags
    }

    /**
     * Parse signature 
     * @throws WrongFormatException if the line does not start with ----BEGIN
     */
    parseSignature() {
        if (this.words[0] !== '-----BEGIN') throw `WrongFormatException`
        this.nextLine()
        let signature = ''
        while (this.lines[this.index] !== "-----END SIGNATURE-----") {
            signature += this.lines[this.index]
            this.nextLine()
        }
        return signature
    }


    /**
     * parase parameters
     */
    tryParseParams() {
        let content = {}
        for (let param of this.words.splice(1, this.words.length)) {
            let tmp = param.split('=')
            content[tmp[0]] = Number(tmp[1])
        }
        return content
    }

    /**
    * Check if the string in date has the format YYYY-MM-DD
    * @param {string} time String representing the date
    */
    isValidDate(date) {
        if (typeof date !== 'string') return false
        let regex = /^\d{4}[-](0[1-9]|1[012])[-](0[1-9]|[12][0-9]|3[01])$/
        return regex.test(date)
    }

    /**Check if the string time has the format HH:MM:SS
     * @param {string} time String representing the time
     */
    isValidTime(time) {
        if (typeof time !== 'string') return false
        let regex = /^(0[0-9]|1[0-9]|2[0-3])[:][0-5][0-9][:][0-5][0-9]$/
        return regex.test(time)
    }

    /**
     * Check if the IP address is valid (either IPv4 or IPv6)
     * @param {string} IP the address we want to check
     */
    isValidIP(IP) {
        let regex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/
        return regex.test(IP)
    }

    /**
     * Check if the IP is an IPv4 address
     * @param {string} IP 
     */
    isIPv4(IP) {
        let regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
        return regex.test(IP)
    }

    /**
     * Check if the given port is valid
     * @param {number} port
     */
    isValidPort(port) {
        if (isNaN(port)) return false
        //TODO: < or <= ?
        return port >= 0 && port <= 65535
    }

    /**
     * Check if the given string is in hexadecimal
     * @param {string} str 
     */
    isHex(str) {
        let regex = /^[a-fA-F0-9]+$/
        return regex.test(str)
    }

    /**
     * Check if the given string is in base 64
     * @param {string} str 
     */
    isBase64(str) {
        let regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
        return regex.test(str)
    }

    /**
     * Updates this.index and this.words
     * @throws EndOfFileException if the end of the file has already been reached
     */
    nextLine() {
        if (this.index >= this.totalLines) throw `EndOfFileException: there are no lines to parse`
        this.words = this.lines[++this.index].split(" ")
    }

    /**
     * Checks if words has the expected size and that words[0] is equal to word
     * @param {number} expectedLength the expected length of words
     * @param {string} expectedWord the expected word[0]
     */
    checkFormat(expectedLength, expectedWord) {
        if (this.words.length != expectedLength) throw `WrongFormatException: ${expectedLength} fields are expected`
        if (this.words[0] != expectedWord) throw `NotEqualException:b ${expectedWord} is not equal to ${this.words[0]}`
    }
}