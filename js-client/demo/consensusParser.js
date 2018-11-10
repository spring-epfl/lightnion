class ConsensusParser{

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
        this.validFlags = ['Authority', 'BadExit', 'Exit', 'Fast', 'Guard', 'HSDir', 'Named', 'Stable', 'Running', 'Unnamed', 'Valid', 'V2Dir', 'NoEdConsensus']
    }

    /**
     * Function that parse the consensus
     */
    parse() {
        this.consumeHeaders()

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
            'vote': this.words[1],
            'dist': this.words[2]
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
        let flags = this.words.splice(1, this.words.length)

        for (let f of flags) {
            if (!this.validFlags.includes(f)) throw `NotValidFlagException: ${f} is not a valid flag`
        }

        this.consensus['headers']['flags'] = flags
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

            let content = {}
            for (let param of this.words.splice(1, this.words.length)) {
                let tmp = param.split('=')
                content[tmp[0]] = Number(tmp[1])
            }

            this.consensus['headers']['params'] = content
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

            this.consensus['headers'][word] = {
                'NumReveals': reveals,
                'Value': value
            }

            this.nextLine()
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
        if (isNaN(this.words[1])) throw `WrongParameterException: ${words[1]} is not a number`

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
     * Updates this.lines and this.words and returns true if it reached the end of the file
     * @throws EndOfFileException if the end of the file has already been reached
     */
    nextLine() {

        if (this.lines.length === 0) throw `EndOfFileException: there are no lines to parse`

        this.lines = this.lines.splice(1, this.lines.length)
        this.words = this.lines[0].split(" ")

        return this.lines.length === 0
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