/**
 * HTTP packet parsing utilities.
 */

// Parsing function helpers
import * as http from "./http.js";

/**
 * Parse the request line of a HTTP request.
 * No validation is made on the request-uri and version.
 * 
 * @param {string} line the request line
 * @throws error when `line` could not be parsed
 * @return {Array{ [method, request-uri, version] the parsed header line fields
 * @private
 */
export function parseRequestLine(line) {
    // Request-Line = Method SP Request-URI SP HTTP-Version CRLF
    if (!line) {
        throw `could not parse request line from ${line}`;
    }

    const elements = line.trim().split(" ");

    if (elements.length < 3) {
        throw `could not parse request line from ${line}: should be of the form 'Method Request-URI HTTP-Version CRLF'`;
    }

    const method = elements[0];
    if (!Object.values(http.methods).includes(method)) {
        throw `could not parse request line from ${line}: method is not recognized'`;
    }

    const requestURI = elements[1];
    const version = elements[2];

    return [method, requestURI, version];
}

/**
 * Parse the status line of a HTTP response.
 * No validation is made on the fields.
 * 
 * @param {string} line the status-line
 * @return {Array} [version, statusCode {int}, reason] the parsed status line fields
 * @private
 */
export function parseStatusLine(line) {
    // Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
    if (!line) {
        throw `could not parse status line from ${line}`;
    }
    const elements = line.trim().split(" ");

    if (elements.length < 3) {
        throw `could not parse status line from ${line}: should be of the form 'HTTP-Version Status-Code Reason CRLF'`;
    }

    const version = elements[0];
    const statusCode = parseInt(elements[1]);
    const reason = elements.slice(2).join(" ");

    if (isNaN(statusCode)) {
        throw `could not parse status line from ${line}: status-code is not an integer`;
    }

    return [version, statusCode, reason];
}

/**
 * Parse the headers of a HTTP packet.
 * No validation is performed on fields and keys.
 * 
 * @param {string} headers HTTP headers
 * @returns a dictionnary of key-values in the header, 
 *  if multiple header key is present, values will be comma separated
 *  the header field names and values are set to lower-case, except for case-sensitive values
 * @private
 */
export function parseHeaders(headers) {
    let parsed = {};

    if (!headers) { return parsed; }

    headers.split('\r\n')
        .forEach(line => {
            // split header line in key - value
            let i = line.indexOf(':');
            let key = line.substr(0, i).trim().toLowerCase();
            let val;
            // Header fields names should be case-insensitive (RFC2616 4.2)
            // So we only use lower case versions, except for 'sec-websocket' headers.
            // For some reason WebSocket servers do not understand lower case 'sec-websocket' headers.
            if (key != "sec-websocket-accept" && key != "sec-websocket-key") {
                val = line.substr(i + 1).trim().toLowerCase();
            } else {
                val = line.substr(i + 1).trim();
            }

            if (key) {
                parsed[key] = parsed[key] ? parsed[key] + ', ' + val : val;
            }
        });

    return parsed;
}


