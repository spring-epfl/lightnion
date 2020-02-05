/**
 * @module lnn
 */

import { isNode } from 'browser-or-node';

if (!isNode) {
    // saving WebSocket default
    // when using lightnion with redirected WebSockets,
    // the client must still create a WebSocket to the lightnion proxy
    // hence we save the standard WebSocket as _WebSocket
    window._WebSocket = WebSocket;
}

import * as header from "./header.js";
import * as endpoint from "./endpoint.js";
import * as api from "./api.js";
import * as consensusParser from "./consensusParser.js";
import * as get from "./get.js";
import * as io from "./io.js";
import * as ntor from "./ntor.js";
import * as onion from "./onion.js";
import * as parser from "./parser.js";
import * as path from "./path.js";
import * as post from "./post.js";
import * as relay from "./relay.js";
import * as signature from "./signature";
import * as stream from "./stream.js";
import * as utils from "./util.js";
import LightnionWebSocket from "./lightnion-websocket/lightnion-websocket.js";

// header
let lnn = header.lnn;

// api
lnn.fast = api.fast
lnn.auth = api.auth
lnn.open = api.open
lnn.agents = api.agents
lnn.send_req = api.send_req
lnn.http_request = api.http_request

// consensus parser
lnn.consensusParser = consensusParser.consensusParser;

// endpoint
lnn.endpoint = endpoint.endpoint;

// get
lnn.get = {};
lnn.get.guard = get.guard;
lnn.get.consensus = get.consensus;
lnn.get.descriptors = get.descriptors;
lnn.get.consensus_raw = get.consensus_raw;
lnn.get.descriptors_raw = get.descriptors_raw;
lnn.get.signing_keys = get.signing_keys;

// io
lnn.io = {};
lnn.io.polling = io.polling;
lnn.io.socket = io.socket;

// ntor
lnn.ntor = ntor.ntor;

// onion
lnn.onion = {};
lnn.onion.ctr = onion.ctr;
lnn.onion.sha = onion.sha;
lnn.onion.forward = onion.forward;
lnn.onion.backward = onion.backward;
lnn.onion.build = onion.build;
lnn.onion.peel = onion.peel;

// parser
lnn.parser = parser.parser;

// path
lnn.path = path.path;

// post
lnn.post = {};
lnn.post.create = post.create;
lnn.post.circuit_info = post.circuit_info;
lnn.post.handshake = post.handshake;
lnn.post.channel = post.channel;
lnn.post.extend = post.extend;
lnn.post.close = post.close;

// relay
lnn.relay = relay.relay;

// signature
lnn.signature = {};
lnn.signature.verify = signature.verify;
lnn.signature.get_hash = signature.get_hash;
lnn.signature.verify_key = signature.verify_key;
lnn.signature.get_sig_and_keys_digests = signature.get_sig_and_keys_digests;
lnn.signature.get_signature_big_int = signature.get_signature_big_int;
lnn.signature.get_hash_from_rsa_cipher = signature.get_hash_from_rsa_cipher;

// stream
lnn.stream = stream.stream;

// utils
lnn.enc = {};
lnn.enc.bits = utils.enc.bits;
lnn.enc.utf8 = utils.enc.utf8;
lnn.enc.base64 = utils.enc.base64;
lnn.enc.bin = utils.enc.bin;

lnn.dec = {};
lnn.dec.bits = utils.dec.bits;
lnn.dec.utf8 = utils.dec.utf8;
lnn.dec.base64 = utils.dec.base64;
lnn.dec.bin = utils.dec.bin;

// websocket
lnn.websocket = LightnionWebSocket;

window.lnn = lnn;

export { lnn };