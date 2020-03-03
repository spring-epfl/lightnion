/*
 * Mocks for use in node/broswer.
 */

import * as utils from "../utils/utils.js";
import { isNode } from 'browser-or-node';

export let EventTargetClass;
export let MessageEventClass;
export let BlobClass;
export let CloseEventClass;

if (isNode) {
    // running in node
    EventTargetClass = utils.EventTarget;
    MessageEventClass = utils.MessageEvent;
    BlobClass = require("cross-blob");
    CloseEventClass = utils.CloseEvent;
} else {
    EventTargetClass = EventTarget;
    MessageEventClass = MessageEvent;
    BlobClass = Blob;
    CloseEventClass = CloseEvent;
}
