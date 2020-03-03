// Utilities

/**
 * A MessageEvent implementation for Node.
 * 
 * @private
 */
export class MessageEvent {
    constructor(type, init = undefined) {
        this.type = type;
        if (init) {
            this.data = init.data;
            this.origin = init.origin;
            this.lastEventId = init.lastEventId;
            this.channel = init.channel;
            this.source = init.source;
            this.port = init.port;
        }
    }
}

/**
 * A CloseEvent implementation for Node.
 * 
 * @private
 */
export class CloseEvent extends MessageEvent {
    constructor(type, init = undefined) {
        super(type, init);
        if (init) {
            this.wasClean = init.wasClean;
            this.code = init.code;
            this.reason = init.reason;
        }
    }
}

/**
 * Simple implementation of EventTarget.
 * See {@link https://developer.mozilla.org/en-US/docs/Web/API/EventTarget}.
 * 
 * Used for mocking browsers' DOM EventTarget.
 * 
 * @private
 */
export class EventTarget {
    constructor() {
        this.listeners = {};
    }

    addEventListener(type, callback) {
        if (!(type in this.listeners)) {
            this.listeners[type] = [];
        }
        this.listeners[type].push(callback);
    }

    removeEventListener(type, callback) {
        if (!(type in this.listeners)) {
            return;
        }
        const stack = this.listeners[type];
        for (let i = 0, l = stack.length; i < l; i++) {
            if (stack[i] === callback) {
                stack.splice(i, 1);
                return;
            }
        }
    }

    dispatchEvent(event) {
        if (!(event.type in this.listeners)) {
            return true;
        }
        const stack = this.listeners[event.type].slice();

        for (let i = 0, l = stack.length; i < l; i++) {
            stack[i].call(this, event);
        }
        return !event.defaultPrevented;

    }

}

/**
 * Check for inclusion of an array in an array.
 * 
 * @param haystack {Array} the array of arrays 
 * @param needle {Array} the array that may be included in the haystack
 * @private
 */
export function containsArray(haystack, needle) {
    return haystack.filter(arr => {
        if (arr.length !== needle.length) {
            return false;
        }

        for (let i = 0; i < needle.length; i++) {
            if (arr[i] !== needle[i]) {
                return false;
            }
        }
        return true;
    }).length > 0;
}