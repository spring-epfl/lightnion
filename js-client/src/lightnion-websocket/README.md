# Lightnion WebSocket

In this folder can be found an abstract implementation of a WebSocket client in JavaScript (`websocket-client`), 

The `WebSocketClient` abstract class could be used on top of other TCP sockets, for this, the implementing class should follow similar code as to the LightnionWebSocket (`lightnion-websocket-client/lightnion-websocket.js`).

The `LightnionWebSocket` is a concrete implementation that uses a TCP socket that is routed through Tor thanks to Lightnion.

This library aims to provide a WebSocket close to the usual [WebSocket client](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) available in browsers.

## Usage

The `LightnionWebSocket` is added to the `lnn` namespace, you can use it thanks to the bundle built for the Lightnion `js-client`.

```html
    <script src="lightnion.bundle.js"></script>
    <script>
        let url = new URL("ws://echo.websocket.org");
        let ws = new lnn.websocket(url, protocols = [], lightnionHost = "localhost", lightnionPort = 4990);
    </script>
```

## Example

For an example of use, consult `js-client/demo/websocket.html`, which shows how to use the lightnion websocket.

## Development

### Package structure

The library is split in different folders under `src/lightnion-websocket/`:

- `websocket-client`

    Exports the (abstract) `WebSocketClient` class, which represents a general websocket client that may be used in both browser and node environment. It relies on an underlying socket, given to it when calling `_start_opening_handshake`.

- `websocket-client-lightnion`

    Concrete implementation of a `WebSocketClient`, using lightnion redirection and lightnion constructed tcp socket.


### Missing features, important notes

#### `WebSocketClient`

- no correct bufferedAmount support (always replies 0), this would depend on the underlying socket.
- no WebSocket subprotocols support
- no WebSocket extensions support
- [WebSocket cookies](https://www.w3.org/TR/websockets/#feedback-from-the-protocol) ?
- [RFC6455 4.1](https://tools.ietf.org/html/rfc6455#page-15) requires that there should be no more than one connection in a connecting state to the same IP address. This is currently not enforced.

### Integration Tests

See [here](../../integration-tests/lightnion-websocket/README.md)

### WebSocketClient socket interface

The `WebSocketClient` class implemented requires an underlying TCP socket, currently with a specific interface:

- a `send(data)` method to send raw data
- a `close()` method to close the socket
- a `closed` boolean property indicating if the socket is closed 
- a `onmessage(data)` callback firing when offering available raw data to the upper layer

### Node support

Node support is not ready yet. However it should be possible to extend the `WebSocketClient` class to implement it over Node's TCP socket.


### Moving to Secure WebSockets

Secure WebSockets (WSS) are WebSocket that work over a TLS connection, similarly to HTTPS.

To enable this, look at the `lightnion-websocket-client/lightnion-helpers.js` file and rewrite commented `ltlsOpen` function.
Use this function in `LightnionWebSocket`'s constructor in place of `ltcpOpen` in `lightnion-websocket-client/lightnion-webscoket.js`.
One also need to implement it in `__do_opening_handhake` method in `websocket-client/websocket-client.js`.

Due to errors like `cannot connect to a non-secure websocket from a secure origin`, we could not implement it.
To avoid the error, use a remote Lightnion Proxy or implement secure websockets in the Lightnion Proxy.


