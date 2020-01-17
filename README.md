Lightnion is a JavaScript library that you can include on your webpage to let any modern browser make anonymous requests. Lightnion uses an *untrusted* proxy to interact with the Tor network. This proxy converts between protocols (Websockets to pure TCP). This repository also contains a Python Lightnion Tor client that we have been using for testing.

**WARNING:** At the moment Lightnion is alpha-level research software. Do *not* use it in production, or for anything that really requires anonymity. You are, however, more than welcome to experiment with Lightnion. Please provide feedback opening issues or writing to the authors.

Quick setup
-----------

Clone the repository and add it to your `PYTHONPATH`:
```sh
git clone --recurse-submodules https://github.com/spring-epfl/lighttor lightnion
cd lightnion
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD"
```

You'll find some examples that showcase the Python Tor client under `./examples`. For example, you could run (after setting up `chutney`, see below):

```
python3 examples/link.py 127.0.0.1 5000
python3 examples/extend_circuit.py 127.0.0.1 5000
python3 examples/path.py 127.0.0.1 5000 7 0 8001
```

Interacting with the Tor network
--------------------------------

Lightnion interacts with the Tor network. For testing and demo purposes we recommend to use a test network generated by `chutney`. To set one up you could do the following:

```sh
git clone https://git.torproject.org/chutney.git
cp lightnion/tools/chutney/small-chut chutney # or read tools/chutney/README.md
cd chutney
git apply ../lightnion/tools/chutney/sandbox_patch # disable sandbox if you need
./small-chut
```

This will setup and run a small Tor test network. See the [notes](notes.sh) for how to run Lightnion with the real Tor network.

lightnion.js
------------

To build the JavaScript `lightnion.js` library, run:

```sh
cd js-client
make # you'll need a java, tested with java-10-openjdk
```

You can then use `lightnion.js` in your website (make sure you are also running a proxy, see below). You can then use `lightnion.js` as follows:

```JavaScript
// create a channel through the proxy

/*
Params: (host, port, success, error, io, fast, auth, select_path, tcp_ports,info)
- Proxy host
- Proxy port
- success callback
- error callback
- socket io (default: websocket)
- fast connection (default: false)
- auth-enabled? (default: false)
- select path at client? (o/w: at proxy) (default: true)
- tcp ports to be used on streams. (default: [80,443])
- info: optional callback for step-by-step information
*/
lnn.open('proxy.example.net', 4990, function(channel)

{
    // Callback interface (skip intermediate states)
    if (lln.state != lln.state.success)
        return

    // Handle response of request
    var handler = function(response) {...};

    // Send HTTP GET request to api.ipify.org

    tcp = lnn.stream.tcp(channel, 'api.ipify.org', 80, handler)
    tcp.send('GET / HTTP/1.1\r\n' +
             'Host: api.ipify.org\r\n\r\n')
})

```

Starting the proxy
------------------

To start the proxy first install its dependencies

```sh
pip install -r requirements-proxy.txt
```

and then run it:

```sh
python -m lightnion.proxy
```

this will however only start the proxy and you will have to host `lightnion.js` and the demo files another way. Alternative, the proxy can host them for you by running:

```
python -m lightnion.proxy -vvv --purge-cache --static ./js-client/demo/: ./js-client/evaluation/:
```

You can now explore some of the demos:

 * [Simple demo, retrieves consensus](http://localhost:4990/dir.html)
 * [Retrieves consensus, more info](http://localhost:4990/verbose.html)
 * [Compare regular and fast key exchange](http://localhost:4990/fast.html)
 * [Webpage retrieval (curl)](http://localhost:4990/curl.html)
 * [Get / post request](http://localhost:4990/get-post.html)
 * [Webpage via TLS](http://localhost:4990/tls.html)
 * [Path selection at client benchmarking](http://localhost:4990/path.html)

Requirements
------------

We do recommend using `chutney`, you'll find some instructions
within `./tools/chutney`.

**Tested with `Python 3.7.0` against
`Tor version 0.3.3.9 (git-45028085ea188baf)`.**

License
-------

This software is licensed under the
[BSD3 clause license](LICENSE).
© 2018-2019 Spring Lab (EPFL) and contributors.
