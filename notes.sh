# Below a walk-through with step-by-step operations and comments
echo "This file is not meant to be executed, go read it."
exit 1

#
# I have tor version 0.3.3.9 installed, but any modern version should work.
#

# quick setup
git clone --recurse-submodules https://github.com/spring-epfl/lighttor lightnion
cd lightnion
source venv/bin/activate
pip install -r requirements.txt -r requirements-proxy.txt # install deps


# running a Tor node that connects to the REAL network
cd lightnion
cd tools
./start-local-relay.sh # Control on 8000, OR on 9050, directory on 9051
# ^C^C to exit


# running a little chutney
git clone https://git.torproject.org/chutney.git
cp lightnion/tools/chutney/small-chut chutney # or read tools/chutney/README.md
cd chutney
git apply ../lightnion/tools/chutney/sandbox_patch # disable sandbox if you need
./small-chut


# library examples, run with real Tor
cd lightnion
source venv/bin/activate
export PYTHONPATH="$(pwd)"
python examples/link.py # 14 loc – open a link
python examples/create_fast.py # 23 loc – create a fast circuit
python examples/consensus.py # 34 loc – download both flavors of consensus
# -: now .lightnion-cache.d/consensus-{unflavored,microdesc} exists
python examples/descriptors.py # 72 loc – download all descriptors +checks
python examples/directory_query.py # 48 loc – get both consensus (low level)
# -: performs directory queries on a lower level and writes result in /tmp
python examples/extend_circuit.py # 89 loc – create extended circuit
# -: random depth, will download exit nodes descriptor and consensus through it


# library examples, run with chutney
cd lightnion
source venv/bin/activate
export PYTHONPATH="$(pwd)"
python examples/link.py 127.0.0.1 5000
# -: other scripts also work with the same parameters
python examples/path.py 127.0.0.1 5000 7 0 8001 # 67 loc – create 7 paths
# ^C because I'm bad with waitpids :d


# run the proxy, run with real Tor
cd lightnion
python -m lightnion.proxy --help # help!
python -m lightnion.proxy -vvv -s 127.0.0.1:9050 -c 8000
# -vvv is very very verbose mode
# -s is the slave node, here the local real one
# -c is the control port for path unholy selection
#
# the first time it starts, the proxy will:
#  - download the consensus
#  - download all the descriptors
# on the real network, that takes two minutes
#
# you'll see "* Serving Flask app" after successful bootup
# ^C to exit


# library examples, run with real Tor
cd lightnion
source venv/bin/activate
export PYTHONPATH="$(pwd)"
python example/polling.py # 40l – full path through proxy, using polling
python example/websocket.py # 53l – full path through proxy, using websockets
python example/websocket.py --help
# method            polling or websocket (default: websocket)
# nb_downloads      number of consensuses to download while testing circuit
# host              proxy host
# port              proxy port
# padding           number of dropped cells to send through the circuit before
#
# Extra options provided for convenience when benchmarking websockets benefits
#


# build the javascript client
cd lightnion
cd js-client
make # you'll need a java, tested with java-10-openjdk
#
# you have:
# - lightnion.js         # /src/* concatenated with config.mk SOURCES order
# - lightnion.min.js     # minified version (using google closure compiler)
# - sjcl.js             # sjcl patched build (see jscl.patch)
# - lightnion.bundle.js  # all-inclusive file, dependencies+minified


# run the proxy, run with chutney and serve static files
cd lightnion
python -m lightnion.proxy -vvv --purge-cache \
    --static ./js-client/demo/: ./js-client/evaluation/:
# --purge-cache purges the cache (same as rm -rf .lightnion-cache.d
# --static path:root serves files in path to url prefix root
#
# for example, we have:
# --static ./js-client/demo/:
#   :- now ./js-client/demo/lightnion.bundle.js is at /lightnion.bundle.js
# --static ./js-client/evaluation/:
#   :- now ./js-client/evaluation/per-message.html is at /per-message.html
# --static ./js-client/demo/.dev/:.dev
#   :- now ./js-client/demo/.dev/io.js is at /.dev/io.sh
#
# you have several .html files with different demos, and a ".dev.html" one:
#  - when using minified versions, you can't debug shit
#  - adding "./js-client/demo/.dev/:.dev" serves source as static files
#  - headers in ".dev.html" can be used to includes everything in order
#  - now, you can debug shit in your demos
# F12
#


# js demos, you must have the proxy running
export BROWSER="$(find /usr/bin|grep -E 'firefox|chromium'|shuf|head -n 1)"
$BROWSER http://localhost:4990/dir.html # 23l – simplest one, get raw consensus
$BROWSER http://localhost:4990/verbose.html # 66l – same, but giving details
$BROWSER http://localhost:4990/raw.html # 52l – low-level access to channel
$BROWSER http://localhost:4990/fast.html # 34l – clock time of open/fast
# fast, you say ?
#
# the fast channel creation sends a shorter ntor handshake where the identity
# and onionkey of the guard node are omitted: the proxy fill-in the blanks and
# send back the guard node descriptor
#
# with open, the client first GET /guard then opens the channel, hence slower
# with fast, the client creates a channel in one query
#
$BROWSER http://localhost:4990/auth.html # 39l – authenticate proxy
# You'll need:
#  - to restart the proxy with --auth-enabled
#  - copy the content of lightnion/.lightnion-auth.d/suffix
#  - paste it
#
# the auth channel creation implies fast channel creation.
# the auth channel creation sends along the request an extra public key, the
# proxy ntor handshakes with the extra public key, it uses the derived shared
# secret to encrypt the answer. The client verify the auth and decrpt.
#
# to be used when you distrust the link with the proxy (cc couldflare)
# suffix is url-safe and can be an input
#
$BROWSER http://localhost:4990/nc.html # 82l – execute nc -l -p 4040 before
$BROWSER http://localhost:4990/loop.html # 122l – python tools/loop.py # server


# evaluation
cd lightnion
source venv/bin/activate
python tools/loop.py # in a separate window, keep it running
pip install numpy
python tools/interact.py # print baseline per-message latency
$BROWSER http://localhost:4990/per_message.html # prints per-message latency
$BROWSER http://localhost:4990/per_circuit.html # prints per-circuit latency


# re-run the proxy before doing last demo^W magic tricks
./start-local-relay.sh # in a separate window, keep it running
python -m lightnion.proxy -vvv -s 127.0.0.1:9050 -c 8000 \
    --static ./js-client/demo/:/


$BROWSER http://localhost:4990/curl.html # 157l – press return several times
# browser curl:
# - only HTTP
# - refresh the page to get new circuit
# - press enter, you'll see a penguin!
# - press enter, you'll see your (exit node) IP address!
# - press enter, you'll see your (exit node) local weather report!
# - refresh the page (you may have a new exit)


$BROWSER http://localhost:4990/tls.html # 121l – unholy TLS, return two times
# browser HTTPs:
# - uses forge
# - connects to given host & port via TLS
# - send given payload
# - retrieve answer
# - surprise!


#
# troubleshooting
#

# purge cache when switching networks
rm -rf .lightnion-cache.d # purge cache when switching between networks

# RuntimeError: Missing entry: ['flavor', 'http']
pkill -f tor # ether wait or re-run your nodes

# every channel creation fails inexplicably
pkill -f lightnion.proxy # either wait self-diagnosis or reboot the proxy

