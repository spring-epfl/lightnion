#!/bin/sh
#
# This script starts a local Tor relay that connects to the public network, but
# doesn't publish its descriptor.
#
# Use Chutney for a larger-scale test:
#  - https://gitweb.torproject.org/chutney.git/tree/README
#
# See also: https://github.com/teor2345/endosome/blob/master/relay-local.sh
#

orport='9050' # -: relay will listen for connections on this port
dirport='9051' # -: relay will advertise the directory service on this port
controlport='8000' # -: relay will advertise the specified control port
log_level='warn' # -: available levels: {debug, info, notice, warn, err}

function cleanup()
{
    pid="$(cat "$tmpdir/.pid" 2> /dev/null)"
    (ps -p "$pid" > /dev/null && kill "$pid") 2> /dev/null
    (ps -p "$pid" 2> /dev/null) | head -1
    rm -rf "$tmpdir"
}
trap cleanup EXIT

tmpdir="${TOR_TMPDIR:-$(mktemp -d "$PWD/local-relay-XXXXXXXX")}"
(ps -p "$(cat "$tmpdir/.pid")" | grep -v PID) 2> /dev/null && exit 1

rm -f "$tmpdir/.pid" "$tmpdir/.options"
(
    echo "PublishServerDescriptor 0"        # do not publish our descriptor
    echo "AssumeReachable 1"                # do not test if were reachable
    echo "ExitRelay 0"                      # do not allow outbound traffic
    echo "ProtocolWarnings 1"               # warn when off-spec behaviors
    echo "SafeLogging 0"                    # do not replace sensitive strings
    echo "LogTimeGranularity 1"             # timestamp resolution (ms)
    echo "PidFile $tmpdir/.pid"             # (write our pid here)
    echo "SOCKSPort 0"                      # do not start a SOCKS server
    echo "ContactInfo none@example.com"     # (contact information)
    echo "DataDirectory $tmpdir"            # do not use ~/.tor
    echo "ControlPort $controlport"         # advertised control port
    echo "ORPort $orport"                   # advertised relay port
    echo "DirPort $dirport"                 # advertised directory service port
) > "$tmpdir/.options"

tor $(cat "$tmpdir/.options") Log "$log_level stderr" "$@"
