"""
Refactored consensus parser
"""

import enum
import re
import urllib.request

from base64 import b64decode
from datetime import datetime, timezone

import lightnion as lnn
import lightnion.keys


RE_NETWORK_STATUS_VERSION = re.compile(r"network-status-version (\d+)")
RE_VOTE_STATUS = re.compile(r"vote-status (.+)")
RE_CONSENSUS_METHOD = re.compile(r"consensus-method (\d+)")
RE_VALID_AFTER = re.compile(r"valid-after (\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})")
RE_FRESH_UNTIL = re.compile(r"fresh-until (\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})")
RE_VALID_UNTIL = re.compile(r"valid-until (\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})")
RE_VOTING_DELAY = re.compile(r"voting-delay (\d+) (\d+)")
RE_CLIENT_VERSIONS = re.compile(r"client-versions (\S*)")
RE_SERVER_VERSIONS = re.compile(r"server-versions (\S*)")
RE_KNOWN_FLAGS = re.compile(r"known-flags (.+)")
RE_RECOMMENDED_CLIENT_PROTOCOLS = re.compile(r"recommended-client-protocols (.+)\n")
RE_RECOMMENDED_RELAY_PROTOCOLS = re.compile(r"recommended-relay-protocols (.+)\n")
RE_REQUIRED_CLIENT_PROTOCOLS = re.compile(r"required-client-protocols (.+)\n")
RE_REQUIRED_RELAY_PROTOCOLS = re.compile(r"required-relay-protocols (.+)\n")
RE_PARAMS = re.compile(r"params ((?:([^ =]+)=(\S+)) )+([^ =]+)=(\S+)")
RE_SHARED_RAND_PREVIOUS_VALUE = re.compile(r"shared-rand-previous-value (\d+) (\S+)")
RE_SHARED_RAND_CURRENT_VALUE = re.compile(r"shared-rand-current-value (\d+) (\S+)")
RE_DIR_SOURCE = re.compile(r"""dir-source (\S+) ([A-Za-z0-9]+) (\S+) (\S+) (\d+) (\d+)
contact (\S+)
vote-digest ([A-Za-z0-9]+)""")
RE_RELAYS = re.compile(r"(^r .+\n(?:(?:[aspvwm].+)\n)+)", re.M)

RE_RELAY_R_U = re.compile(r"r (\S+) (\S+) (\S+) (\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) (\S+) (\d+) (\d+)")
RE_RELAY_R_M = re.compile(r"r (\S+) (\S+) (\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) (\S+) (\d+) (\d+)")
RE_RELAY_M = re.compile(r"\nm ([^\n]+)")
RE_RELAY_A = re.compile(r"\na (\S+):(\d+)")
RE_RELAY_S = re.compile(r"\ns ([^\n]+)")
RE_RELAY_V = re.compile(r"\nv (Tor \S+)")
RE_RELAY_PR = re.compile(r"\npr ([^\n]+)")
RE_RELAY_W = re.compile(r"\nw (Bandwidth)=(\d+)(?:\s([^= ]+)=(\S+))*")
RE_RELAY_P = re.compile(r"\np (accept|reject) (\S+)")
#RE_ = re.compile(r"")
RE_FOOTER = re.compile(r"directory-footer\nbandwidth-weights ([^\n]+)\n([A-Za-z0-9\n /=+-]+)")
RE_DIR_SIGN = re.compile(r"""directory-signature (.+)
-----BEGIN SIGNATURE-----
([0-9A-Za-z+/=\n]+)
-----END SIGNATURE-----
""")

RE_RELAY_DIGEST_UNF = re.compile(r"^r \S+ \S+ (\S+)", re.MULTILINE)
RE_RELAY_DIGEST_MIC = re.compile(r'^m ([^\n]+)', re.MULTILINE)


class InvalidConsensus(Exception):
    pass


class Flavor(enum.IntEnum):
    UNFLAVORED = 0
    MICRO = 1


class Consensus:
    """Container for consensus handling methods."""

    @staticmethod
    def _search_re(string, regex):
        # Convenience function to search for the first instance of the pattern.
        match = regex.search(string)
        if not match:
            raise InvalidConsensus("Invalid format.")

        groups = match.groups()
        return groups


    @staticmethod
    def _findall_re(string, regex):
        # Convenience function to search for all instances of the pattern.
        groups = regex.findall(string)
        if not groups:
            raise InvalidConsensus("Invalid format.")

        return groups


    @staticmethod
    def _parse_date(string, regex):

        groups = Consensus._search_re(string, regex)

        groups_int = [int(x) for x in groups]
        timestamp = datetime(*groups_int, tzinfo=timezone.utc).timestamp()

        date_parsed = {
            "date": "{}-{}-{}".format(*groups[:3]),
            "time": "{}:{}:{}".format(*groups[3:]),
            "stamp": timestamp
        }

        return date_parsed


    @staticmethod
    def _parse_footer(string):
        groups = Consensus._search_re(string, RE_FOOTER)

        bw_weights = dict()
        bw_weights_raw = groups[0].split(" ")
        for bw_weight_raw in bw_weights_raw:
            key, value = bw_weight_raw.split("=")
            bw_weights[key] = int(value)

        dir_signs = list()
        groups_sign = Consensus._findall_re(groups[1], RE_DIR_SIGN)
        for dir_sign_raw in groups_sign:
            params = dir_sign_raw[0].split(" ")
            if len(params) == 3:
                algo, identity, digest = params
            elif len(params) == 2:
                algo = "sha1"
                identity, digest = params

            signature = dir_sign_raw[1]

            dir_sign = {
                    "Algorithm": algo,
                    "identity": identity,
                    "signing-key-digest": digest,
                    "signature": signature.replace("\n", "")
            }

            dir_signs.append(dir_sign)

        footer = {
            "bandwidth-weights": bw_weights,
            "directory-signatures": dir_signs
        }

        return footer


    @staticmethod
    def _parse_protocols(string, regex):
        params = Consensus._search_re(string, regex)[0].split(" ")

        protocols = dict()

        for param in params:
            key, value = param.split("=")
            protocols[key] = Consensus._parse_protocols_vers(value)

        return protocols


    @staticmethod
    def _parse_protocols_vers(proto):
        versions = list()

        version_ranges = proto.split(",")
        for version_range_raw in version_ranges:
            if "-" in version_range_raw:
                vmin, vmax = version_range_raw.split("-")
                version_range = list(range(int(vmin), int(vmax) + 1))
                versions += version_range
            else:
                versions.append(int(version_range_raw))

        return versions


    @staticmethod
    def _parse_relay_port_list(port_list_str):
        ports_ranges = list()

        ports_ranges_raw = port_list_str.split(",")
        for ports_range_raw in ports_ranges_raw:
            if "-" in ports_range_raw:
                pmin, pmax = ports_range_raw.split("-")
                ports_ranges.append([int(pmin), int(pmax)])
            else:
                port = ports_range_raw
                ports_ranges.append([int(port), int(port)])

        return ports_ranges


    @staticmethod
    def _parse_relay_micro(string):
        group_r = Consensus._search_re(string, RE_RELAY_R_M)
        group_m = Consensus._search_re(string, RE_RELAY_M)
        date_int = [int(x) for x in group_r[2:8]]
        date_str = "{}-{}-{}".format(*group_r[2:5])
        time_str = "{}:{}:{}".format(*group_r[5:8])
        timestamp = datetime(*date_int, tzinfo=timezone.utc).timestamp()

        #group_a = Consensus._search_re(string, RE_RELAY_A)

        flags = Consensus._search_re(string, RE_RELAY_S)[0].split(" ")

        version = Consensus._search_re(string, RE_RELAY_V)[0]

        group_pr = Consensus._search_re(string, RE_RELAY_PR)[0]
        protocols = dict()
        for pair in group_pr.split(" "):
            key, value = pair.split("=")
            protocols[key] = Consensus._parse_protocols_vers(value)

        group_w = Consensus._search_re(string, RE_RELAY_W)
        elems = iter(group_w)
        w_dict = {k: int(v) for k, v in zip(elems, elems)}

        relay = {
            "nickname": group_r[0],
            "identity": group_r[1],
            "micro-digest": group_m[0],
            "date": date_str,
            "time": time_str,
            "stamp": timestamp,
            "address": group_r[8],
            "dirport": int(group_r[10]),
            "orport": int(group_r[9]),
            "flags": flags,
            "version": version,
            "protocols": protocols,
            "w": w_dict
        }

        return relay


    @staticmethod
    def _parse_relay_unflavored(string):

        group_r = Consensus._search_re(string, RE_RELAY_R_U)
        date_int = [int(x) for x in group_r[3:9]]
        date_str = "{}-{}-{}".format(*group_r[3:6])
        time_str = "{}:{}:{}".format(*group_r[6:9])
        timestamp = datetime(*date_int, tzinfo=timezone.utc).timestamp()

        #group_a = Consensus._search_re(string, RE_RELAY_A)

        flags = Consensus._search_re(string, RE_RELAY_S)[0].split(" ")

        version = Consensus._search_re(string, RE_RELAY_V)[0]

        group_pr = Consensus._search_re(string, RE_RELAY_PR)[0]
        protocols = dict()
        for pair in group_pr.split(" "):
            key, value = pair.split("=")
            protocols[key] = Consensus._parse_protocols_vers(value)

        group_w = Consensus._search_re(string, RE_RELAY_W)
        elems = iter(group_w)
        w_dict = {k: int(v) for k, v in zip(elems, elems)}

        group_p = Consensus._search_re(string, RE_RELAY_P)

        relay = {
            "nickname": group_r[0],
            "identity": group_r[1],
            "digest": group_r[2],
            "date": date_str,
            "time": time_str,
            "stamp": timestamp,
            "address": group_r[9],
            "dirport": int(group_r[11]),
            "orport": int(group_r[10]),
            "flags": flags,
            "version": version,
            "protocols": protocols,
            "w": w_dict,
            "exit-policy": {
                "type": group_p[0],
                "PortList": Consensus._parse_relay_port_list(group_p[1])
            }
        }

        return relay


    @staticmethod
    def _parse_relays(string, flavor):

        relays = list()

        if flavor == Flavor.MICRO:
            func = Consensus._parse_relay_micro
        elif flavor == Flavor.UNFLAVORED:
            func = Consensus._parse_relay_unflavored

        for relay_str in Consensus._findall_re(string, RE_RELAYS):
            relay = func(relay_str)
            relays.append(relay)

        return relays


    @staticmethod
    def _parse_shared_rand(string, regex):
        groups = Consensus._search_re(string, regex)
        shared_rand = {"NumReveals": int(groups[0]), "Value": groups[1]}
        return shared_rand


    @staticmethod
    def _parse_versions(string, regex):
        versions = Consensus._search_re(string, regex)[0].split(",")
        return versions


    @staticmethod
    def _parse_voting_delay(string):
        groups = Consensus._search_re(string, RE_VOTING_DELAY)
        voting_delay = {"vote": int(groups[0]), "dist": int(groups[1])}
        return voting_delay


    @staticmethod
    def parse(consensus_raw, flavor):
        """Parse a raw consensus."""

        raw = consensus_raw

        if flavor == Flavor.UNFLAVORED:
            flavor_str = "unflavored"
        else:
            flavor_str = "microdesc"

        network_status_version = {
            "version": int( Consensus._search_re(raw, RE_NETWORK_STATUS_VERSION)[0]),
            "flavor": flavor_str
        }

        vote_status = Consensus._search_re(raw, RE_VOTE_STATUS)[0]
        consensus_method = int(Consensus._search_re(raw, RE_CONSENSUS_METHOD)[0])
        valid_after = Consensus._parse_date(raw, RE_VALID_AFTER)
        fresh_until = Consensus._parse_date(raw, RE_FRESH_UNTIL)
        valid_until = Consensus._parse_date(raw, RE_VALID_UNTIL)
        voting_delay = Consensus._parse_voting_delay(raw)
        client_versions = Consensus._parse_versions(raw, RE_CLIENT_VERSIONS)
        server_versions = Consensus._parse_versions(raw, RE_SERVER_VERSIONS)
        known_flags = Consensus._search_re(raw, RE_KNOWN_FLAGS)[0].split(" ")
        rec_client_proto = Consensus._parse_protocols(raw, RE_RECOMMENDED_CLIENT_PROTOCOLS)
        rec_relay_proto = Consensus._parse_protocols(raw, RE_RECOMMENDED_RELAY_PROTOCOLS)
        req_client_proto = Consensus._parse_protocols(raw, RE_REQUIRED_CLIENT_PROTOCOLS)
        req_relay_proto = Consensus._parse_protocols(raw, RE_REQUIRED_RELAY_PROTOCOLS)
        shared_rand_curr_value = Consensus._parse_shared_rand(raw, RE_SHARED_RAND_CURRENT_VALUE)

        headers = {
            "network-status-version": network_status_version,
            "vote-status": vote_status,
            "consensus-method": consensus_method,
            "valid-after": valid_after,
            "fresh-until": fresh_until,
            "valid-until": valid_until,
            "voting-delay": voting_delay,
            "client-versions": client_versions,
            "server-versions": server_versions,
            "known-flags": known_flags,
            "recommended-client-protocols": rec_client_proto,
            "recommended-relay-protocols": rec_relay_proto,
            "required-client-protocols": req_client_proto,
            "required-relay-protocols": req_relay_proto,
            "shared-rand-current-value": shared_rand_curr_value
        }

        try:
            shared_rand_prev_value = Consensus._parse_shared_rand(raw, RE_SHARED_RAND_PREVIOUS_VALUE)
            headers["shared-rand-previous-value"] = shared_rand_prev_value
        except InvalidConsensus:
            pass

        dir_sources = list()

        for groups in Consensus._findall_re(raw, RE_DIR_SOURCE):
            dir_source = {
                "nickname": groups[0],
                "identity": groups[1].lower(),
                "hostname": groups[2],
                "address": groups[3],
                "dirport": int(groups[4]),
                "orport": int(groups[5]),
                "contact": groups[6],
                "vote-digest": groups[7].lower()
            }

            dir_sources.append(dir_source)

        relays = Consensus._parse_relays(raw, flavor)

        footer = Consensus._parse_footer(raw)

        consensus = {
            "flavor": flavor_str,
            "headers": headers,
            "dir-sources": dir_sources,
            "routers": relays,
            "footer": footer
        }

        return consensus


def extract_nodes_digests_unflavored(consensus_raw):
    """Retrieve a list of the digests of all routers in the consensus.
    """

    # We retrieve the third fields of the lines looking like that:
    #r VSIFskylab AD14gl4Llgnuz/Xk4FKXF3cuU8c 3VZwLdY0Et7vqUbqDdXg3WGGHCw 2020-01-12 23:47:04 104.218.63.73 443 80
    digests_raw = RE_RELAY_DIGEST_UNF.findall(consensus_raw)
    digests_bytes = [b64decode(digest + '====') for digest in digests_raw]

    return digests_bytes


def extract_nodes_digests_micro(consensus_raw):
    """Retrieve a list of the digests of all routers in the consensus.
    """
    # We retrieve the third fields of the lines looking like that:
    #m v7E0VcMnwVepVUh+j193lrbqbWOg26g9hXOBwSYv32I
    digests_raw = RE_RELAY_DIGEST_MIC.findall(consensus_raw)
    digests_bytes = [digest for digest in digests_raw]

    return digests_bytes


def download_direct(hostname, port, flavor=Flavor.MICRO):
    """Retrieve consensus via a direct HTTP connection.
    :param hostname: host name of the node from which to retrieve the consensus.
    :param port: port of the node from which to retrieve the consensus.
    :param flavor: flavour of the consensus to retrieve.
    """

    cons_raw = download_raw(hostname, port, flavor)

    keys = lnn.keys.fetch_and_parse_keys(hostname, port)

    if flavor == Flavor.UNFLAVORED:
        if not lnn.signature.verify(cons_raw, keys):
            raise InvalidConsensus("Invalid signature.")

    consensus = Consensus.parse(cons_raw, flavor=flavor)
    
    return consensus, keys


def download_raw(hostname, port, flavor=Flavor.UNFLAVORED):
    """Retrieve raw consensus via a direct HTTP connection.
    :param hostname: host name of the node from which to retrieve the consensus.
    :param port: port of the node from which to retrieve the consensus.
    :param flavor: flavour of the consensus to retrieve.
    """

    endpoint = 'consensus-microdesc' if flavor == Flavor.MICRO else 'consensus'
    uri = 'http://%s:%d/tor/status-vote/current/%s' % (hostname, port, endpoint)

    res = urllib.request.urlopen(uri)
    cons = res.read().decode('ASCII')

    return cons
