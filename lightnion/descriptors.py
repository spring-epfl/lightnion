"""
Descriptors handlers.
"""

import base64
import re
from datetime import datetime, timezone
import logging
import urllib.request

from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.microdescriptor import Microdescriptor

import lightnion as lnn
from lightnion.consensus import Flavor

RE_ROUTERS_UNF = re.compile(r"^router ", re.M)
RE_ROUTERS_MIC = re.compile(r"^onion-key\n", re.M)

RE_PEM = re.compile(r"""-----BEGIN [^-]+-----
([A-Za-z0-9+/=\n]+)
-----END [^-]+-----""")

FLAVOR_STR_MIC = "microdesc"
FLAVOR_STR_UNF = "unflavored"

IDENTIFIERS_TYPES = (
    "ed25519",
    "rsa1024"
)


class InvalidDescriptor(Exception):
    pass


class Descriptors:

    @staticmethod
    def _search_re(string, regex):
        # Convenience function to search for the first instance of the pattern.
        match = regex.search(string)
        if not match:
            raise InvalidDescriptor("Invalid format.")

        groups = match.groups()
        return groups


    @staticmethod
    def _findall_re(string, regex):
        # Convenience function to search for all instances of the pattern.
        groups = regex.findall(string)
        if not groups:
            raise InvalidDescriptor("Invalid format.")

        return groups


    @staticmethod
    def _date_from_datetime(dt):
        date_dict = {
            "date": "{:04d}-{:02d}-{:02d}".format(dt.year, dt.month, dt.day),
            "time": "{:02d}:{:02d}:{:02d}".format(dt.hour, dt.minute, dt.second),
            "stamp": dt.replace(tzinfo=timezone.utc).timestamp()
        }
        return date_dict


    @staticmethod
    def _parse_exit_policy(policy):
        rules = list()
        for rule_obj in policy:
            rule_l = str(rule_obj).split(" ")
            rule = {
                "type": rule_l[0],
                "pattern": rule_l[1]
            }
            rules.append(rule)

        policy_dict = {
            "type": "exitpattern",
            "rules": rules
        }

        return policy_dict


    @staticmethod
    def _parse_exit_policy_mic(policy):

        if not policy:
            return None

        summary = policy.summary()
        # something like 'reject 1-442, 444-1024'

        if summary == "reject 1-65535":
            return None

        rules = list()
        rule_type = summary[0:6]
        ports_pairs = summary[7:].split(", ")

        for ports_pair in ports_pairs:
            if "-" in ports_pair:
                port_min, port_max = ports_pair.split("-")
            else:
                port_min = port_max = ports_pairs

            rules.append([int(port_min), int(port_max)])

        policy_dict = {
            "type": rule_type,
            "PortList": rules
        }

        return policy_dict


    @staticmethod
    def _parse_router_mic(string):
        desc = Microdescriptor(string)

        identity = None
        for identifier_type in IDENTIFIERS_TYPES:
            if identifier_type in desc.identifiers:
                identity = {
                    "type": identifier_type,
                    "master-key": desc.identifiers[identifier_type]
                }
                break

        if not identity:
            raise InvalidDescriptor

        onion_key = Descriptors._search_re(desc.onion_key, RE_PEM)[0]

        microdescriptor = {
            "micro-digest": desc.digest(),
            "onion-key": onion_key.replace("\n", ""),
            "ntor-onion-key": desc.ntor_onion_key,
            "identity": identity,
            "flavor": FLAVOR_STR_MIC
        }

        policy = Descriptors._parse_exit_policy_mic(desc.exit_policy)
        if policy:
            microdescriptor["policy"] = policy

        policy = Descriptors._parse_exit_policy_mic(desc.exit_policy_v6)
        if policy:
            microdescriptor["ipv6-policy"] = policy

        return microdescriptor


    @staticmethod
    def _parse_router_unf(string):
        desc = RelayDescriptor(string)

        router_id = base64.b64encode(bytes.fromhex(desc.fingerprint.replace(" ", ""))).replace(b"=", b"").replace(b"\n", b"")

        identity_cert = Descriptors._search_re(desc.ed25519_certificate, RE_PEM)[0].replace("\n", "")

        fingerprint = desc.fingerprint
        fingerprint = " ".join([fingerprint[i:i+4] for i in range(0,len(fingerprint),4)])

        onion_key = Descriptors._search_re(desc.onion_key, RE_PEM)[0].replace("\n", "")
        signing_key = Descriptors._search_re(desc.signing_key, RE_PEM)[0].replace("\n", "")
        onion_key_crosscert = Descriptors._search_re(desc.onion_key_crosscert, RE_PEM)[0].replace("\n", "")
        ntor_onion_key_crosscert = Descriptors._search_re(desc.ntor_onion_key_crosscert, RE_PEM)[0].replace("\n", "")
        rsa_signature = Descriptors._search_re(desc.signature, RE_PEM)[0].replace("\n", "")

        descriptor = {
            "digest": desc.digest(hash_type='SHA1',encoding='BASE64'),
            "router": {
                "nickname": desc.nickname,
                "address": desc.address,
                "orport": desc.or_port,
                "socksport": 0,
                "dirport": desc.dir_port,
                "identity": router_id.decode("ASCII")
            },
            "identity": {
                "type": "ed25519",
                "cert": identity_cert,
                "master-key": desc.ed25519_master_key
            },
            "platform": desc.platform.decode("ASCII"),
            "proto": desc.protocols,
            "published": Descriptors._date_from_datetime(desc.published),
            "fingerprint": fingerprint,
            "uptime": desc.uptime,
            "bandwidth": {
                "avg": desc.average_bandwidth,
                "burst": desc.burst_bandwidth,
                "observed": desc.observed_bandwidth
            },
            "extra-info-digest": {
                "sha1": desc.extra_info_digest,
                "sha256": desc.extra_info_sha256_digest
            },
            "onion-key": onion_key,
            "signing-key": signing_key,
            "onion-key-crosscert": onion_key_crosscert,
            "ntor-onion-key-crosscert": {
                "bit": int(desc.ntor_onion_key_crosscert_sign),
                "cert": ntor_onion_key_crosscert
            },
            "hidden-service-dir": desc.is_hidden_service_dir,
            "ntor-onion-key": desc.ntor_onion_key,
            "tunnelled-dir-server": desc.allow_tunneled_dir_requests,
            "router-signatures": {
                "ed25519": desc.ed25519_signature,
                "rsa": rsa_signature
            },
            "flavor": FLAVOR_STR_UNF
        }

        if desc.extra_info_cache:
            descriptor["caches-extra-info"] = True

        if desc.exit_policy:
            policy = Descriptors._parse_exit_policy(desc.exit_policy)
            descriptor["policy"] = policy

        policy = Descriptors._parse_exit_policy_mic(desc.exit_policy_v6)
        if policy:
            descriptor["ipv6-policy"] = policy


        if desc.contact:
            contact = desc.contact.decode("ASCII")

            descriptor["contact"] = contact

        return descriptor


    @staticmethod
    def parse(descriptors_raw, flavor=Flavor.MICRO):

        # alias
        raw = descriptors_raw

        if flavor == Flavor.MICRO:
            flavor_str = FLAVOR_STR_MIC
            router_func = Descriptors._parse_router_mic
            routers_regex = RE_ROUTERS_MIC
        elif flavor == Flavor.UNFLAVORED:
            flavor_str = FLAVOR_STR_UNF
            router_func = Descriptors._parse_router_unf
            routers_regex = RE_ROUTERS_UNF

        routers = list()

        matches = routers_regex.finditer(descriptors_raw)
        if not matches:
            raise InvalidDescriptor("Invalid format.")

        match = next(matches)

        idx_0 = match.start()

        for match in matches:
            idx_1 = match.start()

            router = router_func(raw[idx_0:idx_1])
            routers.append(router)

            idx_0 = idx_1

        router = router_func(raw[idx_0:-1])
        routers.append(router)

        descriptors = {
            "flavor": flavor_str,
            "descriptors": routers
        }

        return descriptors


def batch_query(items, prefix, separator='-', fixed_max_length=4096-128):
    # About batches:
    #    https://github.com/plcp/tor-scripts/blob/master/torspec/dir-spec-4d0d42f.txt#L3392

    query = ''
    query_len = 0
    prefix_len = len(prefix)
    sep_len = len(separator)

    for item in items:
        item_len = len(item)
        if query_len + item_len >= fixed_max_length:
            yield query
            query = ''
            query_len = 0

        if query:
            query += separator + item
            query_len += item_len + sep_len
        else:
            query += prefix + item
            query_len += item_len + prefix_len

    if query:
        yield query


def filter_descriptors(descriptors, digests, flavor=Flavor.UNFLAVORED):
    """Filter out the invalid descriptors.
    :param descriptors: Descriptors to be filtered.
    :param digests: Digests from the consensus.
    :param flavor: Flavor of the descriptor.
    """

    descriptor_digests = set()
    descriptors_d = dict()

    # Content depends on descriptor flavour.
    if flavor == Flavor.MICRO:
        for descriptor in descriptors:
            fingerprint = descriptor['micro-digest']
            descriptor_digests.add(fingerprint)
            descriptors_d[fingerprint] = descriptor
    else:
        for descriptor in descriptors:
            fingerprint = base64.b64decode(descriptor['digest'] + '====').hex()
            descriptor_digests.add(fingerprint)
            descriptors_d[fingerprint] = descriptor

    fingerprints_valid = descriptor_digests.intersection(digests)
    descriptors_valid = [descriptors_d[fingerprint] for fingerprint in fingerprints_valid]

    # For logging only.
    desc_l = len(descriptors)
    valid_l = len(descriptors_valid)
    invalid_l = desc_l - valid_l

    logging.info('Filtered %d descriptors, %d valid, %d invalid.', desc_l, valid_l, invalid_l)

    return descriptors_valid


def download_direct(host, port, cons, flavor=Flavor.MICRO):

    if flavor == Flavor.MICRO:
        endpoint = '/tor/micro/d/'
        separator = '-'
        digests = [router['micro-digest'] for router in cons['routers']]
    else:
        endpoint = '/tor/server/d/'
        separator = '+'
        digests = [base64.b64decode(router['digest'] + '====').hex() for router in cons['routers']]

    descriptors = list()

    for query in batch_query(digests, endpoint, separator):
        uri = 'http://%s:%d%s' % (host, port, query)
        res = urllib.request.urlopen(uri)

        if res is None or res.getcode() != 200:
            raise RuntimeError('Unable to fetch descriptors.')

        # Rename parse to something sensible
        new_batch = Descriptors.parse(res.read().decode("ASCII"), flavor=flavor)

        if not new_batch['descriptors']:
            raise RuntimeError('No descriptors listed on {}:{}.'.format(host, port))

        if new_batch is not None:
            descriptors += new_batch['descriptors']

    descriptors = filter_descriptors(descriptors, digests, flavor=flavor)

    if flavor == Flavor.MICRO:
        return {d['micro-digest']: d for d in descriptors}
    else:
        return {d['digest']: d for d in descriptors}


def _download_raw_by_digests(host, port, digests, endpoint, separator):
    """Retrieve  descriptor via a direct HTTP connection.
    """
    desc = b""
    for query in batch_query(digests, endpoint, separator):
        uri = 'http://{}:{}{}'.format(host, port, query)
        res = urllib.request.urlopen(uri)

        if res is None or res.getcode() != 200:
            raise RuntimeError('Unable to fetch descriptors.')

        desc += res.read()

    return desc


def download_raw_by_digests_micro(host, port, digests_bytes):
    """Retrieve  descriptor via a direct HTTP connection.
    :param host: host from which to retrieve the descriptors.
    :param port: port from which to retrieve the descriptors.
    :param digests: Digests (in a binary form) of the nodes for which a descriptor need to be retrieved.
    """

    endpoint = '/tor/micro/d/'
    separator = '-'
    digests = digests_bytes
    return _download_raw_by_digests(host, port, digests, endpoint, separator)


def download_raw_by_digests_unflavored(host, port, digests_bytes):
    """Retrieve  descriptor via a direct HTTP connection.
    :param host: host from which to retrieve the descriptors.
    :param port: port from which to retrieve the descriptors.
    :param digests: Digests (in a binary form) of the nodes for which a descriptor need to be retrieved.
    """

    digests = [digest.hex() for digest in digests_bytes]
    endpoint = '/tor/server/d/'
    separator = '+'

    return _download_raw_by_digests(host, port, digests, endpoint, separator)


def download_relay_descriptor(host='127.0.0.1', port=9051):
    """Retrieve a relay's own descriptor.
    """

    uri = 'http://{}:{}/tor/server/authority'.format(host, port)
    res = urllib.request.urlopen(uri)

    if res is None or res.getcode() != 200:
        raise RuntimeError('Unable to fetch descriptors.')

    descriptors = Descriptors.parse(res.read().decode("ASCII"), flavor=Flavor.UNFLAVORED)

    return descriptors['descriptors'][0]

