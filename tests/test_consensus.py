import json

from dictdiffer import diff

import lightnion as lnn
from lightnion.consensus import Consensus, Flavor


def test_micro_consensus_parsing():
    with open("data/consensus_micro_raw.txt", "r") as consensus_fd:
        consensus_raw = consensus_fd.read()

    with open("data/consensus_micro_parsed.txt", "r") as consensus_fd:
        consensus_expected = json.load(consensus_fd)

    consensus_parsed = Consensus.parse(consensus_raw, Flavor.MICRO)
    print(list(diff(consensus_expected, consensus_parsed)))
    assert consensus_expected == consensus_parsed


def test_consensus_parsing():
    with open("data/consensus_raw.txt", "r") as consensus_fd:
        consensus_raw = consensus_fd.read()

    with open("data/consensus_parsed.txt", "r") as consensus_fd:
        consensus_expected = json.load(consensus_fd)

    consensus_parsed = Consensus.parse(consensus_raw, Flavor.UNFLAVORED)
    print(list(diff(consensus_expected, consensus_parsed)))
    assert consensus_expected == consensus_parsed


if __name__ == "__main__":
    test_micro_consensus_parsing()
    test_consensus_parsing()
