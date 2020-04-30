import json

from dictdiffer import diff

import lightnion as lnn
from lightnion.descriptors import Descriptors, Flavor


def test_micro_descriptors_parsing():
    with open("data/descriptors_micro_raw.txt", "r") as descriptors_fd:
        descriptors_raw = descriptors_fd.read()

    with open("data/descriptors_micro_parsed.txt", "r") as descriptors_fd:
        descriptors_expected = json.load(descriptors_fd)

    descriptors_parsed = Descriptors.parse(descriptors_raw, Flavor.MICRO)
    print(list(diff(descriptors_expected, descriptors_parsed)))
    assert descriptors_expected == descriptors_parsed


def test_descriptors_parsing():
    with open("data/descriptors_raw.txt", "r") as descriptors_fd:
        descriptors_raw = descriptors_fd.read()

    with open("data/descriptors_parsed.txt", "r") as descriptors_fd:
        descriptors_expected = json.load(descriptors_fd)

    descriptors_parsed = Descriptors.parse(descriptors_raw, Flavor.UNFLAVORED)
    print(list(diff(descriptors_expected, descriptors_parsed)))
    assert descriptors_expected == descriptors_parsed


if __name__ == "__main__":
    test_micro_descriptors_parsing()
    test_descriptors_parsing()
