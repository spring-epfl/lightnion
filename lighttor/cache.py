import os
import time
import json
import shutil
import base64
import logging

cache_directory = 'lighttor-cache'

def directory(base_dir=None):
    if base_dir is None:
        base_dir = os.getcwd()
    base_dir = os.path.join(base_dir, cache_directory)

    if not os.path.isdir(base_dir):
        logging.info(
            'Note: creating {} to cache descriptors.'.format(base_dir))
        os.mkdir(base_dir)

    if not os.path.isdir(base_dir):
        raise RuntimeError(
            'Unable to fetch cache directory: {}'.format(base_dir))

    return base_dir

def purge():
    base_dir = directory()
    logging.warning('Note: removing {} to purge cache.'.format(base_dir))
    shutil.rmtree(base_dir)

class descriptors:
    @staticmethod
    def filename(descriptor, get=False):
        base_dir = 'descriptors'
        if 'micro' in descriptor['flavor']:
            base_dir = 'micro-' + base_dir
        base_dir = os.path.join(directory(), base_dir)

        if not os.path.isdir(base_dir):
            os.mkdir(base_dir)

        field = 'digest'
        if 'micro' in descriptor['flavor']:
            field = 'micro-digest'

        digest = descriptor[field]
        if (not get) or 'micro' in descriptor['flavor']:
            digest = base64.b64decode(descriptor[field] + '====').hex()

        half_dir = os.path.join(base_dir, digest[:2])
        if not os.path.isdir(half_dir):
            os.mkdir(half_dir)

        return os.path.join(half_dir, digest)

    @staticmethod
    def put(descriptor):
        filename = descriptors.filename(descriptor)
        if os.path.isfile(filename):
            return
        with open(filename, 'w') as f:
            json.dump(descriptor, f)

    @staticmethod
    def get(flavor, digest):
        field = 'digest'
        if 'micro' in flavor:
            field = 'micro-digest'

        descriptor = {'flavor': flavor, field: digest}
        filename = descriptors.filename(descriptor, get=True)
        with open(filename, 'r') as f:
            descriptor = json.load(f)

        if not descriptor['flavor'] == flavor:
            raise ValueError('Mismatched flavor.')

        new_digest = descriptor[field]
        if not 'micro' in field:
            new_digest = base64.b64decode(new_digest + '====').hex()

        if not new_digest == digest:
            raise ValueError('Mismatched digest.')

        return descriptor

class consensus:
    @staticmethod
    def filename(flavor):
        return os.path.join(directory(), 'consensus-{}'.format(flavor))

    @staticmethod
    def put(fields):
        filename = consensus.filename(fields['flavor'])
        with open(filename, 'w') as f:
            json.dump(fields, f)

    @staticmethod
    def get(flavor):
        filename = consensus.filename(flavor)
        with open(filename, 'r') as f:
            fields = json.load(f)

        if not fields['flavor'] == flavor:
            raise ValueError('Mismatched flavor.')

        if fields['headers']['valid-until']['stamp'] < time.time():
            raise ValueError('Consensus need to be refreshed: {} < {}'.format(
                fields['headers']['valid-until']['stamp'], time.time()))

        return fields
