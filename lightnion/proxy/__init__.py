fake_circuit_id = 0x80000000
api_version = 0.1
base_url = '/lightnion/api/v{}'.format(api_version)


from . import cell, parts, auth, jobs, link
