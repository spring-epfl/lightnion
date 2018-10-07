import lightnion.descriptors as descriptors
import random


def select_path(routers, state):
    """Handle the path selection
    :params routers: list of the routers given by the consensus
    :state:
    :returns: tuple (guard, middle, exit)"""

    state, exit = pick_good_exit(routers, state)


def keep_exit(router, state):
    """Checks that the router is not a bad exit, is not down, is stable,
    is valid, does not run an old TOR's version, has an available ed25519
    identity key and has an 'accept' exit policy
    :params router: the router we want to check
    :state:
    :return: tuple (boolean that indicates if we keep it, new state, descriptor)"""

    if 'BadExit' in router['flags']:
        return False, state, None

    if 'Running' not in router['flags']:
        return False, state, None

    if 'Stable' not in router['flags']:
        return False, state, None

    if 'Valid' not in router['flags']:
        return False, state, None

    if not router['version'].startswith('Tor 0.3.'):
        return False, state, None

    # Retrieve the descriptor
    state, nhop = descriptors.download(state, cons=router, flavor='unflavored')
    nhop = nhop[0]

    if router['digest'] != nhop['digest']:
        return False, state, None

    if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
        return False, state, None

    if 'policy' not in nhop or nhop['policy']['rules'][0]['type'] != 'accept':
        return False, state, None

    return True, state, nhop


def weighted_random_choice(list_of_possible):
    """Choose one of the candidates at random weighted by their (avg)  bandwith
    :params list_of_possible: list of descriptors of the candidates
    :returns: descriptor of the randomly selected router"""

    total = 0
    for router in list_of_possible:
        total += router['bandwidth']['avg']

    r = random.uniform(0, total)
    upto = 0

    for router in list_of_possible:
        if upto + router['bandwidth']['avg'] >= r:
            return router
        upto += router['bandwidth']['avg']

    raise RuntimeError("")


def pick_good_exit(routers, state):
    """Choose the exit node"""

    # keep only the routers with the flag exit
    candidates = []

    for router in routers:
        if "Exit" in router['flags']:
            candidates.append(router)

    # keep only suitable candidates
    if not candidates == []:
        good_candidates = []
        for router in candidates:
            keep, state, descriptor = keep_exit(router, state)
            if keep:
                good_candidates.append(descriptor)

        print("Choose 1 router out of {}.".format(len(good_candidates)))

        return state, weighted_random_choice(good_candidates)
    else:
        # TODO: see if we select another policy here
        raise ValueError('No exit is suitable')
