import random
import sys
import logging

import lightnion.descriptors as descriptors

# Chutney launches all relays in the same subnet.
# So to test the proxy with Chutney, these checks needs to be disabled.
check_different_subnets = False

def select_path(routers, state, testing=False):
    """Handle the path selection
    :params routers: list of the routers given by the consensus
    :state:
    :returns: updated state tuple (guard, middle, exit)"""

    logging.warning('Use of DEPRECATED method %s()' % sys._getframe().f_code.co_name)

    routers = [r for r in routers if obey_minimal_constraint(r)]

    state, exit_node = pick_good_exit(routers, state)

    state, guard = pick_good_entry(routers, state, exit_node, testing)

    state, middle = pick_good_middle(routers, state, exit_node, guard, testing)

    return state, guard, middle, exit_node


def select_guard_from_consensus(cons, descr, testing=False):
    """Handle the selection of the guard node
    :params routers: list of the routers given by the consensus
    :params descr: list of descriptors
    :returns: tuple (guard, middle, exit)"""

    routers = [r for r in cons['routers'] if obey_minimal_constraint(r)]

    guard = pick_good_entry_from_routers(descr, routers, testing)

    return guard


def select_end_path_from_consensus(cons, descr, guard, testing=False):
    """Handle the selection of the middle and exit nodes
    :params routers: list of the routers given by the consensus
    :params descr: list of descriptors
    :returns: tuple (guard, middle, exit)"""

    routers = [r for r in cons['routers'] if obey_minimal_constraint(r)]
    exit_node = pick_good_exit_from_routers(descr, routers, guard)
    middle    = pick_good_middle_from_routers(descr, routers, exit_node, guard, testing)

    return middle, exit_node


def obey_minimal_constraint(router, exit_node=None, guard=None, testing=False):
    """Checks if the given router respects the minimal constraints
    :param testing:
    :param router: router that must respect the constraints
    :param exit_node: the chosen exit node
    :param guard: the chosen guard node
    :return: boolean"""

    flags = router['flags']
    router_address = router['address'].split(".")

    # check that the router  is running, valid and has a recent version of TOR
    if 'Running' not in flags:
        return False
    if 'Valid' not in flags:
        return False
    if not router['version'].startswith('Tor 0.3.'):
        return False

    if exit_node is not None:

        # check that they are distinct
        if router['digest'] == exit_node['digest']:
            return False

        # check if they are in the same 16 subnet
        if check_different_subnets:
            exit_addr = exit_node['router']['address'].split(".")
            if not testing and router_address[0] == exit_addr[0] and router_address[1] == exit_addr[1]:
                return False

    if guard is not None:

        # check that they are distinct
        if router['digest'] == guard['digest']:
            return False

        # check if they are in the same 16 subnet
        if check_different_subnets:
            guard_addr = guard['router']['address'].split(".")
            if not testing and router_address[0] == guard_addr[0] and router_address[1] == guard_addr[1]:
                return False

    return True


def in_same_family(r0, r1, r2=None):
    """Check if r0 and r1 (and possibly r0 and r2) are in the same family or not
    :param r0: the descriptor of the first router (the router we are trying to see if it meets all conditions to be chosen)
    :param r1: the descriptor of the second router
    :param r2: the descriptor of the third router (possibly none)
    :return: a boolean"""

    # check if r0 and r1 are in the same family
    if 'family' in r0 and 'family' in r1:
        for f in r0['family']:
            if f in r1['family']:
                return True

    if r2 and 'family' in r0 and 'family' in r2:
        for f in r0['family']:
            if f in r2['family']:
                return True

    return False


def keep_exit(router, state):
    """Checks that the router is not a bad exit, is not down, is stable,
    is valid, does not run an old TOR's version, has an available ed25519
    identity key and has an 'accept' exit policy
    :params router: the router we want to check
    :state:
    :return: tuple (boolean that indicates if we keep it, new state, descriptor)"""

    logging.warning('Use of DEPRECATED method %s()' % sys._getframe().f_code.co_name)

    if not obey_minimal_constraint(router):
        return False, state, None

    if 'Exit' not in router['flags']:
        return False, state, None

    if 'BadExit' in router['flags']:
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


def keep_exit_with_descr(descr, router, guard):
    """Checks that the router is not a bad exit, is not down, is stable,
    is valid, does not run an old TOR's version, has an available ed25519
    identity key and has an 'accept' exit policy
    :param descr: descriptor of the exit candidate.
    :params router: the router we want to check
    :param guard: the guard in the path
    :return: tuple (boolean that indicates if we keep it, new state, descriptor)"""

    if not obey_minimal_constraint(router, guard=guard):
        return False, None

    if 'Exit' not in router['flags']:
        return False, None

    if 'BadExit' in router['flags']:
        return False, None

    if router['digest'] not in descr:
        return False, None

    nhop = descr[router['digest']]

    if router['digest'] != nhop['digest']:
        return False, None

    if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
        return False, None

    if 'policy' not in nhop or nhop['policy']['rules'][0]['type'] != 'accept':
        return False, None

    if in_same_family(nhop, guard):
        return False, None

    return True, nhop



def weighted_random_choice(list_of_possible):
    """Choose one of the candidates at random weighted by their (avg) bandwidth
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
    """Choose the exit node
    :param routers: the routers given by the consensus
    :param state: the state
    :return: the descriptor of the exit node"""

    logging.warning('Use of DEPRECATED method %s()' % sys._getframe().f_code.co_name)

    # Go through all routers and check if they meet the conditions of an exit node
    candidates = []
    for router in routers:
        keep, state, descriptor = keep_exit(router, state)
        if keep:
            candidates.append(descriptor)

    if candidates:
        return state, weighted_random_choice(candidates)

    else:
        # TODO: see if we select another policy here
        raise ValueError('No exit is suitable')


def pick_good_exit_from_routers(descr, routers, guard):
    """Choose the exit node
    :param routers: the routers given by the consensus
    :param guard: the guard in the path
    :return: the descriptor of the exit node"""

    # Go through all routers and check if they meet the conditions of an exit node
    candidates = []
    for router in routers:
        keep, descriptor = keep_exit_with_descr(descr, router, guard)
        if keep:
            candidates.append(descriptor)

    if candidates:
        return weighted_random_choice(candidates)

    else:
        # TODO: see if we select another policy here
        raise ValueError('No exit is suitable')



def keep_guard(router, state, exit_node, testing):
    """Checks that the given router has the properties to be a guard
    :param router: the router that must be inspected
    :param state: state
    :param exit_node: the previously chosen node
    :return: if the router can be kept, the updated state and the descriptor"""

    logging.warning('Use of DEPRECATED method %s()' % sys._getframe().f_code.co_name)

    flags = router['flags']

    if not obey_minimal_constraint(router, exit_node, testing=testing):
        return False, state, None

    if 'Guard' not in flags:
        return False, state, None

    if 'Stable' not in flags:
        return False, state, None

    if 'Fast' not in flags:
        return False, state, None

    if 'V2Dir' not in flags:
        return False, state, None

    # Retrieve the descriptor
    state, nhop = descriptors.download(state, cons=router, flavor='unflavored')
    nhop = nhop[0]

    if router['digest'] != nhop['digest']:
        return False, state, None

    if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
        return False, state, None

    if in_same_family(nhop, exit_node):
        return False, state, None

    return True, state, nhop



def keep_guard_with_descr(descr, router, testing):
    """Checks that the given router has the properties to be a guard
    :param descr: descriptor of the exit candidate.
    :param router: the router that must be inspected
    :return: if the router can be kept, the updated state and the descriptor"""

    flags = router['flags']

    if not obey_minimal_constraint(router, testing=testing):
        return False, None

    if 'Guard' not in flags:
        return False, None

    if 'Stable' not in flags:
        return False, None

    if 'Fast' not in flags:
        return False, None

    if 'V2Dir' not in flags:
        return False, None

    if router['digest'] not in descr:
        return False, None

    nhop = descr[router['digest']]

    if router['digest'] != nhop['digest']:
        return False, None

    if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
        return False, None

    return True, nhop



def pick_good_entry(routers, state, exit_node, testing):
    """Simplified version of the Guard selection algorithm
    :param routers: the routers of the consensus
    :param state: the state
    :return: updated state and the descriptor of the guard node"""

    logging.warning('Use of DEPRECATED method %s()' % sys._getframe().f_code.co_name)

    candidates = []
    for router in routers:
        keep, state, descriptor = keep_guard(router, state, exit_node, testing)
        if keep:
            candidates.append(descriptor)

    if candidates:
        return state, weighted_random_choice(candidates)

    else:
        # TODO: see if we select another policy here
        raise ValueError('No guard is suitable')


def pick_good_entry_from_routers(descr, routers, testing):
    """Simplified version of the Guard selection algorithm
    :param routers: the routers of the consensus
    :param state: the state
    :return: updated state and the descriptor of the guard node"""

    candidates = []
    for router in routers:
        keep, descriptor = keep_guard_with_descr(descr, router, testing)
        if keep:
            candidates.append(descriptor)

    if candidates:
        return weighted_random_choice(candidates)

    else:
        # TODO: see if we select another policy here
        raise ValueError('No guard is suitable')


def keep_middle(router, state, exit_node, guard, testing):
    """Checks that the given router has the properties to be a middle node
       :param router: the router that must be inspected
       :param state: state
       :param exit_node: the previously chosen exit node
       :param guard: the previously chosen guard
       :return: if the router can be kept, the updated state and the descriptor"""

    logging.warning('Use of DEPRECATED method %s()' % sys._getframe().f_code.co_name)

    if not obey_minimal_constraint(router, exit_node, guard, testing=testing):
        return False, state, None

    # Retrieve the descriptor
    state, nhop = descriptors.download(state, cons=router, flavor='unflavored')
    nhop = nhop[0]

    if router['digest'] != nhop['digest']:
        return False, state, None

    if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
        return False, state, None

    if in_same_family(nhop, guard, exit_node):
        return False, state, None

    return True, state, nhop


def keep_middle_with_descr(descr, router, exit_node, guard, testing):
    """Checks that the given router has the properties to be a middle node
       :param descr: descriptor of the exit candidate.
       :param router: the router that must be inspected
       :param exit_node: the previously chosen exit node
       :param guard: the previously chosen guard
       :return: if the router can be kept, the updated state and the descriptor"""
    if not obey_minimal_constraint(router, exit_node, guard, testing=testing):
        return False, None

    if router['digest'] not in descr:
        return False, None

    nhop = descr[router['digest']]

    if router['digest'] != nhop['digest']:
        return False, None

    if 'identity' not in nhop or nhop['identity']['type'] != 'ed25519':
        return False, None

    if in_same_family(nhop, guard, exit_node):
        return False, None

    return True, nhop


def pick_good_middle(routers, state, exit_node, guard, testing):
    """Choose the middle node given the exit and the guard node
    :param routers: the routers of the consensus
    :param state: the state
    :param exit_node: the previously chosen exit node
    :param guard: the previously chosen guard node
    :return: updated state and the descriptor of the guard node"""

    logging.warning('Use of DEPRECATED method %s()' % sys._getframe().f_code.co_name)

    candidates = []
    for router in routers:
        keep, state, descriptor = keep_middle(router, state, exit_node, guard, testing)
        if keep:
            candidates.append(descriptor)
    if candidates:
        return state, weighted_random_choice(candidates)

    else:
        # TODO: see if we select another policy here
        raise ValueError('No middle node is suitable')


def pick_good_middle_from_routers(descr, routers, exit_node, guard, testing):
    """Choose the middle node given the exit and the guard node
    :param routers: the routers of the consensus
    :param exit_node: the previously chosen exit node
    :param guard: the previously chosen guard node
    :return: updated state and the descriptor of the guard node"""

    candidates = []
    for router in routers:
        keep, descriptor = keep_middle_with_descr(descr, router, exit_node, guard, testing)
        if keep:
            candidates.append(descriptor)

    if candidates:
        return weighted_random_choice(candidates)

    else:
        # TODO: see if we select another policy here
        raise ValueError('No middle node is suitable')
