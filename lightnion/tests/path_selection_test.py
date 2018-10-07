from lightnion import path_selection as ps
from lightnion import link
from lightnion import create
from lightnion import consensus
import pytest


@pytest.fixture()
def get_chutney_consensus():
    """Get chutney's consensus"""
    lk = link.initiate(port=5000)
    state = create.fast(lk)
    state, cons = consensus.download(state, flavor='unflavored')

    dict_cons = {}
    for router in cons['routers']:
        dict_cons[router['nickname']] = router

    return state, dict_cons


def test_keep_exit_works_with_suitable_router(get_chutney_consensus):
    state, cons = get_chutney_consensus

    keep, state, descriptor = ps.keep_exit(cons['test006r'], state)

    assert keep and descriptor is not None


def test_keep_exit_works_with_reject_exit_policy(get_chutney_consensus):
    state, cons = get_chutney_consensus

    keep, state, descriptor = ps.keep_exit(cons['test002a'], state)

    assert not keep and descriptor is None


def test_pick_good_exit_returns_a_router(get_chutney_consensus):
    state, cons = get_chutney_consensus
    routers = cons.values()

    state, exit_node = ps.pick_good_exit(routers, state)

    print(exit_node)

    assert exit_node is not None
