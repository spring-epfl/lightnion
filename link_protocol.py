import stem
import stem.client.cell
import stem.client.datatype
import stem.socket

def handshake(address='127.0.0.1', port=9050, versions=[3, 4, 5], sanity=True):
    """
    We replicate here a link "in-protocol" (v3) handshake:
     - https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L257

    The expected transcript from the point of view of a "client" is:

         (... establish a proper TLS/SSLv3 handshake link here ...)

           Onion Proxy (client)              Onion Router (server)

               /   [1] :-------- VERSIONS ---------> [2]
               |   [4] <-------- VERSIONS ---------: [3]
               |
               |           Negotiated Version
               |                  >= 3
               |
               |   [4] <--------- CERTS -----------: [3]
               |       <----- AUTH_CHALLENGE ------:
               |       <-------- NETINFO ----------:
               |
               |             OP don't need to
        Link   |               authenticate
      Protocol |
        >= 3   |   [5] :-------- NETINFO ----------> [6]
               |
               |
               | Alternative:
               | (          We (OR) authenticate         )
               | (                                       )
               | ( [5] :--------- CERTS -----------> [6] )
               | (     :------ AUTHENTICATE ------->     )
               | (             ^                         )
               | (            (answers AUTH_CHALLENGE)   )
               | (                                       )
               \

    After establishing a link via such "in-protocol" handshake, we can perform
    further operations (for example, establishing a circuit).

    :param str address: remote relay address (default: 127.0.0.1).
    :param int port: remote relay ORPort (default: 9050).
    :param list versions: target link versions (default: [3, 4, 5]).
    :param bool sanity: checks v3 handshake compliance (default: False).

    :returns: a tuple (link socket, link version)

    """

    # [1] Connect to the OR
    socket = stem.socket.RelaySocket(address, port)

    # [1:2] Send a VERSIONS cell to begin with.
    #
    # See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L553
    #
    versions_scell = stem.client.cell.VersionsCell(versions)
    socket.send(versions_scell.pack())

    # [3:4] Receive a VERSIONS cell from the OR.
    answer = socket.recv()
    if not answer:
        socket.close()
        return None, None # (abort if we get no answer to our first cell)

    # [4] We need to have a circuit_id of 2 bytes for VERSIONS cell, hence we
    #     explicitly require here to use an older link_protocol version (< v4).
    #
    # See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L438
    #
    versions_rcell, answer = stem.client.cell.Cell.pop(answer, 2)

    # [4] We compute the set of common versions between the two VERSIONS cell.
    #
    common = set(versions)
    common = common.intersection(versions_rcell.versions)
    if len(common) < 1:
        socket.close()
        return None, None # (abort if no common versions found)

    # [4] We keep the maximal common version
    version = max(common)
    if version < 3:
        return None, None # (let's say that we don't support v2-or-lower links)

    # [3:4] We also expect CERTS, AUTH_CHALLENGE, NETINFO cells afterwards
    if sanity:
        certs_rcell, answer = stem.client.cell.Cell.pop(answer, version)
        assert isinstance(certs_rcell, stem.client.cell.CertsCell)

        auth_rcell, answer = stem.client.cell.Cell.pop(answer, version)
        assert isinstance(auth_rcell, stem.client.cell.AuthChallengeCell)

        netinfo_rcell, answer = stem.client.cell.Cell.pop(answer, version)
        assert isinstance(netinfo_rcell, stem.client.cell.NetinfoCell)

    # [5:6] We send the required NETINFO cell to finish the handshake
    #
    # See https://github.com/plcp/tor-scripts/blob/master/torspec/tor-spec-4d0d42f.txt#L518
    #
    address_packable = stem.client.datatype.Address(address) # stem's datatype
    netinfo_scell = stem.client.cell.NetinfoCell(address_packable, [])

    socket.send(netinfo_scell.pack(version)) # (use negotiated version)
    return (socket, version)

def keepalive(link):
    """
    Send a keepalive through a given link.

    :params tuple link: a tuple (link socket, link version)
    """
    link_socket, link_version = link
    link_socket.send(stem.client.cell.PaddingCell().pack(link_version))

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('addr', nargs='?', default='127.0.0.1')
    parser.add_argument('port', nargs='?', type=int, default=9050)
    sys_argv = parser.parse_args()

    link = handshake(address=sys_argv.addr, port=sys_argv.port)
    print('Link v{} established – {}'.format(link[1], link[0]))
