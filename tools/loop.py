import socket
import ssl

def handshake(peer):
    peer.settimeout(3)

    ctr = 0
    print('Connect')
    try:
        fails = 0
        while fails < 32:
            ctr += 1

            data = peer.recv(498)
            fails = fails + 1 if len(data) == 0 else 0
            peer.send(data)

            print(ctr, end='\r', flush=True)
    except BaseException as e:
        print('\nClosed:', e)

if __name__ == '__main__':
    try:
        sock = socket.socket()
        sock.bind(('0.0.0.0', 12003))
        sock.listen()

        print('Listening here: ', sock.getsockname())
        while True:
            ssock, addr = sock.accept()
            print('Accept')
            try:
                handshake(ssock)
            finally:
                if ssock:
                    ssock.close()
    finally:
        sock.close()
