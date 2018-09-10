import threading
import socket
import time
import ssl

def handshake(peer):
    peer.settimeout(3)

    ctr = 0
    print('Connect', time.time())
    try:
        fails = 0
        first = True
        while fails < 32:
            data = peer.recv(498)
            ctr += len(data)

            if first:
                first = False
                print('First', time.time())

            fails = fails + 1 if len(data) == 0 else 0
            peer.send(data)

            print(ctr // 498, end='\r', flush=True)
    except BaseException as e:
        print('\nClosed:', e, time.time())

class client(threading.Thread):
    def __init__(self, peer):
        super().__init__()
        self.peer = peer

    def run(self):
        handshake(self.peer)

if __name__ == '__main__':
    try:
        sock = socket.socket()
        sock.bind(('0.0.0.0', 12003))
        sock.listen()

        print('Listening here: ', sock.getsockname())
        while True:
            ssock, addr = sock.accept()
            print('Accept', time.time())
            try:
                thread = client(ssock)
                thread.start()
            except BaseException as e:
                if ssock:
                    ssock.close()
    finally:
        sock.close()
