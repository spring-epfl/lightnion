import socket
import ssl

def handshake(peer):
    print(peer.recv())

if __name__ == '__main__':
    sock = socket.socket()
    sock.bind(('0.0.0.0', 0))
    sock.listen()

    print('Listening here: ', sock.getsockname())
    while True:
        conn = None
        ssock, addr = sock.accept()
        print('Accepted')
        try:
            conn = ssl.wrap_socket(ssock,
                certfile='./cert.pem',
                keyfile='./key.pem',
                server_side=True)
            print('Connected')
            handshake(conn)
        except ssl.SSLError as e:
            print('Error:', e)
        finally:
            if conn:
                conn.close()
