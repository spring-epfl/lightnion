import sys
import time
import threading
import socket
import random
import ssl
import logging

class server(threading.Thread):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn

    def run(self):
        self.conn.settimeout(None)
        logging.info('New connection')
        try:
            while True:
                data = random.getrandbits(8 * 512).to_bytes(512, sys.byteorder)
                self.conn.send(data)
                #time.sleep(0.1)

        except Exception as e:
            pass

        finally:
            logging.info('Close connection')
            self.conn.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    threads = []
    try:
        sock = socket.socket()
        sock.bind(('0.0.0.0', 12005))
        sock.listen()

        logging.info('Listening at: {}'.format(sock.getsockname()))
        while True:
            conn, addr = sock.accept()
            try:
                thread = server(conn)
                threads.append(thread)
                thread.start()
            except BaseException as e:
                if conn:
                    conn.close()
    finally:
        sock.close()
        for thread in threads:
            thread.join() 
