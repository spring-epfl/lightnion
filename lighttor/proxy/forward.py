import threading
import flask

class clerk(threading.Thread):
    def __init__(self):
        super().__init__()
        self.lock = threading.RLock()
        self.dead = False
        self.tick = 0

    def __enter__(self):
        with self.lock:
            self.start()
        return self

    def __exit__(self, *kargs):
        with self.lock:
            self.dead = True
        self.join()

    def main(self):
        with self.lock:
            self.tick += 1

    def run(self):
        while not self.dead:
            try:
                self.main()
            except BaseException as e:
                print(e)

app = flask.Flask(__name__)

@app.route('/')
def index():
    with app.clerk.lock:
        return "Hello, World! {}".format(app.clerk.tick)

def main(port=4990):
    with clerk() as app.clerk:
        app.run(port=4990, debug=True)
