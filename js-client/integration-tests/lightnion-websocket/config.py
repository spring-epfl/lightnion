HOST = "localhost"
HTTP_PORT = 8080
WS_PORT = 8081
TCP_PORT = 8082
DEMO_PATH = "public/lws-echo-test.html"
EVALUATION_PATH = "public/evaluation/evaluation.html"

WEBSOCKET_CONNECTING_WAIT = 5  # time to wait for the websocket to connect
WEBSOCKET_RESPONSE_WAIT = 2  # time to wait for the reception of a message
BROWSER_WAIT = 5  # time to wait for elements in the browser

CHUTNEY = "./infra/chutney/chutney"
CHUTNEY_NET = "./infra/chutney/networks/basic"

LIGHTNION_CWD = "./infra/lightnion"
LIGHTNION = "./venv/bin/python -m lightnion.proxy -s 127.0.0.1:5001 -d 7001 -c 8001 -vvv"

LOG_DIRECTORY = "./logs"

EVALUATION_WAIT = 1000
EVALUATION_OUT_DIRECTORY = "./results"
