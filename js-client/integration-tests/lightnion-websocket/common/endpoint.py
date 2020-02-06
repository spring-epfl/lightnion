from aiohttp import web
from http.server import HTTPServer, SimpleHTTPRequestHandler
import datetime
import ssl
import asyncio
import aiohttp
import logging
import threading
import logging
import time
import socket
import sys
from .throughput import UploadState

# for throughtput LTCP tests, hardcoded...
NUM_PACKETS = 10000
PACKET_SIZE = 1000

async def http_handler(request):
    name = request.match_info.get("name", "Anonymous")
    text = "Hello, " + name
    return aiohttp.web.Response(text=text)


async def websocket_handler(request):
    """WebSocket Echo Handler for integration testing."""
    ws = aiohttp.web.WebSocketResponse(compress=False)
    await ws.prepare(request)

    peername = request.transport.get_extra_info("peername")
    if peername is not None:
        logging.info(f"peer connected: {peername}")
        request.app.endpoint.ws_connected_peers.add(peername)

    async for msg in ws:

        logging.info(f"received websocket message: {msg}")

        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == "close":
                await ws.close()
            else:
                response = msg.data
                logging.info(f"sending websocket message: {response}")
                await ws.send_str(response)
        elif msg.type == aiohttp.WSMsgType.ERROR:
            logging.info("ws connection closed with exception %s" %
                         ws.exception())

    logging.info("websocket connection closed")
    return ws


async def websocket_echo_handler(request):
    """WebSocket Echo Handler for evaluation."""
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == "close":
                await ws.close()
            else:
                response = msg.data
                await ws.send_str(response)
        elif msg.type == aiohttp.WSMsgType.ERROR:
            logging.info("ws connection closed with exception %s" %
                         ws.exception())

    logging.info("websocket connection closed")
    return ws


async def websocket_time_to_first_message_handler(request):
    """WebSocket Time to first message handler for evaluation."""
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == "close":
                await ws.close()
            else:
                response = msg.data
                # take the timestamp in ms
                current_time_ms = int(datetime.datetime.now(
                    datetime.timezone.utc).timestamp() * 1000)  # unix time
                # send it as a string
                await ws.send_str(f"{current_time_ms}")
        elif msg.type == aiohttp.WSMsgType.ERROR:
            logging.info("ws connection closed with exception %s" %
                         ws.exception())

    logging.info("websocket connection closed")
    return ws


async def websocket_upload_handler(request):
    """WebSocket Upload Handler for evaluation.

    This is used to perform upload throughput tests from the javascript client.
    """

    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    endpoint = request.app.endpoint

    peername = request.transport.get_extra_info("peername")
    if peername not in endpoint.upload_state_by_peer:
        endpoint.upload_state_by_peer[peername] = UploadState()

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.BINARY:
            if not endpoint.upload_state_by_peer[peername].start_time:
                # first packet received, record start time
                endpoint.upload_state_by_peer[peername].start_time = int(
                    datetime.datetime.now().timestamp() * 1000)

            endpoint.upload_state_by_peer[peername].received_bytes += len(
                msg.data)

            if (endpoint.upload_state_by_peer[peername].received_bytes >= endpoint.upload_state_by_peer[peername].expected_bytes):
                end = int(datetime.datetime.now().timestamp() * 1000)
                endpoint.upload_state_by_peer[peername].end_time = datetime.datetime.now(
                )
                logging.info(
                    f"upload test ended for peer {peername}: received {expected_bytes} bytes")

                start = endpoint.upload_state_by_peer[peername].start_time
                await ws.send_json({"start": start, "end": end})

        elif msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == "close":
                await ws.close()
            else:
                # signal message, indicating the expected byte count to receive
                received = msg.json()
                if ("upload_bytes" in received):
                    expected_bytes = received["upload_bytes"]
                    endpoint.upload_state_by_peer[peername].expected_bytes = expected_bytes
                    logging.info(
                        f"peer {peername} started upload test for {expected_bytes} bytes")

        elif msg.type == aiohttp.WSMsgType.ERROR:
            logging.info("ws connection closed with exception %s" %
                         ws.exception())

    logging.info("websocket connection closed")
    return ws


async def websocket_download_handler(request):
    """WebSocket Upload Handler for evaluation.

    This is used to perform upload throughput tests from the javascript client.
    """

    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    endpoint = request.app.endpoint

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == "close":
                await ws.close()
            else:
                # signal message, indicating the byte count to send, and to start sending
                received = msg.json()
                if ("packetCount" in received and "packetSize" in received):
                    packet_count = received["packetCount"]
                    packet_size = received["packetSize"]

                    # craft packet
                    pkt_src = [i % 256 for i in range(packet_size)]
                    pkt = bytearray(pkt_src)

                    # wait some time
                    await asyncio.sleep(0.5)

                    for i in range(packet_count):
                        await ws.send_bytes(pkt)

        elif msg.type == aiohttp.WSMsgType.ERROR:
            logging.info("ws connection closed with exception %s" %
                         ws.exception())

    logging.info("websocket connection closed")
    return ws


class Endpoint:
    """A HTTP/WebSocket endpoint used to test lightnion javscript client."""

    def __init__(
        self, host: str = "localhost", http_port: int = 8080, ws_port: int = None
    ):
        """Construct a test endpoint.

        The test endpoint hosts a HTTP and WebSocket server, both can be served on the same port or different.

        Args:
            host (str): the host of the webserver (default: 'localhost')
            http_port (int): the port of the http server
            ws_port (int): the port of the webserver, if None, the same as the http_port
        """

        self.host = host
        self.http_port = http_port
        self.ws_port = ws_port

        # the set of peers that connected to the websocket
        self.ws_connected_peers = set()

        # upload state for peers having started a throughput evaluation
        self.upload_state_by_peer = {}

        # setup http server
        self.http_app = aiohttp.web.Application()
        self.http_app.endpoint = self
        self.http_app.add_routes(
            [
                # serve static files in public/ directory under route '/public'
                web.static("/public", "./public/", show_index=True)
            ]
        )

        if ws_port is None or ws_port == http_port:
            self.http_app.add_routes(
                [
                    # serve websocket under route '/ws',
                    # for integration testing
                    web.get("/ws", websocket_handler),
                    web.get("/ws-echo", websocket_echo_handler),
                    web.get("/ws-upload", websocket_upload_handler),
                    web.get("/ws-download", websocket_download_handler),
                    web.get("/ws-ttfm", websocket_time_to_first_message_handler)
                ]
            )
            self.ws_app = None
            self.ws_runner = None
        else:
            # setup a different websocket server
            self.ws_app = aiohttp.web.Application()
            self.ws_app.endpoint = self
            self.ws_app.add_routes(
                [
                    # serve websocke tunder route '/ws',
                    # for integration testing
                    web.get("/ws", websocket_handler),
                    web.get("/ws-echo", websocket_echo_handler),
                    web.get("/ws-upload", websocket_upload_handler),
                    web.get("/ws-download", websocket_download_handler),
                    web.get("/ws-ttfm", websocket_time_to_first_message_handler)
                ]
            )
            self.ws_runner = aiohttp.web.AppRunner(self.ws_app)

        self.http_runner = aiohttp.web.AppRunner(self.http_app)

    def start(self):
        # set event-loop if not defined (maybe running in a thread)
        try:
            loop = asyncio.get_event_loop()
        except:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        loop.run_until_complete(self.http_runner.setup())
        http_site = aiohttp.web.TCPSite(
            self.http_runner, self.host, self.http_port)
        loop.run_until_complete(http_site.start())
        logging.info("http endpoint: started")
        logging.info(f"http endpoint: running on {self.host}:{self.http_port}")

        if self.ws_runner:
            loop.run_until_complete(self.ws_runner.setup())
            ws_site = aiohttp.web.TCPSite(
                self.ws_runner, self.host, self.ws_port)
            loop.run_until_complete(ws_site.start())
            logging.info("ws endpoint: started")
            logging.info(f"ws endpoint: running on {self.host}:{self.ws_port}")

        # TCP
        # self.tcp_echo_thread = threading.Thread(target = self.tcp_echo, daemon=True)
        # self.tcp_echo_thread.start()

        async def tcp_echo(reader, writer):
            request = None
            while True:
                request = await reader.read(255)
                writer.write(request)
                await writer.drain()
            writer.close()

        async def tcp_ttfm(reader, writer):
            import math
            request = None
            while True:
                request = await reader.read(255)
                current_time_ms = int(datetime.datetime.now(
                    datetime.timezone.utc).timestamp() * 1000)  # unix time
                writer.write(current_time_ms.to_bytes(32, 'little'))
                await writer.drain()
            writer.close()

        async def tcp_dl(reader, writer):
            import math
            request = None
            while True:
                request = await reader.read(1000)
                # craft packet
                pkt_src = [i % 256 for i in range(PACKET_SIZE)]
                pkt = bytearray(pkt_src)

                # wait some time
                await asyncio.sleep(0.5)

                for i in range(NUM_PACKETS):
                    writer.write(pkt)
                    await writer.drain()
            writer.close()

        async def tcp_ul(reader, writer):
            import math
            request = None
            start_time = None
            end_time = None
            recv_bytes = 0
            while True:
                request = await reader.read(1000)
                # print(request)
                recv_bytes += len(request)
                if start_time is None:
                    start_time = int(datetime.datetime.now().timestamp() * 1000)
                if end_time is None and recv_bytes == NUM_PACKETS * PACKET_SIZE:
                    end_time = int(datetime.datetime.now().timestamp() * 1000)

                    writer.write(start_time.to_bytes(32, 'little'))
                    writer.write(end_time.to_bytes(32, 'little'))
                    await writer.drain()
                
            writer.close()

        loop = asyncio.get_event_loop()
        loop.create_task(asyncio.start_server(tcp_echo, 'localhost', 8082))
        loop.create_task(asyncio.start_server(tcp_ttfm, 'localhost', 8083))
        loop.create_task(asyncio.start_server(tcp_dl, 'localhost', 8084))
        loop.create_task(asyncio.start_server(tcp_ul, 'localhost', 8085))

        loop.run_forever()

    def stop(self):
        self.socket.close()
        os._exit(0)
