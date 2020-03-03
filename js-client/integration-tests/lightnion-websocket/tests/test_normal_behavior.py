import threading
import unittest
import signal
import logging
import psutil
import time

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.wait import WebDriverWait

from common.endpoint import Endpoint
from config import *
from .lightion_websocket_test import LightnionWebSocketTest
from .utils import ReceivedMessage, WebSocketStatus, received_messages, sent_messages

class NormalBehaviorTest(LightnionWebSocketTest):
    """Test cases for normal operations."""

    @classmethod
    def endpoint_cls(cls):
        return Endpoint

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.demo_url = f"http://{HOST}:{HTTP_PORT}/{DEMO_PATH}"
        cls.ws_url = f"ws://{HOST}:{WS_PORT}/ws"

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    def wait_for_websocket(self):
        wait = WebDriverWait(self.driver, WEBSOCKET_CONNECTING_WAIT)
        state = wait.until(WebSocketStatus("window.ws"))

        if not state:
            # could not connect, still in CONNECTING state
            self.fail(
                f"websocket could not connect, still in CONNECTING state after {WEBSOCKET_CONNECTING_WAIT} seconds"
            )
        return state

    def expect_message(self, expected_message):
        """Wait for a message to be received by the websocket, fail if not received."""
        wait = WebDriverWait(self.driver, WEBSOCKET_RESPONSE_WAIT)
        received = wait.until(ReceivedMessage(expected_message))

        self.assertTrue(
            received,
            f"did not receive expeceted message from server: {expected_message}",
        )

    def send(self, msg: str) -> None:
        """Send a message via the user interface."""
        self.driver.find_element_by_id("echo-input").clear()
        self.driver.find_element_by_id("echo-input").send_keys(msg)
        self.driver.find_element_by_id("echo-button").click()

    @property
    def sent_messages(self):
        """Return the list of client messages."""
        return sent_messages(self.driver)

    @property
    def received_messages(self):
        return received_messages(self.driver)

    def test_webpage_get(self):
        """Test that the webpage is available and that the websocket connection establishes to the correct endpoint."""
        self.driver.get(self.demo_url)
        self.assertIn("lightnion websocket redirect echo demo", self.driver.title)

        # wait for a state change
        state = self.wait_for_websocket()
        self.assertEqual(state, 1, "could not connect to websocket")

        # get url of the websocket endpoint
        ws_url = self.driver.execute_script("return window.ws.url;")
        self.assertEqual(
            ws_url,
            self.ws_url,
            f"websocket is not connected to the correct endpoint: expected {self.ws_url}, got: {ws_url}",
        )

    def test_echo_message(self):
        """Test that a message sent is echoed back,
        hence it is really sent and well received."""
        self.driver.get(self.demo_url)

        # wait for a state change
        state = self.wait_for_websocket()
        self.assertEqual(state, 1, "could not connect to websocket")

        # send message and expect response
        time.sleep(5)
        message = "test message"
        self.send(message)
        self.expect_message(message)

    def test_using_redirection(self):
        """Test that the websocket connection is redirected.
        
        For that, list the ESTABLISHED TCP connections of the browser (webdriver) process,
        and check that remote addresses do not match with the websocket server's.
        """
        self.driver.get(self.demo_url)

        # wait for a state change
        state = self.wait_for_websocket()
        self.assertEqual(state, 1, "could not connect to websocket")

        # list remote ports connected to the browser
        for c in self.driver_connections():
            self.assertTrue(
                c != WS_PORT,
                "browser is connected to the websocket directly, not redirected",
            )

        # check that all connections to the websocket are from Tor nodes

        tor_ports = set()  # ports used by the tor processes
        for pid in self.tor_pids:
            p = psutil.Process(pid)
            for c in p.connections():
                if c.laddr:
                    tor_ports.add(c.laddr.port)

        for peer in self.endpoint.ws_connected_peers:
            port = peer[1]
            self.assertTrue(
                port in tor_ports,
                "found a peer connected to the websocket that is not a tor process",
            )


def sigint_handler(signal, frame):
    NonExistingWebSocketServerTest.close()
    raise KeyboardInterrupt


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    signal.signal(signal.SIGINT, sigint_handler)
    unittest.main()
