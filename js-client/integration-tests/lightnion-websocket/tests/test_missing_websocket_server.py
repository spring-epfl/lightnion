import threading
import unittest
import signal
import logging
import psutil

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.wait import WebDriverWait

from common.endpoint import Endpoint
from .config import *
from .lightion_websocket_test import LightnionWebSocketTest
from .utils import ReceivedMessage, WebSocketStatus, received_messages, sent_messages


class NonExistingWebSocketServerTest(LightnionWebSocketTest):
    """Test cases when the client connects to a non existing websocket server."""

    @classmethod
    def endpoint_cls(cls):
        return Endpoint

    @classmethod
    def setUpClass(cls):
        super().setUpClass(
            HTTP_PORT, WS_PORT + 1
        )  # setup ws server on a different port
        cls.demo_url = f"http://{HOST}:{HTTP_PORT}/{DEMO_PATH}"

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    def test_webpage_get(self):
        """Test that the webpage is available and that the websocket connection does not establishes."""
        self.driver.get(self.demo_url)
        self.assertIn("lightnion websocket redirect echo demo", self.driver.title)

        # wait for a state change
        state = self.wait_for_websocket()
        self.assertEqual(state, 3, "websocket expected to be closed")

        # TODO: verify no direct connection trial


def sigint_handler(signal, frame):
    NonExistingWebSocketServerTest.close()
    raise KeyboardInterrupt


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    signal.signal(signal.SIGINT, sigint_handler)
    unittest.main()
