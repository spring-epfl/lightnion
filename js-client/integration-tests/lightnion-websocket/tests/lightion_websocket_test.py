import logging
import threading
import unittest
import subprocess
import sys
import time
import os
import re
import psutil

from signal import SIGKILL
from abc import ABC, abstractclassmethod
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.wait import WebDriverWait

from common.endpoint import Endpoint
from .utils import ReceivedMessage, WebSocketStatus, received_messages, sent_messages
from config import *

"""
Integration tests for lightnion javascript websocket redirection.
"""


class LightnionWebSocketTest(ABC, unittest.TestCase):
    """Abstract base class for tests of lightnion's websocket redirection.

    Instanciates:
        - an endpoint (http+websocket)
        - a Tor test network (chutney)
        - a ligthnion proxy
    """
    tor_pids = []

    @abstractclassmethod
    def endpoint_cls(self):
        """Returns the class of the endpoint."""
        raise NotImplementedError

    @classmethod
    def setUpClass(cls, http_port: int = HTTP_PORT, ws_port: int = WS_PORT, profile = None):
        
        # instanciate endpoint server
        cls.endpoint = cls.endpoint_cls()(HOST, http_port, ws_port)
        cls.endpoint_thread = threading.Thread(
            target=cls.endpoint.start, name="endpoint-thread", daemon=True
        )

        if not os.path.exists(LOG_DIRECTORY):
            os.mkdir(LOG_DIRECTORY)
        cls.chutney_stdout = os.open("logs/chutney_stdout.log", os.O_WRONLY | os.O_CREAT)
        cls.chutney_stderr = os.open("logs/chutney_stderr.log", os.O_WRONLY | os.O_CREAT)
        cls.lightnion_stdout = os.open("logs/lightnion_stdout.log", os.O_WRONLY | os.O_CREAT)
        cls.lightnion_stderr = os.open("logs/lightnion_stderrr.log", os.O_WRONLY | os.O_CREAT)

        # start external programs
        # TODO
        try:
            cls.start_chutney()
            time.sleep(30)
            cls.start_lightnion()
            cls.start_endpoint()
            time.sleep(30)
        except RuntimeError:
            logging.error("could not set up test infrastructure")
            cls.close()
            sys.exit(1)

        # instanciate driver
        options = Options()
        options.headless = True
        if profile is None:
            cls.driver = webdriver.Firefox(options=options)
        else:
            cls.driver = webdriver.Firefox(options=options, firefox_profile=profile)
        cls.driver.implicitly_wait(BROWSER_WAIT)

    @classmethod
    def close(cls):
        cls.stop_endpoint()
        cls.stop_lightnion()
        cls.stop_chutney()
        try:
            cls.driver.close()
        except AttributeError:
            pass

    @classmethod
    def tearDownClass(cls):
        cls.close()

    @classmethod
    def start_chutney(cls):
        """Start test Tor network."""
        logging.info("starting chutney")
        p = subprocess.run([CHUTNEY, "configure", CHUTNEY_NET], stdout=cls.chutney_stdout, stderr=cls.chutney_stderr)
        if p.returncode != 0:
            logging.error("could not configure chutney test network")
            raise RuntimeError

        p = subprocess.run([CHUTNEY, "start", CHUTNEY_NET], stdout=cls.chutney_stdout, stderr=cls.chutney_stderr)
        if p.returncode != 0:
            logging.error("could not start chutney test network")
            raise RuntimeError
        time.sleep(2)

        try:
            output = subprocess.check_output([CHUTNEY, "status", CHUTNEY_NET])
            # find pids of tor test nodes from output of status command
            pids_str = re.findall(r"PID\s+\d+", str(output))
            cls.tor_pids = [int(s[4:]) for s in pids_str]

            for line in str(output).split("\\n"):
                logging.info(f"\t{line}")
        except subprocess.CalledProcessError:
            logging.error("could not status chutney test network")
            raise RuntimeError

    @classmethod
    def stop_chutney(cls):
        """Stop test Tor network."""
        logging.info("stopping chutney")
        p = subprocess.run([CHUTNEY, "stop", CHUTNEY_NET], stdout=cls.chutney_stdout, stderr=cls.chutney_stderr)
        if p.returncode != 0:
            logging.error("could not stop chutney test network")

    @classmethod
    def start_lightnion(cls):
        """Start lightnion proxy."""
        logging.info("starting lightnion")
        cwd = Path.cwd() / Path(LIGHTNION_CWD)
        cls.__lightnion_process = subprocess.Popen(LIGHTNION.split(' '), cwd=cwd, shell=False, stdout=cls.lightnion_stdout, stderr=cls.lightnion_stderr)

    @classmethod
    def stop_lightnion(cls):
        """Stop lightnion proxy."""
        logging.info("stopping lightnion")
        try:
            cls.__lightnion_process.kill()
        except AttributeError:
            # lightnion process was not initialized
            pass

    @classmethod
    def start_endpoint(cls):
        """Start http/websocket endpoint."""
        logging.info("starting endpoint")
        cls.endpoint_thread.start()

    @classmethod
    def stop_endpoint(cls):
        """Start http/websocket endpoint"""
        logging.info("stopping endpoint")
        # no need to kill thread since daemon
        pass

    def driver_connections(self):
        """Return the set of remote ports the driver is connected to."""
        browser_connections = psutil.Process(
            self.driver.service.process.pid
        ).connections()
        browser_rports = [c.raddr.port for c in browser_connections if c.raddr]
        return browser_rports

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def wait_for_websocket(self):
        wait = WebDriverWait(self.driver, WEBSOCKET_CONNECTING_WAIT)
        state = wait.until(WebSocketStatus("window.ws"))

        if not state:
            # could not connect, still in CONNECTING state
            self.fail(
                f"websocket could not connect, still in CONNECTING state after {WEBSOCKET_CONNECTING_WAIT} seconds"
            )
        return state

