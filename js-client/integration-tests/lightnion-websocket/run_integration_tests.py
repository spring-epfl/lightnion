
import logging
import signal
import unittest

from tests.test_normal_behavior import NormalBehaviorTest

if __name__ == "__main__":
    def sigint_handler(signal, frame):
        NormalBehaviorTest.close()
        raise KeyboardInterrupt

    logging.basicConfig(level=logging.INFO)
    signal.signal(signal.SIGINT, sigint_handler)

    suite = unittest.TestSuite()
    suite.addTest(NormalBehaviorTest("test_webpage_get"))
    suite.addTest(NormalBehaviorTest("test_echo_message"))
    suite.addTest(NormalBehaviorTest("test_using_redirection"))

    runner = unittest.TextTestRunner()
    runner.run(suite)
