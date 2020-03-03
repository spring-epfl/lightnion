"""Some utilities for integration tests."""


def messages_with_class_name(driver, cname):
    messages = driver.find_element_by_id(
        "messages").find_elements_by_class_name(cname)
    return [m.text for m in messages]


def sent_messages(driver):
    return messages_with_class_name(driver, "client")


def received_messages(driver):
    return messages_with_class_name(driver, "server")


class WebSocketStatus:
    """An expectation for checking that a websocket is in a OPEN, CLOSING or CLOSED state.

    Used to wait on a websocket to be connected (or failed).

    see https://selenium-python.OPENreadthedocs.io/waits.html
    """

    def __init__(self, websocket_name):
        self.ws_name = websocket_name

    def __call__(self, driver):
        try:
            state = driver.execute_script(
                f"return {self.ws_name}.readyState;")
            if state >= 1:
                return state
            else:
                return False
        except:
            return False

class ReceivedMessage:
    """An expectation for checking that a websocket received a specific message."""

    def __init__(self, expected_message):
        self.msg = expected_message

    def __call__(self, driver):
        return self.msg in received_messages(driver)
