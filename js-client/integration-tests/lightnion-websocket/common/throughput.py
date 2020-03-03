"""
Throughput evaluation helpers.
"""
from datetime import datetime

class UploadState:
    def __init__(self, start_time: datetime = None, end_time: datetime = None, expected_bytes: int = 0, received_bytes: int = 0):
        self.start_time = start_time
        self.end_time = end_time
        self.expected_bytes = expected_bytes
        self.received_bytes = received_bytes

