"""
Cell handling classes.
"""

import time
import secrets
import socket

from enum import IntEnum

ENDIANNESS = 'big'
PAYLOAD_SIZE_MAX = 509

class Command(IntEnum):
    """Cell type."""
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    VERSIONS = 7
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11
    PADDING_NEGOTIAT = 12
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132

    def is_variable_length(self):
        """If the cell type indicate a cell of variable length."""
        return self.value == 7 or self.value > 127


    @classmethod
    def from_bytes(cls, raw):
        """Cell type from command byte."""
        return cls(int.from_bytes(raw, ENDIANNESS))


    def to_bytes(self):
        """Byte representation."""
        return (self.value).to_bytes(1, ENDIANNESS)


class DestroyReason(IntEnum):
    NONE = 0
    PROTOCOL = 1
    INTERNAL = 2
    REQUESTED = 3
    HIBERNATING = 4
    RESOURCELIMIT = 5
    CONNECTFAILED = 6
    OR_IDENTITY = 7
    OR_CONN_CLOSED = 8
    FINISHED = 9
    TIMEOUT = 10
    DESTROYED = 11
    NOSUCHSERVICE = 12


    @classmethod
    def from_bytes(cls, raw):
        """Cell type from command byte."""
        return cls(int.from_bytes(raw, ENDIANNESS))


    def to_bytes(self):
        """Byte representation."""
        return (self.value).to_bytes(1, ENDIANNESS)


class Cell:
    """Representation of a non-version, non-netinfo Tor cell."""

    SIZE = 514

    CIRCUIT_ID = 0
    CIRCUIT_ID_SIZE = 4
    CIRCUIT_ID_END = 4
    COMMAND = 4
    LENGTH = 5
    LENGTH_SIZE = 2
    LENGTH_END = 7
    PAYLOAD_BEGIN = 7


    @classmethod
    def set_circuit_id(cls, cell_raw, circuit_id):
        circuit_id_b = circuit_id.to_bytes(cls.CIRCUIT_ID_SIZE, ENDIANNESS)
        cell = cell_raw[cls.CIRCUIT_ID_END:]
        return circuit_id_b + cell


    @classmethod
    def circuit_id(cls, cell_raw):
        return int.from_bytes(cell_raw[cls.CIRCUIT_ID:cls.CIRCUIT_ID_END], ENDIANNESS)


    @classmethod
    def command(cls, cell_raw):
        return Command(cell_raw[cls.COMMAND])


    @classmethod
    def length(cls, cell_raw):
        return int.from_bytes(cell_raw[cls.LENGTH:cls.LENGTH_END], ENDIANNESS)


    @classmethod
    def raw_from_buffer(cls, buffer):
        buf_len = len(buffer)
        # len(cell_id + command + payload_size) == 7
        header_len = 7
        if buf_len < header_len:
            return None, buffer

        cmd = cls.command(buffer)

        if cmd.is_variable_length():
            length = cls.length(buffer) + header_len
        else:
            length = cls.SIZE

        if buf_len < length:
            return None, buffer

        return buffer[:length], buffer[length:]

    @classmethod
    def pad(cls, cell_raw):
        cell_len = len(cell_raw)
        padding_size = cls.SIZE - cell_len
        if padding_size > 0:
            padding = secrets.token_bytes(padding_size)
        else:
            padding = b''

        return cell_raw + padding


class CellVersion:
    """Representation of a versions cell."""

    CMD = Command.VERSIONS.to_bytes()
    LENGTH = 3
    LENGTH_SIZE = 2
    LENGTH_END = 5
    VERSION_SIZE = 2


    def __init__(self, versions):
        self.versions = versions


    def payload_size(self):
        return self.VERSION_SIZE * len(self.versions)


    @classmethod
    def length(cls, cell_raw):
        return int.from_bytes(cell_raw[cls.LENGTH:cls.LENGTH_END], ENDIANNESS)


    @classmethod
    def from_bytes(cls, cell_raw):
        versions = list()
        for i in range(5, len(cell_raw), 2):
            version = int.from_bytes(cell_raw[i:i+2], ENDIANNESS)
            versions.append(version)

        return cls(versions)


    def to_bytes(self):
        size_b = self.payload_size().to_bytes(self.LENGTH_SIZE, ENDIANNESS)
        cell_id = b'\x00\x00'

        cell = cell_id + self.CMD + size_b

        for version in self.versions:
            cell += version.to_bytes(self.VERSION_SIZE, ENDIANNESS)

        return cell


class CellNetInfo:
    """Representation of a netinfo cell."""

    SIZE = 514
    CMD = Command.NETINFO.to_bytes()


    @classmethod
    def to_bytes(cls, host):
        if host == 'localhost':
            # Binary representation of 127.0.0.1
            addr = b'\x7f\x00\x00\x01'
        else:
            addr = socket.inet_aton(host)

        tstmp = int(time.time()).to_bytes(4, ENDIANNESS)

        addr_len = len(addr)

        if addr_len == 4:
            addr_t = b'\x04'
        else:
            addr_t = b'\x06'

        addr_len_b = addr_len.to_bytes(1, ENDIANNESS)

        cell_len = 11 + addr_len
        cell_id = b'\x00\x00\x00\x00'

        cell = cell_id + cls.CMD + tstmp + addr_t + addr_len_b + addr

        # padding with \x00
        cell += bytearray(cls.SIZE - cell_len)

        return cell


class CellDestroy:
    SIZE = 514
    CMD = Command.DESTROY

    def __init__(self, circuit_id, reason):
        self.circuit_id = circuit_id
        self.reason = reason

    def to_bytes(self):
        circuit_id_b = self.circuit_id.to_bytes(4, ENDIANNESS)
        cmd = self.CMD.to_bytes()
        reason = self.reason.to_bytes()
        cell_len = 6
        padding = bytearray(self.SIZE - cell_len)
        return circuit_id_b + cmd + reason + padding
