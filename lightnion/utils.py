import lightnion as lnn


class InvalidCellHeaderException(Exception):
    def __init__(self, header):
        super().__init__('Invalid cell header: {}'.format(header))

class InvalidCellLengthException(Exception):
    pass


def cell_slice(payload):
    """Retrieve the next cell from the payload and truncate that one.
    :param payload: bytearray
    """
    cell_header = lnn.cell.header(payload)
    if len(payload) < cell_header.width: # (payload too small, need data)
        return None, payload

    if not cell_header.valid:
        raise InvalidCellHeaderException(cell_header.raw)

    length = cell_header.width + lnn.constants.payload_len
    if not cell_header.cmd.is_fixed:
        cell_header = lnn.cell.header_variable(payload)
        if len(payload) < cell_header.width: # (payload too small, need data)
            return None, payload

        if not cell_header.valid:
            raise InvalidCellHeaderException(cell_header.raw)

        length = cell_header.width + cell_header.length

    if length > lnn.constants.max_payload_len:
        raise InvalidCellLengthException()

    if len(payload) < length:
        return None, payload

    cell = payload[:length]

    return cell, payload[length:]

