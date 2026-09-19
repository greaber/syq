"""Private framed control messages, separate from callback byte streams."""

from __future__ import annotations

from array import array
import json
import os
import socket
import struct

from .errors import SyqProtocolError

VERSION = 1
_MAX_FRAME = 65536
_MARKER = b"S"


def _exact(channel: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = channel.recv(size - len(result))
        if not chunk:
            raise SyqProtocolError("stream mapping control connection ended mid-message")
        result.extend(chunk)
    return bytes(result)


def receive(channel: socket.socket) -> tuple[dict, list[int]]:
    marker, ancillary, flags, _ = channel.recvmsg(1, socket.CMSG_SPACE(3 * array("i").itemsize))
    descriptors: list[int] = []
    try:
        malformed = bool(flags & socket.MSG_CTRUNC)
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                malformed = True
                continue
            values = array("i")
            if len(data) % values.itemsize:
                malformed = True
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
        for descriptor in descriptors:
            os.set_inheritable(descriptor, False)
        if marker != _MARKER or malformed:
            raise SyqProtocolError("invalid stream mapping control message")
        size = struct.unpack("!I", _exact(channel, 4))[0]
        if not 0 < size <= _MAX_FRAME:
            raise SyqProtocolError("invalid stream mapping control frame length")
        try:
            record = json.loads(_exact(channel, size))
        except (ValueError, UnicodeError) as error:
            raise SyqProtocolError("invalid stream mapping control JSON") from error
        if not isinstance(record, dict):
            raise SyqProtocolError("stream mapping control message must be an object")
        return record, descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def send(channel: socket.socket, record: dict) -> None:
    payload = json.dumps(record, separators=(",", ":"), allow_nan=False).encode()
    if not 0 < len(payload) <= _MAX_FRAME:
        raise SyqProtocolError("invalid stream mapping control frame length")
    channel.sendall(_MARKER + struct.pack("!I", len(payload)) + payload)
