from __future__ import annotations

import pwd
import socket
import struct

SO_PEERCRED = 17


class PeerCredentialError(RuntimeError):
    """Raised when peer credentials cannot be obtained."""


def get_peercred(conn: socket.socket) -> tuple[int, int, int]:
    if conn.family != socket.AF_UNIX:
        raise PeerCredentialError("SO_PEERCRED is only available for Unix domain sockets")
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
    except OSError as exc:
        raise PeerCredentialError(f"failed to read peer credentials: {exc}") from exc
    return pid, uid, gid


def uid_to_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError as exc:
        raise PeerCredentialError(f"no username for uid {uid}") from exc
