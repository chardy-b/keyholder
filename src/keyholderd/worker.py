from __future__ import annotations

import json
import os
import select
import signal
import sys
import time
from typing import Any, Callable

# Shared launcher for short-lived, killable credential workers (Linux only).


def kill_group(pid: int) -> None:
    for kill in (lambda: os.killpg(pid, signal.SIGKILL), lambda: os.kill(pid, signal.SIGKILL)):
        try:
            kill()
        except (ProcessLookupError, PermissionError):
            pass


def _child(write_fd: int, payload_fn: Callable[[], dict[str, Any]], timeout: float) -> None:
    status = 70
    try:
        try:
            os.setpgid(0, 0)  # own group (not a new session) so the parent can kill descendants with us
            signal.alarm(int(timeout) + 5)  # self-limit even if the parent vanishes
            null = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(null, fd)
            os.closerange(3, write_fd)
            os.closerange(write_fd + 1, 1 << 20)
            os.environ.pop("RUST_LOG", None)
            payload = payload_fn()
        except BaseException:  # noqa: BLE001 - only a fixed code survives
            payload = {"ok": False, "code": "internal_error"}
        data = json.dumps(payload).encode()
        while data:
            data = data[os.write(write_fd, data):]
        status = 0
    finally:
        os._exit(status)


def run_forked(payload_fn: Callable[[], dict[str, Any]], timeout: float, max_reply_bytes: int) -> tuple[str, bytes]:
    """Run ``payload_fn`` in a forked child with no inherited descriptors or output.

    Returns ``("ok", reply)``, ``("timeout", b"")`` or ``("overflow", b"")``. The
    child's process group is always killed and reaped before returning.
    """
    read_fd, write_fd = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        _child(write_fd, payload_fn, timeout)
    os.close(write_fd)
    try:
        os.setpgid(pid, pid)
    except OSError:
        pass  # the child already did it
    deadline = time.monotonic() + timeout
    buf = bytearray()
    outcome = "ok"
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = "timeout"
                break
            if not select.select([read_fd], [], [], remaining)[0]:
                continue
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > max_reply_bytes:
                outcome = "overflow"
                break
    finally:
        os.close(read_fd)
        kill_group(pid)  # also sweeps any descendants left behind
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    return outcome, bytes(buf) if outcome == "ok" else b""
