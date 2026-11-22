"""Platform compatibility helpers for sandboxed and restricted runtime environments."""

from __future__ import annotations

import sys


class _DummyLoopbackSocket:
    """Mock socket used on Windows when loopback networking is blocked by sandbox policy."""

    def fileno(self) -> int:
        return -1

    def setblocking(self, flag: bool) -> None:
        pass

    def send(self, data: bytes) -> int:
        return len(data)

    def recv(self, n: int = 4096) -> bytes:
        return b""

    def close(self) -> None:
        pass


def _is_loopback_blocked() -> bool:
    """Check if loopback socket connection is blocked (e.g., Windows sandbox)."""
    import socket

    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test_sock.bind(("127.0.0.1", 0))
        port = test_sock.getsockname()[1]
        test_sock.listen(1)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(0.05)
        try:
            client.connect(("127.0.0.1", port))
            return False
        finally:
            client.close()
    except OSError:
        return True
    finally:
        test_sock.close()


def ensure_sandbox_compatibility() -> None:
    """Ensure asyncio and socketpair work on Windows even in network-restricted sandboxes."""
    if sys.platform != "win32":
        return

    if not _is_loopback_blocked():
        return

    import asyncio.proactor_events as pe
    import socket

    def _safe_make_self_pipe(self: pe.BaseProactorEventLoop) -> None:
        self._ssock = _DummyLoopbackSocket()  # type: ignore[assignment]
        self._csock = _DummyLoopbackSocket()  # type: ignore[assignment]
        self._internal_fds += 1

    pe.BaseProactorEventLoop._make_self_pipe = _safe_make_self_pipe  # type: ignore[method-assign]
    pe.BaseProactorEventLoop._loop_self_reading = lambda self, f=None: None  # type: ignore[method-assign]
    pe.BaseProactorEventLoop._write_to_self = lambda self: None  # type: ignore[method-assign]

    def _safe_socketpair(
        family: int = socket.AF_INET,
        type_: int = socket.SOCK_STREAM,
        proto: int = 0,
    ) -> tuple[_DummyLoopbackSocket, _DummyLoopbackSocket]:
        return _DummyLoopbackSocket(), _DummyLoopbackSocket()

    socket.socketpair = _safe_socketpair  # type: ignore[assignment]
