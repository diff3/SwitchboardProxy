import unittest
from unittest.mock import patch

from proxy.telnet.server import _is_authenticated


class _FakeIO:
    def __init__(self, script):
        self._script = list(script)
        self.writes = []

    def read_byte(self):
        if not self._script:
            return None
        return self._script.pop(0)

    def write(self, data: bytes):
        self.writes.append(data)


class TelnetAuthTest(unittest.TestCase):
    def test_auth_disabled_allows_access(self):
        io = _FakeIO([])
        self.assertTrue(_is_authenticated(io, ("127.0.0.1", 1), {"enabled": False}))

    def test_auth_accepts_matching_username_and_password(self):
        io = _FakeIO(
            [
                b"a", b"d", b"m", b"i", b"n", b"\r",
                b"s", b"e", b"c", b"r", b"e", b"t", b"\r",
            ]
        )
        with patch("proxy.telnet.server.LOGGER.info"):
            ok = _is_authenticated(
                io,
                ("127.0.0.1", 1),
                {
                    "enabled": True,
                    "username": "admin",
                    "password": "secret",
                    "max_attempts": 3,
                },
            )
        self.assertTrue(ok)

    def test_auth_rejects_after_max_attempts(self):
        io = _FakeIO(
            [
                b"x", b"\r", b"y", b"\r",
                b"x", b"\r", b"y", b"\r",
            ]
        )
        with patch("proxy.telnet.server.LOGGER.warning"):
            ok = _is_authenticated(
                io,
                ("127.0.0.1", 1),
                {
                    "enabled": True,
                    "username": "admin",
                    "password": "secret",
                    "max_attempts": 2,
                },
            )
        self.assertFalse(ok)
        rendered = b"".join(io.writes)
        self.assertIn(b"Invalid credentials.", rendered)
        self.assertIn(b"Too many failed login attempts.", rendered)


if __name__ == "__main__":
    unittest.main()
