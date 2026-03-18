# telnet/server.py

import socket
import threading

from proxy.telnet.transport import TelnetIO
from proxy.telnet.editor import LineEditor   # 👈 TELNET-editor
from proxy.cli.repl import run_repl
from shared.Logger import Logger

LOGGER = Logger


def _read_prompt(io, prompt: bytes, *, secret: bool = False) -> str | None:
    io.write(prompt)
    buffer = []

    while True:
        ch = io.read_byte()
        if ch is None:
            return None

        if ch in (b"\r", b"\n"):
            io.write(b"\r\n")
            return "".join(buffer)

        if ch in (b"\x7f", b"\b"):
            if buffer:
                buffer.pop()
                if not secret:
                    io.write(b"\b \b")
            continue

        try:
            text = ch.decode()
        except Exception:
            continue

        if text.isprintable():
            buffer.append(text)
            if not secret:
                io.write(ch)


def _is_authenticated(io, addr, auth_cfg: dict | None) -> bool:
    auth_cfg = auth_cfg if isinstance(auth_cfg, dict) else {}
    if not bool(auth_cfg.get("enabled", False)):
        return True

    expected_user = str(auth_cfg.get("username", "") or "")
    expected_password = str(auth_cfg.get("password", "") or "")
    max_attempts = int(auth_cfg.get("max_attempts", 3) or 3)

    for attempt in range(max_attempts):
        username = _read_prompt(io, b"Username: ")
        if username is None:
            return False

        password = _read_prompt(io, b"Password: ", secret=True)
        if password is None:
            return False

        if username == expected_user and password == expected_password:
            LOGGER.info("telnet auth ok %s", addr)
            io.write(b"\r\n")
            return True

        LOGGER.warning("telnet auth failed %s attempt=%s", addr, attempt + 1)
        io.write(b"Invalid credentials.\r\n")

    io.write(b"Too many failed login attempts.\r\n")
    return False


def run_telnet_server(global_state, host="127.0.0.1", port=1337, auth_cfg=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    server.settimeout(1.0)  # allow shutdown polling

    LOGGER.info("telnet listening %s:%s", host, port)

    while not global_state.shutdown:
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        threading.Thread(
            target=_handle_client,
            args=(client, addr, global_state, auth_cfg),
            daemon=True,
        ).start()

    try:
        server.close()
    except OSError:
        pass


def _handle_client(sock, addr, global_state, auth_cfg=None):
    io = TelnetIO(sock)

    try:
        # Telnet negotiation (IAC, ECHO, SGA, no LINEMODE)
        io.negotiate()

        if not _is_authenticated(io, addr, auth_cfg):
            return

        io.write(b"Entropy control socket (raw TCP)\r\n")
        io.write(b"Type 'help' for commands.\r\n\r\n")

        # 🔑 Skapa TELNET-editor explicit
        editor = LineEditor(
            io=io,
            prompt="€ ".encode("utf-8"),
            completer=None,  # eller complete om du vill ha TAB
        )

        # 🔑 Kör REPL med editor, inte med io
        run_repl(
            global_state,
            editor=editor,
        )

    except Exception as exc:
        LOGGER.exception("telnet error from %s: %s", addr, exc)

    finally:
        try:
            sock.close()
        except OSError:
            pass
