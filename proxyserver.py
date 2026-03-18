#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bidirectional TCP proxy.
Version: 0.3

State-aware, datacentric design.

WARNING:
Default listen_host is 127.0.0.1.
Binding to 0.0.0.0 exposes the proxy to the network.
"""

import socket
import threading
import itertools
import signal
import asyncio

from proxy.utils.config_loader import ConfigLoader
from proxy.state import SessionState, GlobalState
from proxy.state_machine import update_state
from proxy.adapters import apply_adapters
from proxy.packet_adapters import apply_packet_adapters, configure_packet_adapters
from proxy.telnet.server import run_telnet_server
from proxy.utils.route_scope import route_phase, scoped_proxy_config
from shared.ConfigLoader import ConfigLoader as SharedConfigLoader
from shared.Logger import Logger


# ----------------------------------------------------------------------
# Global runtime state
# ----------------------------------------------------------------------

CONFIG = {}
SHUTDOWN_EVENT = threading.Event()

MAX_CONNECTIONS = 200
CONNECTION_SEMAPHORE = threading.Semaphore(MAX_CONNECTIONS)

CONNECTION_ID_LOCK = threading.Lock()
CONNECTION_IDS = itertools.count(1)

SOCKET_TIMEOUT = 300  # seconds

STATE = GlobalState()

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

LOGGER = Logger


def _project_name() -> str:
    try:
        cfg = SharedConfigLoader.load_config()
    except Exception:
        return "Unknown"
    return str(cfg.get("project_name", "Unknown")).strip() or "Unknown"


def _proxy_logging_cfg() -> dict:
    proxy_cfg = getattr(STATE, "proxy", None)
    if isinstance(proxy_cfg, dict):
        return proxy_cfg.get("logging") or {}
    proxy_cfg = CONFIG.get("proxy") or {}
    return proxy_cfg.get("logging") or {}


def _proxy_route_cfg(route_name: str, phase: str | None = None) -> dict:
    proxy_cfg = getattr(STATE, "proxy", None)
    if not isinstance(proxy_cfg, dict):
        proxy_cfg = CONFIG.get("proxy") or {}
    if not phase:
        phase = route_phase(route_name, STATE.routes.get(route_name) if isinstance(STATE.routes, dict) else None)
    return scoped_proxy_config(proxy_cfg, phase=phase, route_name=route_name)


def _format_stream_raw(data: bytes, route_name: str, phase: str | None = None) -> str:
    logging_cfg = (_proxy_route_cfg(route_name, phase).get("logging") or {})
    raw_format = str(logging_cfg.get("raw_format", "hex") or "hex").lower()
    max_raw_bytes = int(
        logging_cfg.get(
            "max_raw_bytes",
            logging_cfg.get("max_hex_bytes", 256),
        )
        or 256
    )
    sample = bytes(data[:max_raw_bytes])
    if raw_format == "bytes":
        return repr(sample)
    return sample.hex()


# ----------------------------------------------------------------------
# Signal handling
# ----------------------------------------------------------------------

def _handle_shutdown(signum, frame):
    SHUTDOWN_EVENT.set()
    STATE.shutdown = True


signal.signal(signal.SIGINT, _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


# ----------------------------------------------------------------------
# Taps (state-aware)
# ----------------------------------------------------------------------

def log_tap(conn_id, client_addr, direction, data, state: SessionState):
    client_ip, client_port = client_addr
    LOGGER.info(
        "conn=%s client=%s:%s phase=%s encrypted=%s %s raw=%s",
        conn_id,
        client_ip,
        client_port,
        state.phase,
        state.encrypted,
        direction,
        _format_stream_raw(data, state.route_name, state.phase),
    )


def view_tap(conn_id, client_addr, direction, data, state):
    LOGGER.info(
        "conn=%s client=%s:%s phase=%s encrypted=%s %s raw=%s",
        conn_id,
        client_addr[0],
        client_addr[1],
        state.phase,
        state.encrypted,
        direction,
        _format_stream_raw(data, state.route_name, state.phase),
    )


def build_taps(state: GlobalState, route_name: str, phase: str = ""):
    proxy_cfg = _proxy_route_cfg(route_name, phase)
    adapters_cfg = proxy_cfg.get("adapters") or {}
    if adapters_cfg.get("opcode_parser", False) and adapters_cfg.get("logging", False):
        return ()

    taps = []

    if state.enable_log:
        taps.append(log_tap)

    if state.enable_view:
        taps.append(view_tap)

    return tuple(taps)


# ----------------------------------------------------------------------
# Core pipe
# ----------------------------------------------------------------------

def pipe(source, destination, conn_id, client_addr, direction, state):
    while not SHUTDOWN_EVENT.is_set() and not state.shutdown:
        try:
            data = source.recv(CONFIG["buffer_size"])
        except socket.timeout:
            continue
        except OSError:
            break

        update_state(state, data, direction)
        apply_packet_adapters(state, data, direction)
        data = apply_adapters(state, data, direction)

        if not data:
            continue

        for tap in build_taps(STATE, state.route_name, state.phase):
            try:
                tap(conn_id, client_addr, direction, data, state)
            except Exception as exc:
                LOGGER.error("tap error conn=%s: %s", conn_id, exc)

        try:
            destination.sendall(data)
        except OSError:
            break


# ----------------------------------------------------------------------
# Connection handler
# ----------------------------------------------------------------------

def handle_connection(client, client_addr, route):
    if not CONNECTION_SEMAPHORE.acquire(blocking=False):
        client.close()
        return

    with CONNECTION_ID_LOCK:
        conn_id = next(CONNECTION_IDS)

    # PATCH: route-lookup vid connect-ögonblicket (state switch påverkar nya conns)
    route_name = route.get("name")
    current_route = STATE.routes.get(route_name) if route_name else route
    if not current_route:
        LOGGER.warning("route missing conn=%s route=%s", conn_id, route_name)
        client.close()
        CONNECTION_SEMAPHORE.release()
        return

    LOGGER.info(
        "connect conn=%s %s:%s -> %s:%s",
        conn_id,
        CONFIG["listen_host"],
        current_route["listen"],
        current_route["forward"]["host"],
        current_route["forward"]["port"],
    )

    state = SessionState()
    state.route_name = route_name or ""
    state.conn_id = conn_id
    state.phase = route_phase(route_name, current_route) or state.phase
    state.proxy = STATE.proxy
    configure_packet_adapters(state, CONFIG, state.route_name, state.phase)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.settimeout(SOCKET_TIMEOUT)
        server.connect(
            (current_route["forward"]["host"], current_route["forward"]["port"])
        )

        LOGGER.info(
            "connect conn=%s client=%s:%s",
            conn_id,
            client_addr[0],
            client_addr[1],
        )

        threads = [
            threading.Thread(
                target=pipe,
                args=(
                    client,
                    server,
                    conn_id,
                    client_addr,
                    "IN ---> OUT",
                    state,
                ),
            ),
            threading.Thread(
                target=pipe,
                args=(
                    server,
                    client,
                    conn_id,
                    client_addr,
                    "OUT ---> IN",
                    state,
                ),
            ),
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

    except ConnectionRefusedError:
        LOGGER.warning("backend unavailable conn=%s", conn_id)

    finally:
        state.shutdown = True
        client.close()
        server.close()
        CONNECTION_SEMAPHORE.release()
        LOGGER.info("disconnect conn=%s", conn_id)


# ----------------------------------------------------------------------
# Route runner
# ----------------------------------------------------------------------

def run_route(cfg, route):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(1.0)

    listener.bind((cfg["listen_host"], route["listen"]))
    listener.listen(5)

    LOGGER.info(
        "listening %s:%s -> %s:%s",
        cfg["listen_host"],
        route["listen"],
        route["forward"]["host"],
        route["forward"]["port"],
    )

    while not SHUTDOWN_EVENT.is_set():
        try:
            client, client_addr = listener.accept()
            client.settimeout(SOCKET_TIMEOUT)

            threading.Thread(
                target=handle_connection,
                args=(client, client_addr, route),
            ).start()

        except socket.timeout:
            continue
        except OSError:
            break

    listener.close()


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def run():
    global CONFIG
    CONFIG = ConfigLoader.load_active_config("default")

    # PATCH: använd global STATE, skugga den inte
    STATE.active_state = "default"
    STATE.routes = CONFIG["routes"]
    STATE.proxy = CONFIG.setdefault("proxy", {})

    Logger.configure(
        scope="proxy",
        write_to_log=bool(CONFIG.get("write_to_log", True)),
        log_file=str(CONFIG.get("log_file", "proxy.log")),
        reset=True,
    )
    LOGGER.info("%s Proxy starting", _project_name())

    for name, route in CONFIG["routes"].items():
        route["name"] = name
        route["phase"] = route_phase(name, route)
        threading.Thread(
            target=run_route,
            args=(CONFIG, route),
            daemon=True,
            name=f"proxy-route-{name}",
        ).start()

    threading.Thread(
        target=lambda: asyncio.run(run_telnet_server(STATE)),
        daemon=True,
        name="telnet-server",
    ).start()

    try:
        SHUTDOWN_EVENT.wait()
    finally:
        pass


if __name__ == "__main__":
    run()
