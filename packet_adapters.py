#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from DSL.modules.DslRuntime import DslRuntime
from shared.PathUtils import get_captures_root
from server.modules.interpretation.EncryptedWorldStream import EncryptedWorldStream
from server.modules.interpretation.OpcodeResolver import OpcodeResolver
from server.modules.interpretation.parser import parse_header
from server.modules.PacketDump import dump_capture
from server.modules.opcodes.AuthOpcodes import AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES
from server.modules.opcodes.WorldOpcodes import WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES
import server.modules.opcodes.WorldOpcodes as world_opcode_module
from proxy.utils.route_scope import route_phase, scoped_proxy_config


LOGGER = logging.getLogger("proxy")
WORLD_AUTH_RESPONSE_OPCODE = 0x01F6
try:
    WORLD_AUTH_SESSION_OPCODE = world_opcode_module.WorldClientOpcodes.CMSG_AUTH_SESSION.value
except Exception:
    WORLD_AUTH_SESSION_OPCODE = 0x00B2
_RUNTIME_LOCK = threading.Lock()
_RUNTIME: DslRuntime | None = None
_DB_LOCK = threading.Lock()
_DB_CONNECTION: Any = None
_DB_FAILED = False

_AUTH_FIXED_LENGTHS_C = {
    "AUTH_LOGON_PROOF_C": 75,
    "AUTH_RECONNECT_PROOF_C": 58,
    "REALM_LIST_C": 5,
}
_AUTH_FIXED_LENGTHS_S = {
    "AUTH_LOGON_CHALLENGE_S": 119,
    "AUTH_LOGON_PROOF_S": 32,
    "AUTH_RECONNECT_CHALLENGE_S": 34,
    "AUTH_RECONNECT_PROOF_S": 4,
}
_AUTH_SIZE_FIELD_PACKETS_C = {
    "AUTH_LOGON_CHALLENGE_C",
    "AUTH_RECONNECT_CHALLENGE_C",
}


def _to_safe_json(value: Any, key: str | None = None) -> Any:
    if isinstance(value, int):
        if key and "guid" in key.lower():
            hexstr = hex(value)[2:]
            if len(hexstr) % 2:
                hexstr = "0" + hexstr
            return "0x" + hexstr.upper()
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {k: _to_safe_json(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_safe_json(v, key) for v in value]
    return value


def _get_runtime() -> DslRuntime | None:
    global _RUNTIME
    if _RUNTIME is not None:
        return _RUNTIME

    with _RUNTIME_LOCK:
        if _RUNTIME is not None:
            return _RUNTIME
        try:
            runtime = DslRuntime(watch=False)
            runtime.load_runtime_all()
            _RUNTIME = runtime
            LOGGER.info("proxy packet adapters: DSL runtime ready")
        except Exception as exc:
            LOGGER.warning("proxy packet adapters: DSL runtime init failed: %s", exc)
            _RUNTIME = None
    return _RUNTIME


def _get_database_connection() -> Any:
    global _DB_CONNECTION
    global _DB_FAILED

    if _DB_CONNECTION is not None:
        return _DB_CONNECTION
    if _DB_FAILED:
        return None

    with _DB_LOCK:
        if _DB_CONNECTION is not None:
            return _DB_CONNECTION
        if _DB_FAILED:
            return None
        try:
            from server.modules.database.DatabaseConnection import DatabaseConnection

            DatabaseConnection.initialize()
            _DB_CONNECTION = DatabaseConnection
            LOGGER.info("proxy packet adapters: auth database ready")
        except Exception as exc:
            LOGGER.warning("proxy packet adapters: auth database init failed: %s", exc)
            _DB_FAILED = True
            _DB_CONNECTION = None

    return _DB_CONNECTION


def _decode_auth_session_payload(payload: bytes) -> dict[str, Any]:
    runtime = _get_runtime()
    if runtime is None:
        return {}
    try:
        return runtime.decode("CMSG_AUTH_SESSION", payload, silent=True) or {}
    except Exception:
        return {}


def _resolve_auth_account(decoded: dict[str, Any]) -> str:
    account = decoded.get("account") or decoded.get("username") or decoded.get("I") or ""
    return str(account).strip()


def _normalize_raw_format(raw_format: str | None) -> str:
    if str(raw_format or "").lower() == "bytes":
        return "bytes"
    return "hex"


def _format_raw_bytes(data: bytes, *, raw_format: str, max_bytes: int) -> str:
    sample = bytes(data[:max_bytes])
    if raw_format == "bytes":
        return repr(sample)
    return sample.hex()


def _proxy_cfg(state: Any) -> dict[str, Any]:
    proxy_cfg = getattr(state, "proxy", None)
    if isinstance(proxy_cfg, dict):
        return proxy_cfg
    return {}


def _proxy_route_cfg(state: Any, route_name: str | None = None) -> dict[str, Any]:
    proxy_cfg = _proxy_cfg(state)
    route_name = route_name or getattr(state, "route_name", "")
    phase = getattr(state, "phase", "") or route_phase(route_name)
    return scoped_proxy_config(proxy_cfg, phase=phase, route_name=route_name)


def _proxy_adapters_cfg(state: Any) -> dict[str, Any]:
    return _proxy_route_cfg(state).get("adapters") or {}


def _proxy_logging_cfg(state: Any) -> dict[str, Any]:
    return _proxy_route_cfg(state).get("logging") or {}


def _proxy_filter_cfg(state: Any) -> dict[str, Any]:
    return _proxy_route_cfg(state).get("filter") or {}


def _proxy_capture_cfg(state: Any) -> dict[str, Any]:
    return _proxy_route_cfg(state).get("capture") or {}


def _normalize_name_list(values: Any) -> set[str]:
    if not values:
        return set()
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    return {
        str(item).strip().upper()
        for item in values
        if str(item).strip()
    }


class PacketParserAdapter:
    """Read-only packet splitter that mirrors current auth/world framing rules."""

    def __init__(self, route_phase_name: str) -> None:
        self.route_phase = route_phase_name

    def feed(self, state: Any, data: bytes, direction: str) -> list[dict[str, Any]]:
        packet_direction = "C" if direction == "IN ---> OUT" else "S"
        if self.route_phase == "world":
            return self._feed_world(state, data, packet_direction)
        if self.route_phase == "auth":
            return self._feed_auth(state, data, packet_direction)
        return []

    def _feed_world(self, state: Any, data: bytes, packet_direction: str) -> list[dict[str, Any]]:
        if getattr(state, "encrypted", False):
            crypto = getattr(state, "world_crypto", None)
            stream = getattr(state, "encrypted_world_stream", None)
            if crypto is None or stream is None:
                return []
            raw_buf = state.packet_buffers[packet_direction]
            raw_buf.extend(data)
            packets = stream.feed(raw_buf, crypto=crypto, direction=packet_direction)
            return [
                {
                    "direction": packet_direction,
                    "header": raw_header,
                    "opcode": header.cmd,
                    "payload": payload,
                    "encrypted": True,
                }
                for raw_header, header, payload in packets
            ]

        raw_buf = state.packet_buffers[packet_direction]
        raw_buf.extend(data)

        packets: list[dict[str, Any]] = []
        while True:
            if not raw_buf:
                break

            # Match the worldserver/plain parser handshake shortcut.
            if b"WORLD OF WARCRAFT" in raw_buf:
                packets.append(
                    {
                        "direction": packet_direction,
                        "header": bytes(raw_buf[:4]),
                        "opcode": -1,
                        "payload": bytes(raw_buf),
                        "encrypted": False,
                    }
                )
                raw_buf.clear()
                break

            if len(raw_buf) < 4:
                break

            header = bytes(raw_buf[:4])
            size, opcode, _hex_opcode = parse_header(header)
            if size is None or opcode is None:
                break

            payload_len = max(0, int(size) - 2)
            if int(opcode) == WORLD_AUTH_RESPONSE_OPCODE:
                payload_len = max(0, int(size) - 4)

            packet_len = 4 + payload_len
            if len(raw_buf) < packet_len:
                break

            payload = bytes(raw_buf[4:packet_len])
            del raw_buf[:packet_len]

            packets.append(
                {
                    "direction": packet_direction,
                    "header": header,
                    "opcode": int(opcode),
                    "payload": payload,
                    "encrypted": False,
                }
            )

            # Match worldserver transition: CMSG_AUTH_SESSION is the final plain packet.
            if packet_direction == "C" and int(opcode) == WORLD_AUTH_SESSION_OPCODE:
                break

        return packets

    def _feed_auth(self, state: Any, data: bytes, packet_direction: str) -> list[dict[str, Any]]:
        raw_buf = state.packet_buffers[packet_direction]
        raw_buf.extend(data)

        packets: list[dict[str, Any]] = []
        while True:
            packet_len = self._next_auth_packet_len(bytes(raw_buf), packet_direction)
            if packet_len is None or len(raw_buf) < packet_len:
                break

            raw_packet = bytes(raw_buf[:packet_len])
            del raw_buf[:packet_len]

            packets.append(
                {
                    "direction": packet_direction,
                    "header": raw_packet[:1],
                    "opcode": raw_packet[0],
                    "payload": raw_packet[1:],
                    "encrypted": False,
                }
            )

        return packets

    def _next_auth_packet_len(self, data: bytes, packet_direction: str) -> int | None:
        if not data:
            return None

        opcode = data[0]
        opcode_name = (
            AUTH_CLIENT_OPCODES.get(opcode)
            if packet_direction == "C"
            else AUTH_SERVER_OPCODES.get(opcode)
        )
        if not opcode_name:
            return None

        if packet_direction == "C":
            if opcode_name in _AUTH_SIZE_FIELD_PACKETS_C:
                if len(data) < 4:
                    return None
                return 4 + int.from_bytes(data[2:4], "little")
            return _AUTH_FIXED_LENGTHS_C.get(opcode_name)

        if opcode_name == "REALM_LIST_S":
            if len(data) < 3:
                return None
            return 3 + int.from_bytes(data[1:3], "little")
        return _AUTH_FIXED_LENGTHS_S.get(opcode_name)


class OpcodeResolverAdapter:
    def __init__(self, route_phase_name: str) -> None:
        self.route_phase = route_phase_name
        self.world_resolver = OpcodeResolver(
            WORLD_CLIENT_OPCODES,
            WORLD_SERVER_OPCODES,
            world_opcode_module,
        )

    def __call__(self, state: Any, packets: list[dict[str, Any]], direction: str) -> list[dict[str, Any]]:
        _ = state
        _ = direction
        for packet in packets:
            packet_direction = packet.get("direction", "C")
            opcode = int(packet.get("opcode", 0))
            if self.route_phase == "world":
                if opcode < 0:
                    packet["opcode_name"] = "HANDSHAKE"
                else:
                    packet["opcode_name"] = self.world_resolver.decode_opcode(opcode, packet_direction)
                continue

            if packet_direction == "C":
                packet["opcode_name"] = AUTH_CLIENT_OPCODES.get(opcode, f"UNKNOWN_AUTH_C_0x{opcode:02X}")
            else:
                packet["opcode_name"] = AUTH_SERVER_OPCODES.get(opcode, f"UNKNOWN_AUTH_S_0x{opcode:02X}")
        return packets


class DslDecodeAdapter:
    def __call__(self, state: Any, packets: list[dict[str, Any]], direction: str) -> list[dict[str, Any]]:
        _ = state
        _ = direction
        if not _proxy_adapters_cfg(state).get("decode", False):
            for packet in packets:
                packet["decoded"] = None
            return packets

        runtime = _get_runtime()
        if runtime is None:
            for packet in packets:
                packet["decoded"] = None
            return packets

        for packet in packets:
            opcode_name = str(packet.get("opcode_name") or "")
            if not opcode_name or opcode_name == "HANDSHAKE" or opcode_name.startswith("UNKNOWN_"):
                packet["decoded"] = None
                continue
            try:
                raw = self._decode_input(state, packet)
                packet["decoded"] = runtime.decode(opcode_name, raw, silent=True) or {}
            except Exception:
                packet["decoded"] = None
        return packets

    def _decode_input(self, state: Any, packet: dict[str, Any]) -> bytes:
        if getattr(state, "phase", "") == "auth":
            return bytes(packet["header"]) + bytes(packet["payload"])
        return bytes(packet["payload"])


class WorldCryptoInitAdapter:
    def __call__(self, state: Any, packets: list[dict[str, Any]], direction: str) -> list[dict[str, Any]]:
        _ = direction
        if getattr(state, "phase", "") != "world":
            return packets
        if getattr(state, "world_crypto", None) is not None or getattr(state, "encrypted", False):
            return packets

        for packet in packets:
            if packet.get("direction") != "C":
                continue
            if int(packet.get("opcode", -1)) != WORLD_AUTH_SESSION_OPCODE:
                continue

            decoded = packet.get("decoded")
            if not isinstance(decoded, dict) or not decoded:
                decoded = _decode_auth_session_payload(bytes(packet.get("payload", b"")))

            account = _resolve_auth_account(decoded)
            if not account:
                LOGGER.warning(
                    "conn=%s route=world auth-session missing account name",
                    getattr(state, "conn_id", 0),
                )
                continue

            db = _get_database_connection()
            if db is None:
                continue

            try:
                from server.modules.crypto.ARC4Crypto import Arc4CryptoHandler

                row = db.get_user_by_username(account.upper())
                if row is None or not getattr(row, "session_key", None):
                    LOGGER.warning(
                        "conn=%s route=world missing session key for account=%s",
                        getattr(state, "conn_id", 0),
                        account,
                    )
                    continue

                crypto = Arc4CryptoHandler()
                crypto.init_arc4(row.session_key.hex())
                state.world_crypto = crypto
                state.encrypted = True

                for pending_direction in ("C", "S"):
                    if state.packet_buffers[pending_direction]:
                        state.packet_reparse_directions.add(pending_direction)

                LOGGER.info(
                    "conn=%s route=world world-crypto initialized account=%s",
                    getattr(state, "conn_id", 0),
                    account,
                )
            except Exception as exc:
                LOGGER.warning(
                    "conn=%s route=world failed to init crypto: %s",
                    getattr(state, "conn_id", 0),
                    exc,
                )
            break

        return packets


class LoggingAdapter:
    def _settings(self, state: Any) -> tuple[str, str, bool, bool, bool, bool, int, set[str], set[str]]:
        logging_cfg = _proxy_logging_cfg(state)
        filter_cfg = _proxy_filter_cfg(state)
        self.mode = str(logging_cfg.get("mode", "opcode") or "opcode")
        self.raw_format = _normalize_raw_format(logging_cfg.get("raw_format", "hex"))
        self.show_opcode = bool(logging_cfg.get("show_opcode", True))
        self.show_decoded = bool(logging_cfg.get("show_decoded", False))
        self.show_raw = bool(logging_cfg.get("show_raw", False))
        self.show_raw_if_undecoded = bool(logging_cfg.get("show_raw_if_undecoded", True))
        self.max_raw_bytes = int(
            logging_cfg.get(
                "max_raw_bytes",
                logging_cfg.get("max_hex_bytes", 256),
            )
            or 256
        )
        self.whitelist = _normalize_name_list(filter_cfg.get("whitelist", []))
        self.blacklist = _normalize_name_list(filter_cfg.get("blacklist", []))
        return (
            self.mode,
            self.raw_format,
            self.show_opcode,
            self.show_decoded,
            self.show_raw,
            self.show_raw_if_undecoded,
            self.max_raw_bytes,
            self.whitelist,
            self.blacklist,
        )

    def _is_visible(self, opcode_name: str, whitelist: set[str], blacklist: set[str]) -> bool:
        opcode_key = str(opcode_name).strip().upper()
        if opcode_key in whitelist:
            return True
        if whitelist:
            return False
        if opcode_key in blacklist:
            return False
        return True

    def _resolve_logging_flags(
        self,
        *,
        mode: str,
        show_opcode: bool,
        show_decoded: bool,
        show_raw: bool,
        show_raw_if_undecoded: bool,
        raw_format: str,
        decoded: Any,
    ) -> tuple[bool, bool, bool, str]:
        mode = mode.lower()

        if mode == "decoded":
            show_decoded = True
        elif mode == "raw":
            show_raw = True
        elif mode == "hex":
            show_raw = True
            raw_format = "hex"
        elif mode == "bytes":
            show_raw = True
            raw_format = "bytes"
        elif mode == "auto":
            if decoded is not None:
                show_decoded = True
            else:
                show_raw = True

        if show_decoded and decoded is None and show_raw_if_undecoded:
            show_raw = True

        return show_opcode, show_decoded, show_raw, raw_format

    def _packet_raw_bytes(self, packet: dict[str, Any]) -> bytes:
        # Once a header has been parsed/decrypted, raw view should exclude it.
        return bytes(packet.get("payload", b""))

    def __call__(self, state: Any, packets: list[dict[str, Any]], direction: str) -> list[dict[str, Any]]:
        _ = direction
        if not _proxy_adapters_cfg(state).get("logging", False):
            return packets

        conn_id = getattr(state, "conn_id", 0)
        route_name = getattr(state, "route_name", "")
        route_phase_name = getattr(state, "phase", "") or route_phase(route_name)
        if route_phase_name == "world":
            route_label = "WorldProxy"
        elif route_phase_name == "auth":
            route_label = "AuthProxy"
        else:
            route_label = "Proxy"
        (
            mode,
            raw_format_default,
            show_opcode_default,
            show_decoded_default,
            show_raw_default,
            show_raw_if_undecoded,
            max_raw_bytes,
            whitelist,
            blacklist,
        ) = self._settings(state)
        for packet in packets:
            opcode_name = packet.get("opcode_name", f"0x{int(packet.get('opcode', 0)):X}")
            if not self._is_visible(str(opcode_name), whitelist, blacklist):
                continue
            packet_direction = packet.get("direction", "?")
            arrow = "C→S" if packet_direction == "C" else "S→C"
            payload = bytes(packet.get("payload", b""))
            decoded = packet.get("decoded")
            encrypted = bool(packet.get("encrypted", False))
            show_opcode, show_decoded, show_raw, raw_format = self._resolve_logging_flags(
                mode=mode,
                show_opcode=show_opcode_default,
                show_decoded=show_decoded_default,
                show_raw=show_raw_default,
                show_raw_if_undecoded=show_raw_if_undecoded,
                raw_format=raw_format_default,
                decoded=decoded,
            )

            parts = [
                f"[{route_label}]",
                f"conn={conn_id}",
                arrow,
            ]

            if show_opcode:
                parts.append(str(opcode_name))

            parts.append(f"encrypted={encrypted}")
            parts.append(f"size={len(payload)}")

            if show_decoded and decoded is not None:
                parts.append(
                    "decoded="
                    + json.dumps(_to_safe_json(decoded), default=str, ensure_ascii=True)
                )

            if show_raw:
                parts.append(
                    "raw="
                    + _format_raw_bytes(
                        self._packet_raw_bytes(packet),
                        raw_format=raw_format,
                        max_bytes=max_raw_bytes,
                    )
                )

            LOGGER.info(" ".join(parts))
        return packets


class PacketCaptureAdapter:
    def _capture_settings(self, state: Any) -> tuple[bool, set[str]]:
        capture_cfg = _proxy_capture_cfg(state)
        dump_enabled = bool(capture_cfg.get("dump", False))
        focus_names = _normalize_name_list(capture_cfg.get("focus", []))
        return dump_enabled, focus_names

    def _decode_input(self, state: Any, packet: dict[str, Any]) -> bytes:
        if getattr(state, "phase", "") == "auth":
            return bytes(packet.get("header", b"")) + bytes(packet.get("payload", b""))
        return bytes(packet.get("payload", b""))

    def _decoded_payload(self, state: Any, packet: dict[str, Any]) -> dict[str, Any]:
        decoded = packet.get("decoded")
        if isinstance(decoded, dict):
            return _to_safe_json(decoded)

        opcode_name = str(packet.get("opcode_name") or "")
        if not opcode_name or opcode_name == "HANDSHAKE" or opcode_name.startswith("UNKNOWN_"):
            return {}

        runtime = _get_runtime()
        if runtime is None:
            return {}

        try:
            decoded = runtime.decode(opcode_name, self._decode_input(state, packet), silent=True) or {}
            return _to_safe_json(decoded)
        except Exception:
            return {}

    def __call__(self, state: Any, packets: list[dict[str, Any]], direction: str) -> list[dict[str, Any]]:
        _ = direction
        dump_enabled, focus_names = self._capture_settings(state)
        if not dump_enabled and not focus_names:
            return packets

        for packet in packets:
            opcode_name = str(packet.get("opcode_name") or f"OPCODE_{int(packet.get('opcode', 0)):04X}")
            raw_header = bytes(packet.get("header", b""))
            payload = bytes(packet.get("payload", b""))
            decoded = self._decoded_payload(state, packet)

            if dump_enabled:
                try:
                    dump_capture(
                        opcode_name,
                        raw_header,
                        payload,
                        decoded,
                        root=get_captures_root(),
                    )
                except Exception as exc:
                    LOGGER.warning(
                        "conn=%s capture-dump-error opcode=%s: %s",
                        getattr(state, "conn_id", 0),
                        opcode_name,
                        exc,
                    )

            if opcode_name.strip().upper() in focus_names:
                try:
                    dump_capture(
                        opcode_name,
                        raw_header,
                        payload,
                        decoded,
                        root=get_captures_root(focus=True),
                        ts=int(time.time()),
                    )
                except Exception as exc:
                    LOGGER.warning(
                        "conn=%s focus-dump-error opcode=%s: %s",
                        getattr(state, "conn_id", 0),
                        opcode_name,
                        exc,
                    )

        return packets


def configure_packet_adapters(state: Any, config: dict, route_name: str, route_phase_name: str) -> None:
    state.packet_parser = PacketParserAdapter(route_phase_name)
    state.encrypted_world_stream = EncryptedWorldStream() if route_phase_name == "world" else None
    state.packet_adapters = [OpcodeResolverAdapter(route_phase_name)]

    state.packet_adapters.append(DslDecodeAdapter())
    if route_phase_name == "world":
        state.packet_adapters.append(WorldCryptoInitAdapter())
    state.packet_adapters.append(PacketCaptureAdapter())
    state.packet_adapters.append(LoggingAdapter())


def apply_packet_adapters(state: Any, data: bytes, direction: str) -> None:
    parser = getattr(state, "packet_parser", None)
    if parser is None:
        return
    if not _proxy_adapters_cfg(state).get("opcode_parser", False):
        return

    with state.packet_lock:
        pending_directions = [direction]
        first_direction = direction
        first_data_consumed = False

        while pending_directions:
            current_direction = pending_directions.pop(0)
            current_data = b""
            if current_direction == first_direction and not first_data_consumed:
                current_data = data
                first_data_consumed = True

            try:
                packets = parser.feed(state, current_data, current_direction)
            except Exception as exc:
                LOGGER.warning("packet-parser-error conn=%s: %s", getattr(state, "conn_id", 0), exc)
                return

            if packets:
                current = packets
                for adapter in getattr(state, "packet_adapters", []):
                    try:
                        current = adapter(state, current, current_direction)
                    except Exception as exc:
                        LOGGER.warning(
                            "packet-adapter-error conn=%s adapter=%s: %s",
                            getattr(state, "conn_id", 0),
                            adapter.__class__.__name__,
                            exc,
                        )
                        continue

            while state.packet_reparse_directions:
                packet_direction = state.packet_reparse_directions.pop()
                replay_direction = "IN ---> OUT" if packet_direction == "C" else "OUT ---> IN"
                if replay_direction not in pending_directions:
                    pending_directions.append(replay_direction)
