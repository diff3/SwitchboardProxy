#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proxy-side protocol analysis for auth/world login packets.

This module is intentionally lightweight:
- it reads DSL-decoded packet data
- it classifies the connection as SRP6, LEGACY or UNKNOWN
- it extracts semantic auth metadata without mutating DSL output

SRP6 is identified by canonical SRP fields such as A, M1, B, g, N and s.
Legacy is treated as any non-SRP auth flow with explicit credentials, hashes,
digests or session-key-like fields. When a packet is ambiguous, the analyzer
falls back to the configured world mode instead of guessing.
"""

from __future__ import annotations

from typing import Any

from proxy.utils.route_scope import route_phase, scoped_proxy_config

PROTOCOL_UNKNOWN = "UNKNOWN"
PROTOCOL_SRP6 = "SRP6"
PROTOCOL_LEGACY = "LEGACY"

_SRP_FIELDS = {"A", "M1", "B", "g", "N", "s", "M2"}
_USERNAME_FIELDS = ("account", "username", "I")
_SESSION_KEY_FIELDS = ("session_key", "sessionkey", "K")
_CREDENTIAL_KEYWORDS = ("password", "hash", "digest", "proof", "session_key", "sessionkey")
_STAGE_BY_OPCODE = {
    "AUTH_LOGON_CHALLENGE_C": "AUTH_CHALLENGE",
    "AUTH_LOGON_CHALLENGE_S": "AUTH_CHALLENGE",
    "AUTH_LOGON_PROOF_C": "AUTH_PROOF",
    "AUTH_LOGON_PROOF_S": "AUTH_PROOF",
    "AUTH_RECONNECT_CHALLENGE_C": "AUTH_RECONNECT",
    "AUTH_RECONNECT_CHALLENGE_S": "AUTH_RECONNECT",
    "AUTH_RECONNECT_PROOF_C": "AUTH_RECONNECT_PROOF",
    "AUTH_RECONNECT_PROOF_S": "AUTH_RECONNECT_PROOF",
    "CMSG_AUTH_SESSION": "AUTH_SESSION",
}


def _decoded_fields(decoded: Any) -> dict[str, Any]:
    if isinstance(decoded, dict):
        return decoded
    return {}


def _coerce_bytes(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None
    return None


def _extract_username(decoded: dict[str, Any]) -> str | None:
    for key in _USERNAME_FIELDS:
        value = decoded.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _extract_session_key(decoded: dict[str, Any]) -> bytes | None:
    for key in _SESSION_KEY_FIELDS:
        value = _coerce_bytes(decoded.get(key))
        if value:
            return value
    return None


def configured_protocol_hint(state: Any) -> str:
    proxy_cfg = getattr(state, "proxy", None)
    if not isinstance(proxy_cfg, dict):
        return PROTOCOL_UNKNOWN

    route_name = getattr(state, "route_name", "")
    phase = getattr(state, "phase", "") or route_phase(route_name)
    scoped = scoped_proxy_config(proxy_cfg, phase=phase, route_name=route_name)
    world_mode = str((scoped.get("mode") or "")).strip().lower()
    if world_mode == "srp6":
        return PROTOCOL_SRP6
    if world_mode == "legacy":
        return PROTOCOL_LEGACY
    return PROTOCOL_UNKNOWN


def _has_legacy_credentials(decoded: dict[str, Any]) -> bool:
    for key, value in decoded.items():
        key_text = str(key).strip().lower()
        if not key_text:
            continue
        if not any(token in key_text for token in _CREDENTIAL_KEYWORDS):
            continue
        if value in (None, "", b"", bytearray()):
            continue
        return True
    return False


def _detect_protocol(state: Any, opcode_name: str, decoded: dict[str, Any]) -> tuple[str, str]:
    keys = set(decoded.keys())
    if keys & _SRP_FIELDS:
        return PROTOCOL_SRP6, "srp_fields"

    if opcode_name == "CMSG_AUTH_SESSION" and {"account", "digest"} <= keys:
        current = str(getattr(state, "protocol", PROTOCOL_UNKNOWN) or PROTOCOL_UNKNOWN).upper()
        if current in {PROTOCOL_SRP6, PROTOCOL_LEGACY}:
            return current, "session_continuation"
        hint = configured_protocol_hint(state)
        if hint != PROTOCOL_UNKNOWN:
            return hint, "config_hint"
        return PROTOCOL_UNKNOWN, ""

    if _has_legacy_credentials(decoded):
        return PROTOCOL_LEGACY, "legacy_credentials"

    return PROTOCOL_UNKNOWN, ""


def analyze_packet(state: Any, packet_ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze a decoded packet and extract auth semantics.

    The returned dictionary is safe to attach to packet metadata. It does not
    modify the packet payload or decoded DSL fields.
    """

    opcode_name = str(packet_ctx.get("opcode_name") or "").strip()
    decoded = _decoded_fields(packet_ctx.get("decoded"))
    protocol, reason = _detect_protocol(state, opcode_name, decoded)
    stage = _STAGE_BY_OPCODE.get(opcode_name, "")

    srp_values = {
        key: decoded[key]
        for key in ("A", "M1", "B", "g", "N", "s", "M2")
        if key in decoded
    }

    result = {
        "auth_type": protocol,
        "username": _extract_username(decoded),
        "stage": stage,
        "session_key": _extract_session_key(decoded),
        "proof_fields": srp_values,
        "digest": decoded.get("digest"),
        "reason": reason,
    }

    if result["auth_type"] == PROTOCOL_UNKNOWN:
        hinted = configured_protocol_hint(state)
        if hinted != PROTOCOL_UNKNOWN and opcode_name == "CMSG_AUTH_SESSION":
            result["auth_type"] = hinted
            result["reason"] = "config_hint"

    return result
