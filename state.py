#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Literal

from proxy.config import CONFIG as DEFAULT_CONFIG
from proxy.utils.config_loader import ConfigLoader
from shared.Logger import Logger

Phase = Literal["auth", "world"]

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROXY_STATE_PATH = _PROJECT_ROOT / "config" / "proxy.state.json"
_STATE_SCHEMA_VERSION = 1


@dataclass
class SessionState:
    """
    Per-connection session state.
    Describes protocol position and capabilities.
    """

    phase: Phase = "auth"
    protocol: str = "UNKNOWN"
    auth_stage: str = ""
    username: str | None = None
    session_key: bytes | None = None
    srp_session: Any = None
    auth_analysis: dict[str, Any] = field(default_factory=dict)
    encrypted: bool = False
    shutdown: bool = False
    route_name: str = ""
    conn_id: int = 0
    adapters: list[Any] = field(default_factory=list)
    packet_parser: Any = None
    packet_adapters: list[Any] = field(default_factory=list)
    packet_buffers: dict[str, bytearray] = field(
        default_factory=lambda: {"C": bytearray(), "S": bytearray()}
    )
    encrypted_world_stream: Any = None
    world_crypto: Any = None
    packet_lock: Lock = field(default_factory=Lock)
    packet_reparse_directions: set[str] = field(default_factory=set)
    proxy: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProxyState:
    """
    Global runtime state for the proxy control plane.

    This is the single source of truth for persisted proxy runtime state.
    Transient runtime-only fields are kept here too, but excluded from JSON.
    """

    shutdown: bool = False
    enable_log: bool = True
    enable_view: bool = True
    enable_decode: bool = False
    active_state: str = "default"
    routes: dict[str, Any] = field(default_factory=dict)
    proxy: dict[str, Any] = field(default_factory=dict)
    reload_requested: bool = False
    reload_epoch: int = 0
    lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    @classmethod
    def from_active_config(cls, state_name: str = "default") -> "ProxyState":
        normalized_state = str(state_name or "default")
        if normalized_state not in (DEFAULT_CONFIG.get("states", {}) or {}):
            normalized_state = "default"

        cfg = ConfigLoader.load_active_config(normalized_state)
        state = cls()
        state.active_state = normalized_state
        state.routes = deepcopy(cfg.get("routes", {}))
        state.proxy = deepcopy(cfg.get("proxy", {}))
        state.enable_log = bool(cfg.get("enable_log", True))
        state.enable_view = bool(cfg.get("enable_view", True))
        state.enable_decode = bool(cfg.get("enable_decode", False))
        return state

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _STATE_SCHEMA_VERSION,
            "active_state": str(self.active_state or "default"),
            "enable_log": bool(self.enable_log),
            "enable_view": bool(self.enable_view),
            "enable_decode": bool(self.enable_decode),
            "routes": deepcopy(self.routes),
            "proxy": deepcopy(self.proxy),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProxyState":
        if not isinstance(data, dict):
            raise ValueError("state payload must be a JSON object")

        active_state = str(data.get("active_state", "default") or "default")
        state = cls.from_active_config(active_state)

        if isinstance(data.get("enable_log"), bool):
            state.enable_log = data["enable_log"]
        if isinstance(data.get("enable_view"), bool):
            state.enable_view = data["enable_view"]
        if isinstance(data.get("enable_decode"), bool):
            state.enable_decode = data["enable_decode"]
        if isinstance(data.get("routes"), dict):
            state.routes = deepcopy(data["routes"])
        if isinstance(data.get("proxy"), dict):
            state.proxy = deepcopy(data["proxy"])

        state.shutdown = False
        state.reload_requested = False
        state.reload_epoch = 0
        return state


GlobalState = ProxyState


def save_state(state: ProxyState, path: str | Path = DEFAULT_PROXY_STATE_PATH) -> bool:
    state_path = Path(path)
    payload = state.to_dict()
    tmp_path = state_path.with_name(f"{state_path.name}.tmp")

    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp_path.replace(state_path)
        Logger.info("[STATE] Saved to disk: %s", state_path, scope="proxy")
        return True
    except Exception as exc:
        Logger.error("[STATE] Save failed: %s (%s)", state_path, exc, scope="proxy")
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        return False


def load_state(path: str | Path = DEFAULT_PROXY_STATE_PATH) -> ProxyState:
    state_path = Path(path)

    if not state_path.exists():
        state = ProxyState.from_active_config("default")
        Logger.info("[STATE] Fallback to default (missing): %s", state_path, scope="proxy")
        return state

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        state = ProxyState.from_dict(data)
        Logger.info("[STATE] Loaded from disk: %s", state_path, scope="proxy")
        return state
    except Exception as exc:
        Logger.error("[STATE] Load failed: %s (%s)", state_path, exc, scope="proxy")
        state = ProxyState.from_active_config("default")
        Logger.info("[STATE] Fallback to default (corrupt): %s", state_path, scope="proxy")
        return state
