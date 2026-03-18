#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# state.py
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Literal

Phase = Literal["auth", "world"]


@dataclass
class SessionState:
    """
    Per-connection session state.
    Describes protocol position and capabilities.
    """
    phase: Phase = "auth"
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
class GlobalState:
    """
    Global control-plane state.
    Controlled by telnet, observed by proxy.
    """
    shutdown: bool = False
    enable_log: bool = True
    enable_view: bool = True
    enable_decode: bool = False
    active_state: str = "default"
    routes: dict[str, Any] = field(default_factory=dict)
    proxy: dict[str, Any] = field(default_factory=dict)

    lock: Lock = field(default_factory=Lock)
