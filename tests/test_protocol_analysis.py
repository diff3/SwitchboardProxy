from types import SimpleNamespace
from unittest.mock import patch

from proxy.packet_adapters import (
    ProtocolAnalysisAdapter,
    WorldCryptoInitAdapter,
    _AUTH_PROTOCOL_BY_ACCOUNT,
)
from proxy.protocol_analysis import PROTOCOL_LEGACY, PROTOCOL_SRP6, analyze_packet
from proxy.state import SessionState


def _proxy_cfg(world_mode: str | None = "srp6") -> dict:
    world_cfg = {}
    if world_mode is not None:
        world_cfg["mode"] = world_mode
    return {
        "adapters": {"decode": True},
        "logging": {},
        "filter": {},
        "capture": {},
        "phases": {
            "auth": {},
            "world": world_cfg,
        },
        "routes": {},
    }


def test_analyze_packet_detects_srp6_from_proof_fields():
    state = SimpleNamespace(proxy=_proxy_cfg("srp6"), route_name="auth", phase="auth")
    packet = {
        "opcode_name": "AUTH_LOGON_PROOF_C",
        "decoded": {
            "A": b"\x11" * 32,
            "M1": b"\x22" * 20,
        },
    }

    analysis = analyze_packet(state, packet)

    assert analysis["auth_type"] == PROTOCOL_SRP6
    assert analysis["stage"] == "AUTH_PROOF"
    assert set(analysis["proof_fields"]) == {"A", "M1"}


def test_analyze_packet_uses_config_hint_for_legacy_world_auth():
    state = SimpleNamespace(proxy=_proxy_cfg("legacy"), route_name="world", phase="world")
    packet = {
        "opcode_name": "CMSG_AUTH_SESSION",
        "decoded": {
            "account": "LEGACYUSER",
            "digest": b"\x33" * 20,
        },
    }

    analysis = analyze_packet(state, packet)

    assert analysis["auth_type"] == PROTOCOL_LEGACY
    assert analysis["username"] == "LEGACYUSER"
    assert analysis["stage"] == "AUTH_SESSION"


def test_analyze_packet_keeps_existing_srp6_protocol_for_world_auth():
    state = SimpleNamespace(
        proxy=_proxy_cfg("legacy"),
        route_name="world",
        phase="world",
        protocol=PROTOCOL_SRP6,
    )
    packet = {
        "opcode_name": "CMSG_AUTH_SESSION",
        "decoded": {
            "account": "SRPUSER",
            "digest": b"\x55" * 20,
        },
    }

    analysis = analyze_packet(state, packet)

    assert analysis["auth_type"] == PROTOCOL_SRP6
    assert analysis["reason"] == "session_continuation"


def test_protocol_analysis_adapter_updates_session_state():
    _AUTH_PROTOCOL_BY_ACCOUNT.clear()
    state = SessionState()
    state.proxy = _proxy_cfg("srp6")
    state.route_name = "auth"
    state.phase = "auth"
    state.conn_id = 7
    packets = [
        {
            "opcode_name": "AUTH_LOGON_CHALLENGE_C",
            "decoded": {"username": "TESTUSER"},
        },
        {
            "opcode_name": "AUTH_LOGON_PROOF_C",
            "decoded": {"A": b"\x11" * 32, "M1": b"\x22" * 20},
        },
    ]

    with patch("proxy.packet_adapters.LOGGER.info"):
        ProtocolAnalysisAdapter()(state, packets, "IN ---> OUT")

    assert state.username == "TESTUSER"
    assert state.protocol == PROTOCOL_SRP6
    assert state.auth_stage == "AUTH_PROOF"
    assert packets[0]["analysis"]["username"] == "TESTUSER"
    assert packets[1]["analysis"]["auth_type"] == PROTOCOL_SRP6


def test_protocol_analysis_adapter_reuses_cached_auth_protocol_for_world_session():
    _AUTH_PROTOCOL_BY_ACCOUNT.clear()
    auth_state = SessionState()
    auth_state.proxy = _proxy_cfg(None)
    auth_state.route_name = "auth"
    auth_state.phase = "auth"
    auth_state.conn_id = 1
    world_state = SessionState()
    world_state.proxy = _proxy_cfg(None)
    world_state.route_name = "world"
    world_state.phase = "world"
    world_state.conn_id = 2

    auth_packets = [
        {
            "opcode_name": "AUTH_LOGON_CHALLENGE_C",
            "decoded": {"username": "MAPE"},
        },
        {
            "opcode_name": "AUTH_LOGON_PROOF_C",
            "decoded": {"A": b"\x11" * 32, "M1": b"\x22" * 20},
        },
    ]
    world_packets = [
        {
            "opcode_name": "CMSG_AUTH_SESSION",
            "decoded": {"account": "MAPE", "digest": b"\x33" * 20},
        }
    ]

    with patch("proxy.packet_adapters.LOGGER.info"):
        ProtocolAnalysisAdapter()(auth_state, auth_packets, "IN ---> OUT")
        ProtocolAnalysisAdapter()(world_state, world_packets, "IN ---> OUT")

    assert world_state.protocol == PROTOCOL_SRP6
    assert world_packets[0]["analysis"]["auth_type"] == PROTOCOL_SRP6
    assert world_packets[0]["analysis"]["reason"] == "auth_cache"


def test_protocol_analysis_adapter_keeps_explicit_legacy_world_mode_over_auth_cache():
    _AUTH_PROTOCOL_BY_ACCOUNT.clear()
    auth_state = SessionState()
    auth_state.proxy = _proxy_cfg(None)
    auth_state.route_name = "auth"
    auth_state.phase = "auth"
    world_state = SessionState()
    world_state.proxy = _proxy_cfg("legacy")
    world_state.route_name = "world"
    world_state.phase = "world"

    auth_packets = [
        {
            "opcode_name": "AUTH_LOGON_PROOF_C",
            "decoded": {"A": b"\x11" * 32, "M1": b"\x22" * 20, "username": "MAPE"},
        }
    ]
    world_packets = [
        {
            "opcode_name": "CMSG_AUTH_SESSION",
            "decoded": {"account": "MAPE", "digest": b"\x33" * 20},
        }
    ]

    with patch("proxy.packet_adapters.LOGGER.info"):
        ProtocolAnalysisAdapter()(auth_state, auth_packets, "IN ---> OUT")
        ProtocolAnalysisAdapter()(world_state, world_packets, "IN ---> OUT")

    assert world_state.protocol == PROTOCOL_LEGACY
    assert world_packets[0]["analysis"]["auth_type"] == PROTOCOL_LEGACY
    assert world_packets[0]["analysis"]["reason"] == "config_hint"


def test_world_crypto_init_uses_analyzed_username_and_sets_session_key():
    state = SessionState()
    state.proxy = _proxy_cfg("legacy")
    state.route_name = "world"
    state.phase = "world"
    state.conn_id = 11
    state.protocol = PROTOCOL_LEGACY

    packets = [
        {
            "direction": "C",
            "opcode": 0x00B2,
            "opcode_name": "CMSG_AUTH_SESSION",
            "payload": b"",
            "decoded": {"account": "legacyuser"},
            "analysis": {"username": "legacyuser"},
        }
    ]

    fake_row = SimpleNamespace(session_key=b"\x44" * 40)
    fake_db = SimpleNamespace(get_user_by_username=lambda username: fake_row)

    with patch("proxy.packet_adapters._get_database_connection", return_value=fake_db):
        with patch("proxy.packet_adapters._create_world_crypto", return_value=object()):
            with patch("proxy.packet_adapters.LOGGER.info"):
                WorldCryptoInitAdapter()(state, packets, "IN ---> OUT")

    assert state.encrypted is True
    assert state.session_key == b"\x44" * 40
    assert state.world_crypto is not None
