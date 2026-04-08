import proxy.packet_adapters as packet_adapters
import struct
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from proxy.packet_adapters import (
    PacketParserAdapter,
    ProtocolAnalysisAdapter,
    WorldCryptoInitAdapter,
    _AUTH_PROTOCOL_BY_ACCOUNT,
    _get_database_connection,
    _normalize_world_session_key,
    reset_packet_adapter_runtime,
    get_account_row,
)
from proxy.protocol_analysis import PROTOCOL_LEGACY, PROTOCOL_SRP6, analyze_packet
from proxy.state import SessionState
from server.modules.interpretation.EncryptedWorldStream import EncryptedWorldStream


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


def test_analyze_packet_uses_configured_legacy_world_mode():
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
    assert analysis["reason"] == "config"


def test_analyze_packet_ignores_existing_protocol_and_follows_config():
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

    assert analysis["auth_type"] == PROTOCOL_LEGACY
    assert analysis["reason"] == "config"


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


def test_protocol_analysis_adapter_uses_configured_world_mode_for_world_session():
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
    assert world_packets[0]["analysis"]["reason"] == "config"


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
    assert world_packets[0]["analysis"]["reason"] == "config"


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
            "header": b"\xb2\x00\x00\x00",
            "payload": b"\x10\x20\x30",
            "decoded": {"account": "legacyuser"},
            "analysis": {"username": "legacyuser"},
        }
    ]

    fake_row = SimpleNamespace(sessionkey="44" * 40)

    with patch("proxy.packet_adapters._get_database_connection", return_value=object()):
        with patch("proxy.packet_adapters.get_account_row", return_value=fake_row):
            with patch("proxy.packet_adapters._create_world_crypto", return_value=object()) as create_crypto:
                with patch("proxy.packet_adapters.LOGGER.info"):
                    WorldCryptoInitAdapter()(state, packets, "IN ---> OUT")

    assert state.encrypted is True
    assert state.session_key == b"\x44" * 40
    assert state.world_crypto is not None
    assert state.encrypted_world_stream is not None
    assert state.packet_reparse_directions == {"S"}
    assert bytes(state.packet_buffers["C"]) == b""
    create_crypto.assert_called_once_with(PROTOCOL_LEGACY, b"\x44" * 40)


def test_world_plain_server_parser_leaves_non_auth_challenge_bytes_buffered():
    state = SessionState()
    state.proxy = _proxy_cfg("legacy")
    state.route_name = "world"
    state.phase = "world"

    parser = PacketParserAdapter("world")
    encrypted_server_bytes = b"\x9B\x3E\x02\x00\x16\x32\x47\x00"

    packets = parser.feed(state, encrypted_server_bytes, "OUT ---> IN")

    assert packets == []
    assert bytes(state.packet_buffers["S"]) == encrypted_server_bytes


def test_encrypted_world_stream_keeps_full_auth_response_size_for_legacy_and_next_header_aligns():
    def _pack(cmd: int, size: int) -> bytes:
        return struct.pack("<I", (size << 13) | (cmd & 0x1FFF))

    class FakeCrypto:
        def __init__(self):
            self.calls = 0

        def encrypt_send(self, _header: bytes) -> bytes:
            self.calls += 1
            if self.calls == 1:
                return _pack(0x01F6, 124)
            return _pack(0x0C0A, 21)

        def decrypt_recv(self, header: bytes) -> bytes:
            return header

        def unpack_data(self, data: bytes):
            value = struct.unpack("<I", data)[0]
            return SimpleNamespace(cmd=value & 0x1FFF, size=(value & 0xFFFFE000) >> 13)

    stream = EncryptedWorldStream(server_auth_response_size_adjust=0)
    crypto = FakeCrypto()
    raw_buf = bytearray(b"\x00" * 4 + b"\x11" * 124 + b"\x00" * 4 + b"\x22" * 21)

    packets = stream.feed(raw_buf, crypto=crypto, direction="S")

    assert len(packets) == 2
    assert packets[0][1].cmd == 0x01F6
    assert len(packets[0][2]) == 124
    assert packets[1][1].cmd == 0x0C0A
    assert len(packets[1][2]) == 21


def test_encrypted_world_stream_subtracts_four_from_server_auth_response_for_srp6():
    def _pack(cmd: int, size: int) -> bytes:
        return struct.pack("<I", (size << 13) | (cmd & 0x1FFF))

    class FakeCrypto:
        def __init__(self):
            self.calls = 0

        def encrypt_send(self, _header: bytes) -> bytes:
            self.calls += 1
            if self.calls == 1:
                return _pack(0x01F6, 124)
            return _pack(0x0C0A, 21)

        def decrypt_recv(self, header: bytes) -> bytes:
            return header

        def unpack_data(self, data: bytes):
            value = struct.unpack("<I", data)[0]
            return SimpleNamespace(cmd=value & 0x1FFF, size=(value & 0xFFFFE000) >> 13)

    stream = EncryptedWorldStream(server_auth_response_size_adjust=-4)
    crypto = FakeCrypto()
    raw_buf = bytearray(b"\x00" * 4 + b"\x11" * 120 + b"\x00" * 4 + b"\x22" * 21)

    packets = stream.feed(raw_buf, crypto=crypto, direction="S")

    assert len(packets) == 2
    assert packets[0][1].cmd == 0x01F6
    assert len(packets[0][2]) == 120
    assert packets[1][1].cmd == 0x0C0A
    assert len(packets[1][2]) == 21



def test_normalize_world_session_key_reverses_legacy_only():
    key = bytes(range(8))

    assert _normalize_world_session_key(PROTOCOL_LEGACY, key) == key[::-1]
    assert _normalize_world_session_key(PROTOCOL_SRP6, key) == key


def test_get_database_connection_reinitializes_cached_database_connection():
    fake_module = ModuleType("server.modules.database.DatabaseConnection")

    class FakeDatabaseConnection:
        initialize_calls = 0

        @staticmethod
        def initialize():
            FakeDatabaseConnection.initialize_calls += 1

    fake_module.DatabaseConnection = FakeDatabaseConnection

    with patch.dict("sys.modules", {"server.modules.database.DatabaseConnection": fake_module}):
        with patch.object(packet_adapters, "_DB_CONNECTION", FakeDatabaseConnection):
            with patch.object(packet_adapters, "_DB_FAILED", False):
                with patch("proxy.packet_adapters.LOGGER.info"):
                    conn = _get_database_connection()

    assert conn is FakeDatabaseConnection
    assert FakeDatabaseConnection.initialize_calls == 1


def test_reset_packet_adapter_runtime_clears_db_failure_and_disposes_connections():
    fake_db_module = ModuleType("server.modules.database.DatabaseConnection")
    fake_auth_module = ModuleType("server.modules.auth.AuthConnection")

    class FakeDatabaseConnection:
        dispose_calls = 0
        reset_calls = 0

        @staticmethod
        def _dispose_existing():
            FakeDatabaseConnection.dispose_calls += 1

        @staticmethod
        def _reset_caches():
            FakeDatabaseConnection.reset_calls += 1

    class FakeAuthConnection:
        dispose_calls = 0

        @staticmethod
        def _dispose_existing():
            FakeAuthConnection.dispose_calls += 1

    fake_db_module.DatabaseConnection = FakeDatabaseConnection
    fake_auth_module.AuthConnection = FakeAuthConnection

    with patch.dict(
        "sys.modules",
        {
            "server.modules.database.DatabaseConnection": fake_db_module,
            "server.modules.auth.AuthConnection": fake_auth_module,
        },
    ):
        with patch.object(packet_adapters, "_DB_CONNECTION", object()):
            with patch.object(packet_adapters, "_DB_FAILED", True):
                with patch("proxy.packet_adapters.LOGGER.info"):
                    reset_packet_adapter_runtime()
                    assert packet_adapters._DB_CONNECTION is None
                    assert packet_adapters._DB_FAILED is False

    assert FakeDatabaseConnection.dispose_calls == 1
    assert FakeDatabaseConnection.reset_calls == 1
    assert FakeAuthConnection.dispose_calls == 1


def test_get_account_row_routes_legacy_queries_to_legacy_session_and_model():
    fake_row = SimpleNamespace(sessionkey="44" * 40)
    captured = {}
    legacy_model = type("AccountLegacy", (), {"username": object()})

    class FakeQuery:
        def __init__(self, model):
            captured["model"] = model

        def filter(self, expr):
            captured["filter"] = expr
            return self

        def first(self):
            return fake_row

    class FakeSession:
        def query(self, model):
            return FakeQuery(model)

    fake_db = SimpleNamespace(auth_legacy=lambda: FakeSession())
    fake_module = ModuleType("server.modules.database.AuthModelLegacy")
    fake_module.AccountLegacy = legacy_model

    with patch.dict("sys.modules", {"server.modules.database.AuthModelLegacy": fake_module}):
        row = get_account_row(fake_db, PROTOCOL_LEGACY, "legacyuser")

    assert row is fake_row
    assert captured["model"] is legacy_model


def test_get_account_row_routes_srp6_queries_to_srp6_session_and_model():
    fake_row = SimpleNamespace(session_key=b"\x55" * 40)
    captured = {}
    srp6_model = type("Account", (), {"username": object()})

    class FakeQuery:
        def __init__(self, model):
            captured["model"] = model

        def filter(self, expr):
            captured["filter"] = expr
            return self

        def first(self):
            return fake_row

    class FakeSession:
        def query(self, model):
            return FakeQuery(model)

    fake_db = SimpleNamespace(auth=lambda: FakeSession())
    fake_module = ModuleType("server.modules.database.AuthModel")
    fake_module.Account = srp6_model

    with patch.dict("sys.modules", {"server.modules.database.AuthModel": fake_module}):
        row = get_account_row(fake_db, PROTOCOL_SRP6, "srpuser")

    assert row is fake_row
    assert captured["model"] is srp6_model


def test_get_account_row_returns_none_for_unknown_protocol():
    fake_db = SimpleNamespace(auth=lambda: None, auth_legacy=lambda: None)

    assert get_account_row(fake_db, "UNKNOWN", "user") is None
