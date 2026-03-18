import unittest
from types import SimpleNamespace
from unittest.mock import patch

from proxy.packet_adapters import LoggingAdapter


def _state(*, route_name="world_1", phase="world", proxy=None):
    return SimpleNamespace(
        conn_id=7,
        route_name=route_name,
        phase=phase,
        proxy=proxy
        or {
            "adapters": {"logging": True},
            "logging": {
                "mode": "opcode",
                "raw_format": "hex",
                "show_opcode": True,
                "show_decoded": False,
                "show_raw": False,
                "show_raw_if_undecoded": True,
                "max_raw_bytes": 256,
            },
            "filter": {"whitelist": [], "blacklist": []},
            "phases": {},
            "routes": {},
        },
    )


class LoggingAdapterTest(unittest.TestCase):
    def test_whitelist_overrides_blacklist(self):
        adapter = LoggingAdapter()
        self.assertTrue(
            adapter._is_visible(
                "MSG_MOVE_FALL_LAND",
                {"MSG_MOVE_FALL_LAND"},
                {"MSG_MOVE_FALL_LAND"},
            )
        )

    def test_auto_mode_falls_back_to_raw_when_decoded_missing(self):
        adapter = LoggingAdapter()
        show_opcode, show_decoded, show_raw, raw_format = adapter._resolve_logging_flags(
            mode="auto",
            show_opcode=True,
            show_decoded=False,
            show_raw=False,
            show_raw_if_undecoded=True,
            raw_format="hex",
            decoded=None,
        )
        self.assertTrue(show_opcode)
        self.assertFalse(show_decoded)
        self.assertTrue(show_raw)
        self.assertEqual(raw_format, "hex")

    def test_packet_raw_bytes_excludes_header(self):
        adapter = LoggingAdapter()
        packet = {"header": b"\xAA\xBB\xCC\xDD", "payload": b"\x11\x22"}
        self.assertEqual(adapter._packet_raw_bytes(packet), b"\x11\x22")

    def test_logging_adapter_logs_world_packet_with_decoded_payload(self):
        adapter = LoggingAdapter()
        state = _state(
            proxy={
                "adapters": {"logging": True},
                "logging": {
                    "mode": "decoded",
                    "raw_format": "hex",
                    "show_opcode": True,
                    "show_decoded": True,
                    "show_raw": False,
                    "show_raw_if_undecoded": True,
                    "max_raw_bytes": 256,
                },
                "filter": {"whitelist": [], "blacklist": []},
                "phases": {},
                "routes": {},
            }
        )
        packets = [
            {
                "direction": "C",
                "opcode": 0x1234,
                "opcode_name": "MSG_MOVE_FALL_LAND",
                "payload": b"\x01\x02",
                "decoded": {"x": 1, "y": 2},
                "encrypted": True,
            }
        ]

        with patch("proxy.packet_adapters.LOGGER.info") as log_info:
            adapter(state, packets, "IN ---> OUT")

        rendered = log_info.call_args[0][0]
        self.assertIn("[WorldProxy]", rendered)
        self.assertIn("C→S MSG_MOVE_FALL_LAND", rendered)
        self.assertIn("encrypted=True", rendered)
        self.assertIn('decoded={"x": 1, "y": 2}', rendered)

    def test_logging_adapter_hides_blacklisted_packet(self):
        adapter = LoggingAdapter()
        state = _state(
            proxy={
                "adapters": {"logging": True},
                "logging": {
                    "mode": "opcode",
                    "raw_format": "hex",
                    "show_opcode": True,
                    "show_decoded": False,
                    "show_raw": False,
                    "show_raw_if_undecoded": True,
                    "max_raw_bytes": 256,
                },
                "filter": {"whitelist": [], "blacklist": ["MSG_MOVE_HEARTBEAT"]},
                "phases": {},
                "routes": {},
            }
        )
        packets = [
            {
                "direction": "C",
                "opcode_name": "MSG_MOVE_HEARTBEAT",
                "opcode": 1,
                "payload": b"\x00",
                "decoded": None,
                "encrypted": False,
            }
        ]

        with patch("proxy.packet_adapters.LOGGER.info") as log_info:
            adapter(state, packets, "IN ---> OUT")

        log_info.assert_not_called()


if __name__ == "__main__":
    unittest.main()
