from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from proxy.state import ProxyState, load_state, save_state


class ProxyStatePersistenceTest(unittest.TestCase):
    def test_to_dict_roundtrip_preserves_serializable_runtime_state(self) -> None:
        state = ProxyState.from_active_config("default")
        state.active_state = "skyfire"
        state.enable_log = False
        state.enable_view = False
        state.enable_decode = True
        state.routes["world"]["listen"] = 9999
        state.proxy.setdefault("logging", {})["show_raw"] = True

        restored = ProxyState.from_dict(state.to_dict())

        self.assertEqual(restored.active_state, "skyfire")
        self.assertFalse(restored.enable_log)
        self.assertFalse(restored.enable_view)
        self.assertTrue(restored.enable_decode)
        self.assertEqual(restored.routes["world"]["listen"], 9999)
        self.assertTrue(restored.proxy["logging"]["show_raw"])
        self.assertFalse(restored.shutdown)
        self.assertFalse(restored.reload_requested)
        self.assertEqual(restored.reload_epoch, 0)

    def test_from_dict_ignores_unknown_fields_and_uses_config_defaults_for_missing(self) -> None:
        restored = ProxyState.from_dict(
            {
                "active_state": "default",
                "enable_log": False,
                "unknown_field": "ignored",
            }
        )

        default_state = ProxyState.from_active_config("default")

        self.assertEqual(restored.active_state, "default")
        self.assertFalse(restored.enable_log)
        self.assertEqual(restored.routes, default_state.routes)
        self.assertEqual(restored.proxy, default_state.proxy)

    def test_load_state_missing_file_falls_back_to_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "missing.json"

            state = load_state(path)

            self.assertEqual(state.active_state, "default")
            self.assertIsInstance(state.routes, dict)
            self.assertIsInstance(state.proxy, dict)

    def test_load_state_corrupt_file_falls_back_to_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "proxy.state.json"
            path.write_text("{not-json", encoding="utf-8")

            state = load_state(path)

            self.assertEqual(state.active_state, "default")
            self.assertIsInstance(state.routes, dict)
            self.assertIsInstance(state.proxy, dict)

    def test_save_state_and_load_state_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "proxy.state.json"
            state = ProxyState.from_active_config("default")
            state.active_state = "pandaria"
            state.enable_decode = True
            state.proxy.setdefault("capture", {})["dump"] = True

            saved = save_state(state, path)
            restored = load_state(path)

            self.assertTrue(saved)
            self.assertTrue(path.exists())

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["active_state"], "pandaria")
            self.assertTrue(payload["enable_decode"])
            self.assertTrue(payload["proxy"]["capture"]["dump"])

            self.assertEqual(restored.active_state, "pandaria")
            self.assertTrue(restored.enable_decode)
            self.assertTrue(restored.proxy["capture"]["dump"])


if __name__ == "__main__":
    unittest.main()
