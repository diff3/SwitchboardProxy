from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import proxy.cli.commands as commands
from proxy.state import ProxyState


class CliStateCommandsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._config_backup = deepcopy(commands.DEFAULT_CONFIG)
        self._tmpdir = tempfile.TemporaryDirectory()
        self._config_path = Path(self._tmpdir.name) / "proxy.json"
        self._config_path.write_text(
            json.dumps(self._config_backup, indent=2),
            encoding="utf-8",
        )

        self._config_patch = patch.object(commands, "_CONFIG_PATH", self._config_path)
        self._persist_patch = patch.object(commands, "_persist_runtime_state", lambda state: None)
        self._config_patch.start()
        self._persist_patch.start()

        commands._sync_default_config(json.loads(self._config_path.read_text(encoding="utf-8")))

    def tearDown(self) -> None:
        self._persist_patch.stop()
        self._config_patch.stop()
        commands._sync_default_config(self._config_backup)
        self._tmpdir.cleanup()

    def _read_config(self) -> dict:
        return json.loads(self._config_path.read_text(encoding="utf-8"))

    def test_state_create_uses_active_runtime_snapshot(self) -> None:
        state = ProxyState.from_active_config("pandaria")
        state.active_state = "pandaria"
        state.routes["world"]["listen"] = 9011
        state.enable_decode = True

        result = commands.cmd_state_create(state, ["lab"])

        cfg = self._read_config()
        self.assertEqual(result, ["created state 'lab' from 'pandaria'"])
        self.assertEqual(cfg["states"]["lab"]["routes"]["world"]["listen"], 9011)
        self.assertTrue(cfg["states"]["lab"]["enable_decode"])
        self.assertEqual(cfg["states"]["lab"]["database"]["auth_db"], "pandaria548_auth")

    def test_state_clone_copies_existing_state(self) -> None:
        state = ProxyState.from_active_config("default")

        result = commands.cmd_state_clone(state, ["pandaria", "pandaria_copy"])

        cfg = self._read_config()
        self.assertEqual(result, ["cloned state 'pandaria' -> 'pandaria_copy'"])
        self.assertEqual(cfg["states"]["pandaria_copy"], cfg["states"]["pandaria"])

    def test_state_rename_updates_active_state(self) -> None:
        state = ProxyState.from_active_config("pandaria")
        state.active_state = "pandaria"

        result = commands.cmd_state_rename(state, ["pandaria", "pandaria_live"])

        cfg = self._read_config()
        self.assertEqual(result, ["renamed state 'pandaria' -> 'pandaria_live'"])
        self.assertEqual(state.active_state, "pandaria_live")
        self.assertIn("pandaria_live", cfg["states"])
        self.assertNotIn("pandaria", cfg["states"])

    def test_state_rm_protects_default_and_removes_inactive_state(self) -> None:
        state = ProxyState.from_active_config("default")

        protected = commands.cmd_state_rm(state, ["default"])
        removed = commands.cmd_state_rm(state, ["pandaria"])

        cfg = self._read_config()
        self.assertEqual(protected, ["cannot remove default state"])
        self.assertEqual(removed, ["removed state 'pandaria'"])
        self.assertNotIn("pandaria", cfg["states"])

    def test_state_set_mode_and_db_set_update_runtime_and_config(self) -> None:
        state = ProxyState.from_active_config("default")
        state.active_state = "default"

        set_flag = commands.cmd_state_set(state, ["enable_decode", "on"])
        set_mode = commands.cmd_state_mode(state, ["legacy"])
        set_db = commands.cmd_state_db_set(state, ["auth_db", "custom_auth"])

        cfg = self._read_config()
        self.assertEqual(set_flag, ["default enable_decode = True"])
        self.assertEqual(set_mode, ["default world mode = legacy", "run 'reload' to apply protocol mode changes"])
        self.assertEqual(set_db, ["default database.auth_db = custom_auth", "run 'reload' to apply database changes"])

        self.assertTrue(state.enable_decode)
        self.assertEqual(state.proxy["phases"]["world"]["mode"], "legacy")
        self.assertTrue(cfg["states"]["default"]["enable_decode"])
        self.assertEqual(cfg["states"]["default"]["proxy"]["phases"]["world"]["mode"], "legacy")
        self.assertEqual(cfg["states"]["default"]["database"]["auth_db"], "custom_auth")

    def test_state_show_and_db_show_can_read_inactive_state(self) -> None:
        state = ProxyState.from_active_config("default")
        state.active_state = "default"

        show_lines = commands.cmd_state_show(state, ["pandaria"])
        db_lines = commands.cmd_state_db_show(state, ["pandaria"])

        self.assertIn("state         = pandaria", show_lines)
        self.assertIn("world_mode   = legacy", show_lines)
        self.assertIn("auth_db      = pandaria548_auth", show_lines)
        self.assertIn("state db (pandaria):", db_lines)
        self.assertIn(" - world_db = pandaria548_world", db_lines)

    def test_status_includes_active_state_mode_and_databases(self) -> None:
        state = ProxyState.from_active_config("pandaria")
        state.active_state = "pandaria"

        lines = commands.cmd_status(state, [])

        self.assertIn("state         = pandaria", lines)
        self.assertIn("world_mode    = legacy", lines)
        self.assertIn("auth_db       = pandaria548_auth", lines)


if __name__ == "__main__":
    unittest.main()
