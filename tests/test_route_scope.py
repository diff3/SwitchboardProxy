import unittest

from proxy.utils.route_scope import merge_dicts, route_phase, scoped_proxy_config


class RouteScopeTest(unittest.TestCase):
    def test_route_phase_prefers_explicit_phase(self):
        self.assertEqual(route_phase("world_1", {"phase": "auth"}), "auth")
        self.assertEqual(route_phase("auth_1", {"type": "world"}), "world")

    def test_route_phase_falls_back_to_name_heuristics(self):
        self.assertEqual(route_phase("world_1"), "world")
        self.assertEqual(route_phase("auth-main"), "auth")
        self.assertEqual(route_phase("other"), "")

    def test_merge_dicts_merges_nested_values(self):
        base = {"logging": {"mode": "opcode", "show_raw": False}}
        override = {"logging": {"show_raw": True}, "capture": {"dump": True}}
        self.assertEqual(
            merge_dicts(base, override),
            {
                "logging": {"mode": "opcode", "show_raw": True},
                "capture": {"dump": True},
            },
        )

    def test_scoped_proxy_config_applies_global_then_phase_then_route(self):
        proxy_cfg = {
            "logging": {"mode": "opcode", "show_raw": False},
            "capture": {"dump": False},
            "phases": {
                "world": {
                    "logging": {"mode": "decoded"},
                    "capture": {"dump": True},
                }
            },
            "routes": {
                "world_1": {
                    "logging": {"mode": "bytes", "show_raw": True},
                }
            },
        }

        scoped = scoped_proxy_config(proxy_cfg, phase="world", route_name="world_1")

        self.assertEqual(scoped["logging"]["mode"], "bytes")
        self.assertTrue(scoped["logging"]["show_raw"])
        self.assertTrue(scoped["capture"]["dump"])

    def test_scoped_proxy_config_keeps_legacy_phase_override(self):
        proxy_cfg = {
            "logging": {"mode": "opcode"},
            "routes": {
                "auth": {"logging": {"mode": "raw"}},
            },
        }

        scoped = scoped_proxy_config(proxy_cfg, phase="auth")
        self.assertEqual(scoped["logging"]["mode"], "raw")


if __name__ == "__main__":
    unittest.main()
