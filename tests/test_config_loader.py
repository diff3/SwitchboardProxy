import unittest
from unittest.mock import patch

from proxy.utils.config_loader import ConfigLoader


class ProxyConfigLoaderTest(unittest.TestCase):
    def test_load_active_config_merges_shared_default_and_state_override(self):
        fake_config = {
            "shared": {
                "buffer_size": 4096,
                "listen_host": "0.0.0.0",
                "database": {
                    "host": "127.0.0.1",
                    "port": 3306,
                    "username": "root",
                    "password": "pwd",
                },
                "logging": {
                    "log_file": "proxy.log",
                    "write_to_log": True,
                },
                "proxy": {"logging": {"mode": "opcode"}},
            },
            "states": {
                "default": {
                    "database": {
                        "auth_db": "auth_default",
                        "world_db": "world_default",
                        "characters_db": "characters_default",
                    },
                    "enable_log": True,
                    "routes": {
                        "auth": {
                            "listen": 3724,
                            "forward": {"host": "127.0.0.1", "port": 3720},
                        },
                        "world": {
                            "listen": 8085,
                            "forward": {"host": "127.0.0.1", "port": 8086},
                        },
                    },
                },
                "skyfire": {
                    "database": {
                        "world_db": "world_skyfire",
                    },
                    "proxy": {"logging": {"mode": "decoded"}},
                    "routes": {
                        "world": {
                            "forward": {"host": "192.168.11.30"},
                        }
                    },
                },
            },
        }

        with patch("proxy.utils.config_loader.DEFAULT_CONFIG", fake_config):
            cfg = ConfigLoader.load_active_config("skyfire")

        self.assertEqual(cfg["buffer_size"], 4096)
        self.assertTrue(cfg["enable_log"])
        self.assertEqual(cfg["database"]["host"], "127.0.0.1")
        self.assertEqual(cfg["database"]["world_db"], "world_skyfire")
        self.assertEqual(cfg["proxy"]["logging"]["mode"], "decoded")
        self.assertEqual(cfg["routes"]["auth"]["forward"]["host"], "127.0.0.1")
        self.assertEqual(cfg["routes"]["world"]["forward"]["host"], "192.168.11.30")
        self.assertEqual(cfg["routes"]["world"]["forward"]["port"], 8086)

    def test_merge_dicts_overrides_nested_values(self):
        merged = ConfigLoader._merge_dicts(
            {"proxy": {"logging": {"mode": "opcode", "show_raw": False}}},
            {"proxy": {"logging": {"show_raw": True}}},
        )
        self.assertEqual(
            merged,
            {"proxy": {"logging": {"mode": "opcode", "show_raw": True}}},
        )

    def test_load_runtime_config_maps_proxy_settings_to_shared_runtime_shape(self):
        fake_config = {
            "shared": {
                "logging": {
                    "write_to_log": False,
                    "log_file": "proxy-custom.log",
                },
                "paths": {
                    "root": ".",
                    "logs": "proxy-logs",
                },
                "database": {
                    "host": "db",
                    "port": 3306,
                    "username": "root",
                    "password": "pwd",
                },
                "proxy": {"phases": {"world": {"mode": "legacy"}}},
            },
            "states": {
                "default": {
                    "database": {
                        "auth_db": "auth_default",
                        "world_db": "world_default",
                        "characters_db": "characters_default",
                    }
                }
            },
        }

        with patch("proxy.utils.config_loader.DEFAULT_CONFIG", fake_config):
            cfg = ConfigLoader.load_runtime_config("default")

        self.assertEqual(cfg["Logging"]["log_file"], "proxy-custom.log")
        self.assertFalse(cfg["Logging"]["write_to_log"])
        self.assertEqual(cfg["paths"]["logs"], "proxy-logs")
        self.assertEqual(cfg["database"]["auth_db"], "auth_default")
        self.assertEqual(cfg["proxy"]["phases"]["world"]["mode"], "legacy")


if __name__ == "__main__":
    unittest.main()
