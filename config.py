# default_config.py
#
# Factory defaults.
# This file must never be modified by runtime code.
#
# Merge order:
#   shared -> default -> selected state
#
# Routes are identified by NAME, not index.
# Each route is independent and explicitly addressed.

CONFIG = {
    "shared": {
        # Infrastructure settings (always applied)
        "buffer_size": 4096,
        "log_file": "logs/proxy.log",
        "listen_host": "0.0.0.0",
        "proxy": {
            "adapters": {
                "opcode_parser": True,
                "decode": False,
                "logging": True,
            },
            "logging": {
                "mode": "opcode",
                "raw_format": "hex",
                "show_opcode": True,
                "show_decoded": False,
                "show_raw": False,
                "show_raw_if_undecoded": True,
                "max_raw_bytes": 256,
            },
            "filter": {
                "whitelist": [],
                "blacklist": [],
            },
            "capture": {
                "dump": False,
                "focus": [],
            },
            "phases": {
                "auth": {},
                "world": {},
            },
            "routes": {
            },
        },
    },

    "states": {
        # Baseline state
        "default": {
            "enable_log": True,
            "enable_view": True,
            "enable_decode": True,

            "routes": {
                "auth": {
                    "listen": 3724,
                    "forward": {
                        "host": "127.0.0.1",
                        "port": 3720,
                    },
                },
                "world": {
                    "listen": 8085,
                    "forward": {
                        "host": "127.0.0.1",
                        "port": 8086,
                    },
                },
            },
        },

        # Skyfire state
        # Overrides are applied per route name.
        # Missing keys are inherited from the default state.
        "skyfire": {
            "routes": {
                "auth": {
                    "forward": {
                        "host": "192.168.11.30",
                    },
                },
                "world": {
                    "forward": {
                        "host": "192.168.11.30",
                         "port": 8086,
                    },
                },
            },
        },
    },
}
