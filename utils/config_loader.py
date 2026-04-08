# utils/config_loader.py

from copy import deepcopy
from proxy.config import CONFIG as DEFAULT_CONFIG
from shared.ConfigLoader import ConfigLoader as SharedConfigLoader


class ConfigLoader:
    @staticmethod
    def load_active_config(state_name: str) -> dict:
        base = deepcopy(DEFAULT_CONFIG["shared"])
        default = DEFAULT_CONFIG["states"]["default"]
        override = DEFAULT_CONFIG["states"].get(state_name, {})

        cfg = ConfigLoader._merge_dicts(base, default)

        # routes need deep merge by name
        routes = deepcopy(default.get("routes", {}))

        for name, route in override.get("routes", {}).items():
            routes[name] = ConfigLoader._merge_dicts(
                routes.get(name, {}),
                route,
            )

        cfg["routes"] = routes

        # merge other top-level overrides (if any later)
        for key, value in override.items():
            if key != "routes":
                if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                    cfg[key] = ConfigLoader._merge_dicts(cfg[key], value)
                else:
                    cfg[key] = value

        return cfg

    @staticmethod
    def _merge_dicts(base: dict, override: dict) -> dict:
        result = deepcopy(base)
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(result.get(k), dict):
                result[k] = ConfigLoader._merge_dicts(result[k], v)
            else:
                result[k] = v

        return result

    @staticmethod
    def _logging_defaults(cfg: dict) -> dict:
        logging_cfg = deepcopy(cfg.get("logging", {}))
        return {
            "write_to_log": bool(logging_cfg.get("write_to_log", True)),
            "log_file": str(logging_cfg.get("log_file", "proxy.log") or "proxy.log"),
            "logging_levels": str(logging_cfg.get("logging_levels", "All") or "All"),
            "logging_file_levels": str(
                logging_cfg.get("logging_file_levels", "All") or "All"
            ),
            "show_scope": bool(logging_cfg.get("show_scope", False)),
            "date_format": str(
                logging_cfg.get("date_format", " [%Y-%m-%d %H:%M:%S]")
                or " [%Y-%m-%d %H:%M:%S]"
            ),
        }

    @staticmethod
    def _path_defaults(cfg: dict) -> dict:
        paths_cfg = deepcopy(cfg.get("paths", {}))
        return {
            "root": str(paths_cfg.get("root", ".") or "."),
            "def_dir": str(paths_cfg.get("def_dir", "data/def") or "data/def"),
            "capture_dir": str(paths_cfg.get("capture_dir", "data/captures") or "data/captures"),
            "logs": str(paths_cfg.get("logs", "logs") or "logs"),
            "json_dir": str(paths_cfg.get("json_dir", "data/json") or "data/json"),
            "debug_dir": str(paths_cfg.get("debug_dir", "data/debug") or "data/debug"),
        }

    @staticmethod
    def load_runtime_config(state_name: str) -> dict:
        cfg = deepcopy(ConfigLoader.load_active_config(state_name))
        cfg["paths"] = ConfigLoader._path_defaults(cfg)
        cfg["Logging"] = ConfigLoader._logging_defaults(cfg)
        return cfg

    @staticmethod
    def install_shared_runtime_config(state_name: str) -> dict:
        runtime_cfg = ConfigLoader.load_runtime_config(state_name)
        SharedConfigLoader.set_runtime_config(runtime_cfg)
        return runtime_cfg
