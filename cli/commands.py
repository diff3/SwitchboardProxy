# cli/commands.py
from __future__ import annotations

from copy import deepcopy
import json
import re
from pathlib import Path

from proxy.cli.core import ArgSpec, CommandNode, ParseContext, register_arg_type
from proxy.config import CONFIG as DEFAULT_CONFIG, _CONFIG_PATH
from proxy.utils.config_loader import ConfigLoader
from proxy.utils.route_scope import route_phase, scoped_proxy_config
from shared.Logger import Logger
from shared.PathUtils import (
    get_captures_root,
    get_debug_root,
    get_def_root,
    get_json_root,
    normalize_capture_profile_name,
)


_PROXY_SETTING_TYPES = {
    "adapters.opcode_parser": bool,
    "adapters.decode": bool,
    "adapters.logging": bool,
    "logging.mode": str,
    "logging.raw_format": str,
    "logging.show_opcode": bool,
    "logging.show_decoded": bool,
    "logging.show_raw": bool,
    "logging.show_raw_if_undecoded": bool,
    "logging.max_raw_bytes": int,
    "capture.dump": bool,
    "capture.profile": str,
    "capture.focus": list,
    "filter.whitelist": list,
    "filter.blacklist": list,
}

_PROXY_SETTING_CHOICES = {
    "logging.mode": {"opcode", "decoded", "raw", "hex", "bytes", "auto"},
    "logging.raw_format": {"hex", "bytes"},
}
_PROXY_PHASES = {"auth", "world"}
_PROTOCOL_VIEW_TYPES = {"def", "debug", "json"}
_ROUTE_SETTING_TYPES = {
    "listen": int,
    "forward.host": str,
    "forward.port": int,
}


def _proxy_config(state) -> dict:
    proxy_cfg = getattr(state, "proxy", None)
    if proxy_cfg is None:
        proxy_cfg = {}
        state.proxy = proxy_cfg
    return proxy_cfg


def _active_state_name(state) -> str:
    return str(getattr(state, "active_state", "default") or "default")


def _active_config(state) -> dict:
    return ConfigLoader.load_active_config(_active_state_name(state))


def _runtime_state_snapshot(state) -> dict:
    snapshot = {
        "routes": deepcopy(getattr(state, "routes", {})),
        "proxy": deepcopy(_proxy_config(state)),
    }
    for key in ("enable_log", "enable_view", "enable_decode"):
        if hasattr(state, key):
            snapshot[key] = getattr(state, key)
    return snapshot


def _proxy_log_file() -> str:
    return str(DEFAULT_CONFIG.get("log_file", "proxy.log") or "proxy.log")


def _sync_default_config(config_data: dict) -> None:
    DEFAULT_CONFIG.clear()
    DEFAULT_CONFIG.update(config_data)


def _proxy_scope_and_path(args):
    if not args:
        return "global", None, None
    if args[0] == "route":
        route_name = args[1] if len(args) > 1 else None
        path = args[2] if len(args) > 2 else None
        return "route", route_name, path
    if args[0] in _PROXY_PHASES:
        phase = args[0]
        path = args[1] if len(args) > 1 else None
        return "phase", phase, path
    return "global", None, args[0]


def _proxy_scope_label(scope: str, name: str | None) -> str:
    if scope == "phase" and name:
        return f"{name} "
    if scope == "route" and name:
        return f"route {name} "
    return ""


def _proxy_scope_config(state, scope: str, name: str | None) -> dict:
    proxy_cfg = _proxy_config(state)
    if scope == "global":
        return proxy_cfg
    if scope == "phase":
        phases_cfg = proxy_cfg.setdefault("phases", {})
        phase_cfg = phases_cfg.get(name)
        if not isinstance(phase_cfg, dict):
            phase_cfg = {}
            phases_cfg[name] = phase_cfg
        return phase_cfg
    routes_cfg = proxy_cfg.setdefault("routes", {})
    route_cfg = routes_cfg.get(name)
    if not isinstance(route_cfg, dict):
        route_cfg = {}
        routes_cfg[name] = route_cfg
    return route_cfg


def _default_proxy_scope_config(state, scope: str, name: str | None) -> dict:
    proxy_cfg = deepcopy(_active_config(state).get("proxy", {}))
    if scope == "global":
        return proxy_cfg
    if scope == "phase":
        phases_cfg = proxy_cfg.get("phases", {})
        value = phases_cfg.get(name, {})
        return deepcopy(value) if isinstance(value, dict) else {}
    routes_cfg = proxy_cfg.get("routes", {})
    value = routes_cfg.get(name, {})
    return deepcopy(value) if isinstance(value, dict) else {}


def _scope_args(args: list[str]) -> tuple[str, str | None, list[str]]:
    if not args:
        return "global", None, []
    if args[0] == "route":
        route_name = args[1] if len(args) > 1 else None
        return "route", route_name, args[2:]
    if args[0] in _PROXY_PHASES:
        return "phase", args[0], args[1:]
    return "global", None, args


def _scope_display_name(scope: str, name: str | None) -> str:
    if scope == "phase" and name:
        return name
    if scope == "route" and name:
        return f"route {name}"
    return "global"


def _normalize_name_list(values) -> list[str]:
    names = []
    for value in values or []:
        name = str(value).strip().upper()
        if name and name not in names:
            names.append(name)
    return names


def _route_exists(state, route_name: str | None) -> bool:
    return bool(route_name) and route_name in getattr(state, "routes", {})


def _effective_scope_proxy_config(state, scope: str, name: str | None) -> dict:
    proxy_cfg = _proxy_config(state)
    if scope == "global":
        return deepcopy(proxy_cfg)
    if scope == "phase":
        return scoped_proxy_config(proxy_cfg, phase=name)
    route_cfg = getattr(state, "routes", {}).get(name, {})
    phase = route_phase(name, route_cfg)
    return scoped_proxy_config(proxy_cfg, phase=phase, route_name=name)


def _joined_names(values) -> str:
    items = _normalize_name_list(values)
    return ",".join(items) if items else "<empty>"


def _capture_focus_list(state, scope: str, name: str | None) -> list[str]:
    try:
        values = _get_nested_value(_proxy_scope_config(state, scope, name), "capture.focus")
    except KeyError:
        return []
    return _normalize_name_list(values if isinstance(values, list) else [])


def _parse_opcode_names(raw: str) -> list[str]:
    normalized = str(raw or "").strip()
    if not normalized:
        return []
    return _normalize_name_list(item for item in normalized.split(","))


def _protocol_cases() -> list[str]:
    names: set[str] = set()
    for path in (get_def_root(), get_json_root(), get_debug_root()):
        if not path.exists():
            continue
        for entry in path.iterdir():
            if not entry.is_file():
                continue
            if entry.suffix not in {".def", ".json"}:
                continue
            names.add(entry.stem)
    return sorted(names)


def _protocol_view_path(view_type: str, case_name: str) -> Path:
    case_name = _normalize_capture_case_name(case_name)
    if view_type == "def":
        return get_def_root() / f"{case_name}.def"
    if view_type == "json":
        return get_json_root() / f"{case_name}.json"
    return get_debug_root() / f"{case_name}.json"


def _format_status_line(label: str, cfg: dict) -> str:
    adapters_cfg = cfg.get("adapters") or {}
    logging_cfg = cfg.get("logging") or {}
    capture_cfg = cfg.get("capture") or {}
    filter_cfg = cfg.get("filter") or {}
    focus = _normalize_name_list(capture_cfg.get("focus", []))
    whitelist = _normalize_name_list(filter_cfg.get("whitelist", []))
    blacklist = _normalize_name_list(filter_cfg.get("blacklist", []))
    capture_profile = str(capture_cfg.get("profile") or "").strip() or "default"
    return (
        f"{label}: "
        f"parser={'on' if adapters_cfg.get('opcode_parser', False) else 'off'} "
        f"decode={'on' if adapters_cfg.get('decode', False) else 'off'} "
        f"log={'on' if adapters_cfg.get('logging', False) else 'off'} "
        f"mode={logging_cfg.get('mode', 'opcode')} "
        f"raw={'on' if logging_cfg.get('show_raw', False) else 'off'} "
        f"decoded={'on' if logging_cfg.get('show_decoded', False) else 'off'} "
        f"dump={'on' if capture_cfg.get('dump', False) else 'off'} "
        f"profile={capture_profile} "
        f"focus={len(focus)} "
        f"whitelist={len(whitelist)} "
        f"blacklist={len(blacklist)}"
    )


def _get_nested_value(data: dict, path: str):
    current = data
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            raise KeyError(path)
        current = current[key]
    return current


def _set_nested_value(data: dict, path: str, value):
    keys = path.split(".")
    current = data
    for key in keys[:-1]:
        current = current.setdefault(key, {})
    current[keys[-1]] = value


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "on", "yes", "y"}:
        return True
    if normalized in {"0", "false", "off", "no", "n"}:
        return False
    raise ValueError("expected boolean: on/off, true/false, yes/no, 1/0")


def _parse_proxy_value(path: str, raw: str):
    value_type = _PROXY_SETTING_TYPES[path]
    if value_type is bool:
        value = _parse_bool(raw)
    elif value_type is int:
        value = int(raw, 10)
    elif path == "capture.profile":
        value = normalize_capture_profile_name(raw) or ""
    elif value_type is list:
        normalized = raw.strip()
        if normalized.lower() in {"none", "off", "clear", "-"}:
            value = []
        else:
            value = [
                item.strip().upper()
                for item in normalized.split(",")
                if item.strip()
            ]
    else:
        value = str(raw).strip().lower()

    allowed = _PROXY_SETTING_CHOICES.get(path)
    if allowed and value not in allowed:
        raise ValueError(f"allowed values: {', '.join(sorted(allowed))}")

    return value


def _parse_proxy_target_args(args: list[str], *, require_value: bool):
    min_args = 2 if require_value else 1
    if len(args) < min_args:
        raise ValueError

    scope = "global"
    scope_name = None
    path_index = 0

    if args[0] == "route":
        min_route_args = 4 if require_value else 3
        if len(args) < min_route_args:
            raise ValueError
        scope = "route"
        scope_name = args[1]
        path_index = 2
    elif args[0] in _PROXY_PHASES:
        min_phase_args = 3 if require_value else 2
        if len(args) < min_phase_args:
            raise ValueError
        scope = "phase"
        scope_name = args[0]
        path_index = 1

    path = args[path_index]
    raw_value = " ".join(args[path_index + 1:]) if require_value else None
    return scope, scope_name, path, raw_value


def _proxy_list_value(state, scope: str, scope_name: str | None, path: str) -> list[str]:
    try:
        current = _get_nested_value(_proxy_scope_config(state, scope, scope_name), path)
    except KeyError:
        return []
    return _normalize_name_list(current if isinstance(current, list) else [])


def _is_route(token: str, _parsed_args: dict[str, object]) -> bool:
    return token in _PROXY_PHASES


def _is_proxy_scope(token: str, _parsed_args: dict[str, object]) -> bool:
    return token in _PROXY_PHASES or token == "route"


def _is_route_name(token: str, parsed_args: dict[str, object]) -> bool:
    return parsed_args.get("scope") == "route" and bool(str(token).strip())


register_arg_type("route", accepts=_is_route)
register_arg_type("proxy_scope", accepts=_is_proxy_scope)
register_arg_type("route_name", accepts=_is_route_name)
register_arg_type("state_name")
register_arg_type("proxy_setting")
register_arg_type("proxy_value")
register_arg_type("bool")
register_arg_type("command_path")
register_arg_type("capture_name")
register_arg_type("promoted_case")
register_arg_type("protocol_view_type")
register_arg_type("route_config_name")
register_arg_type("route_setting")
register_arg_type("route_value")


_FOCUS_CAPTURE_SUFFIX_RE = re.compile(r"_(\d+)_(\d{4})$")


def _capture_debug_dirs() -> list[Path]:
    return _capture_debug_dirs_for_profile(None)


def _capture_json_dirs() -> list[Path]:
    return _capture_json_dirs_for_profile(None)


def _active_capture_profile(state) -> str | None:
    capture_cfg = (_proxy_scope_config(state, "global", None).get("capture") or {})
    try:
        return normalize_capture_profile_name(capture_cfg.get("profile"))
    except Exception:
        return None


def _capture_debug_dirs_for_profile(profile: str | None) -> list[Path]:
    return [
        get_captures_root(profile=profile) / "debug",
        get_captures_root(profile=profile, focus=True) / "debug",
    ]


def _capture_json_dirs_for_profile(profile: str | None) -> list[Path]:
    return [
        get_captures_root(profile=profile) / "json",
        get_captures_root(profile=profile, focus=True) / "json",
    ]


def _capture_file_candidates(name: str, *, profile: str | None = None) -> list[Path]:
    raw = str(name or "").strip()
    if not raw:
        return []
    filename = raw if raw.endswith(".json") else f"{raw}.json"
    candidates: list[Path] = []
    for directory in _capture_debug_dirs_for_profile(profile):
        candidates.append(directory / filename)
    return candidates


def _resolve_capture_debug_file(name: str, *, profile: str | None = None) -> Path | None:
    for candidate in _capture_file_candidates(name, profile=profile):
        if candidate.exists():
            return candidate
    return None


def _normalize_capture_case_name(name: str) -> str:
    stem = Path(str(name)).stem
    return _FOCUS_CAPTURE_SUFFIX_RE.sub("", stem)


def _promoted_paths(case_name: str) -> tuple[Path, Path, Path]:
    base = _normalize_capture_case_name(case_name)
    return (
        get_def_root() / f"{base}.def",
        get_json_root() / f"{base}.json",
        get_debug_root() / f"{base}.json",
    )


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _route_config(state, route_name: str) -> dict | None:
    routes = getattr(state, "routes", {})
    if not isinstance(routes, dict):
        return None
    route = routes.get(route_name)
    return route if isinstance(route, dict) else None


def _parse_route_value(path: str, raw: str):
    value_type = _ROUTE_SETTING_TYPES[path]
    if value_type is int:
        return int(str(raw).strip(), 10)
    return str(raw).strip()


def cmd_exit(state, args):
    return "__exit__", None


def cmd_clear(state, args):
    return "\x1b[2J\x1b[H", None


def cmd_help(state, args):
    return "__help__", args


def cmd_routes_show(state, args):
    lines = []
    for name, route in state.routes.items():
        lines.append(
            f"{name}: "
            f"{route['listen']} -> "
            f"{route['forward']['host']}:{route['forward']['port']}"
        )
    return lines


def cmd_route_show(state, args):
    if not args:
        return ["usage: route show <name> [listen|forward.host|forward.port]"]

    route_name = args[0]
    route = _route_config(state, route_name)
    if route is None:
        return [f"unknown route: {route_name}"]

    if len(args) == 1:
        return [
            f"route {route_name}:",
            f" - listen = {route.get('listen')}",
            f" - forward.host = {((route.get('forward') or {}).get('host', ''))}",
            f" - forward.port = {((route.get('forward') or {}).get('port', ''))}",
        ]

    if len(args) != 2:
        return ["usage: route show <name> [listen|forward.host|forward.port]"]

    path = args[1]
    if path not in _ROUTE_SETTING_TYPES:
        return [f"unknown route setting: {path}"]

    try:
        value = _get_nested_value(route, path)
    except KeyError:
        return [f"route {route_name} {path} = <unset>"]
    return [f"route {route_name} {path} = {value}"]


def cmd_route_set(state, args):
    if len(args) < 3:
        return ["usage: route set <name> <listen|forward.host|forward.port> <value>"]

    route_name = args[0]
    path = args[1]
    raw_value = " ".join(args[2:])

    route = _route_config(state, route_name)
    if route is None:
        return [f"unknown route: {route_name}"]
    if path not in _ROUTE_SETTING_TYPES:
        return [f"unknown route setting: {path}"]

    try:
        value = _parse_route_value(path, raw_value)
    except Exception as exc:
        return [f"invalid value for {path}: {exc}"]

    _set_nested_value(route, path, value)
    return [f"route {route_name} {path} = {value}", "run 'reload' to apply listener changes"]


def cmd_state_list(state, args):
    states = DEFAULT_CONFIG.get("states", {})

    if not states:
        return ["No states defined"]

    return ["states:"] + [f" - {name}" for name in sorted(states)]


def cmd_state_use(state, args):
    if not args:
        return ["usage: state use <name>"]

    name = args[0]

    try:
        cfg = ConfigLoader.load_active_config(name)
    except Exception:
        return [f"unknown state: {name}"]

    state.routes.clear()
    state.routes.update(cfg["routes"])
    state.proxy.clear()
    state.proxy.update(deepcopy(cfg.get("proxy", {})))
    state.active_state = name

    for key in ("enable_log", "enable_view", "enable_decode"):
        if key in cfg:
            setattr(state, key, cfg[key])

    return [f"state switched to '{name}'"]


def cmd_state_show(state, args):
    lines = [
        f"active_state  = {_active_state_name(state)}",
        f"shutdown     = {state.shutdown}",
    ]

    for name in ("enable_log", "enable_view"):
        if hasattr(state, name):
            lines.append(f"{name:12} = {getattr(state, name)}")

    return lines


def cmd_default(state, args):
    if args:
        return ["usage: default"]
    return cmd_state_use(state, ["default"])


def cmd_status(state, args):
    scope, name, rest = _scope_args(args)
    if scope == "route" and not name:
        return ["usage: status [auth|world|route <name>]"]
    if rest:
        return ["usage: status [auth|world|route <name>]"]
    if scope == "route" and not _route_exists(state, name):
        return [f"unknown route: {name}"]

    lines = [
        f"state         = {_active_state_name(state)}",
        f"routes        = {','.join(sorted(getattr(state, 'routes', {})))}",
    ]

    if scope == "global":
        lines.append(_format_status_line("global", _effective_scope_proxy_config(state, "global", None)))
        for phase in sorted(_PROXY_PHASES):
            lines.append(_format_status_line(phase, _effective_scope_proxy_config(state, "phase", phase)))
        for route_name in sorted(getattr(state, "routes", {})):
            lines.append(
                _format_status_line(
                    f"route {route_name}",
                    _effective_scope_proxy_config(state, "route", route_name),
                )
            )
        return lines

    label = _scope_display_name(scope, name)
    cfg = _effective_scope_proxy_config(state, scope, name)
    lines = [f"status ({label}):", _format_status_line(label, cfg)]
    lines.append(f"focus        = {_joined_names((cfg.get('capture') or {}).get('focus', []))}")
    lines.append(f"whitelist    = {_joined_names((cfg.get('filter') or {}).get('whitelist', []))}")
    lines.append(f"blacklist    = {_joined_names((cfg.get('filter') or {}).get('blacklist', []))}")
    return lines


def cmd_proxy_show(state, args):
    scope, name, path = _proxy_scope_and_path(args)
    if scope == "route" and not name:
        return ["usage: proxy show [auth|world|route <name>] [path]"]
    proxy_cfg = _proxy_scope_config(state, scope, name)
    paths = sorted(_PROXY_SETTING_TYPES.keys())
    scope_label = _proxy_scope_label(scope, name)

    if path:
        if path not in _PROXY_SETTING_TYPES:
            return [f"unknown proxy setting: {path}"]
        try:
            value = _get_nested_value(proxy_cfg, path)
        except KeyError:
            return [f"{scope_label}{path} = <unset>"]
        if isinstance(value, list):
            value = ",".join(value)
        elif path == "capture.profile" and not str(value).strip():
            value = "<default>"
        return [f"{scope_label}{path} = {value}"]

    scope_name = name if scope != "global" else "global"
    lines = [f"proxy settings ({scope_name}):"]
    for path in paths:
        try:
            value = _get_nested_value(proxy_cfg, path)
        except KeyError:
            value = "<unset>"
        if isinstance(value, list):
            value = ",".join(value)
        elif path == "capture.profile" and not str(value).strip():
            value = "<default>"
        lines.append(f" - {path} = {value}")
    return lines


def cmd_proxy_get(state, args):
    if not args:
        return ["usage: proxy get [auth|world|route <name>] [path]"]
    return cmd_proxy_show(state, args)


def cmd_proxy_set(state, args):
    if len(args) < 2:
        return ["usage: proxy set [auth|world|route <name>] <path> <value>"]

    try:
        scope, scope_name, path, raw_value = _parse_proxy_target_args(args, require_value=True)
    except ValueError:
        return ["usage: proxy set [auth|world|route <name>] <path> <value>"]

    if path not in _PROXY_SETTING_TYPES:
        return [f"unknown proxy setting: {path}"]

    try:
        value = _parse_proxy_value(path, raw_value)
    except Exception as exc:
        return [f"invalid value for {path}: {exc}"]

    if _PROXY_SETTING_TYPES[path] is list:
        if not value:
            return [f"use 'proxy clear {_proxy_scope_label(scope, scope_name)}{path}' to clear {path}"]
        current = _proxy_list_value(state, scope, scope_name, path)
        updated = current[:]
        for item in value:
            if item not in updated:
                updated.append(item)
        value = updated

    _set_nested_value(_proxy_scope_config(state, scope, scope_name), path, value)
    prefix = _proxy_scope_label(scope, scope_name)
    display_value = "<default>" if path == "capture.profile" and not str(value).strip() else value
    return [f"{prefix}{path} = {display_value}"]


def cmd_proxy_rm(state, args):
    if len(args) < 2:
        return ["usage: proxy rm [auth|world|route <name>] <path> <value>"]

    try:
        scope, scope_name, path, raw_value = _parse_proxy_target_args(args, require_value=True)
    except ValueError:
        return ["usage: proxy rm [auth|world|route <name>] <path> <value>"]

    if path not in _PROXY_SETTING_TYPES:
        return [f"unknown proxy setting: {path}"]
    if _PROXY_SETTING_TYPES[path] is not list:
        return [f"proxy rm only supports list settings: {path}"]

    try:
        values = _parse_proxy_value(path, raw_value)
    except Exception as exc:
        return [f"invalid value for {path}: {exc}"]
    if not values:
        return [f"missing values for {path}"]

    current = _proxy_list_value(state, scope, scope_name, path)
    updated = [item for item in current if item not in values]
    _set_nested_value(_proxy_scope_config(state, scope, scope_name), path, updated)
    prefix = _proxy_scope_label(scope, scope_name)
    return [f"{prefix}{path} = {updated}"]


def cmd_proxy_clear(state, args):
    if not args:
        return ["usage: proxy clear [auth|world|route <name>] <path>"]

    try:
        scope, scope_name, path, _ = _parse_proxy_target_args(args, require_value=False)
    except ValueError:
        return ["usage: proxy clear [auth|world|route <name>] <path>"]

    if path not in _PROXY_SETTING_TYPES:
        return [f"unknown proxy setting: {path}"]
    if _PROXY_SETTING_TYPES[path] is not list:
        return [f"proxy clear only supports list settings: {path}"]

    _set_nested_value(_proxy_scope_config(state, scope, scope_name), path, [])
    prefix = _proxy_scope_label(scope, scope_name)
    return [f"cleared {prefix}{path}"]


def cmd_save(state, args):
    if args:
        return ["usage: save"]

    try:
        config_data = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"missing config file: {_CONFIG_PATH}"]
    except json.JSONDecodeError as exc:
        return [f"invalid json in {_CONFIG_PATH.name}: {exc}"]

    states_cfg = config_data.setdefault("states", {})
    state_name = _active_state_name(state)
    states_cfg[state_name] = _runtime_state_snapshot(state)

    _write_json(_CONFIG_PATH, config_data)
    _sync_default_config(config_data)
    return [f"saved runtime settings to state '{state_name}'"]


def cmd_reload(state, args):
    clear_log = False
    if args:
        token = str(args[0]).strip().lower()
        if len(args) != 1 or token not in {"log", "clearlog"}:
            return ["usage: reload [log]"]
        clear_log = True

    if clear_log:
        Logger.reset_log(_proxy_log_file())
    state.reload_requested = True
    if clear_log:
        return ["proxy log cleared", "reload scheduled; active proxy connections will be dropped"]
    return ["reload scheduled; active proxy connections will be dropped"]


def cmd_log_reset(state, args):
    _ = state
    if args:
        return ["usage: log reset"]
    Logger.reset_log(_proxy_log_file())
    return [f"cleared {_proxy_log_file()}"]


def cmd_reset(state, args):
    scope, name, rest = _scope_args(args)
    if scope == "route" and not name:
        return ["usage: reset [auth|world|route <name>]"]
    if rest:
        return ["usage: reset [auth|world|route <name>]"]

    cfg = _active_config(state)

    if scope == "global":
        state.routes.clear()
        state.routes.update(cfg["routes"])
        state.proxy.clear()
        state.proxy.update(deepcopy(cfg.get("proxy", {})))
        for key in ("enable_log", "enable_view", "enable_decode"):
            if key in cfg:
                setattr(state, key, cfg[key])
        return [f"reset state '{_active_state_name(state)}' to config defaults"]

    if scope == "route" and not _route_exists(state, name):
        return [f"unknown route: {name}"]

    target_cfg = _proxy_scope_config(state, scope, name)
    default_cfg = _default_proxy_scope_config(state, scope, name)
    target_cfg.clear()
    target_cfg.update(default_cfg)
    return [f"reset {_scope_display_name(scope, name)} proxy settings"]


def cmd_focus_list(state, args):
    scope, name, rest = _scope_args(args)
    if scope == "route" and not name:
        return ["usage: focus list [auth|world|route <name>]"]
    if rest:
        return ["usage: focus list [auth|world|route <name>]"]
    if scope == "route" and not _route_exists(state, name):
        return [f"unknown route: {name}"]

    names = _capture_focus_list(state, scope, name)
    label = _scope_display_name(scope, name)
    return [f"focus ({label}) = {_joined_names(names)}"]


def cmd_focus_clear(state, args):
    scope, name, rest = _scope_args(args)
    if scope == "route" and not name:
        return ["usage: focus clear [auth|world|route <name>]"]
    if rest:
        return ["usage: focus clear [auth|world|route <name>]"]
    if scope == "route" and not _route_exists(state, name):
        return [f"unknown route: {name}"]

    _set_nested_value(_proxy_scope_config(state, scope, name), "capture.focus", [])
    return [f"cleared focus for {_scope_display_name(scope, name)}"]


def _cmd_focus_update(state, args, *, remove: bool):
    scope, name, rest = _scope_args(args)
    action = "rm" if remove else "add"
    if scope == "route" and not name:
        return [f"usage: focus {action} [auth|world|route <name>] <opcode[,opcode...]>"]
    if not rest:
        return [f"usage: focus {action} [auth|world|route <name>] <opcode[,opcode...]>"]
    if scope == "route" and not _route_exists(state, name):
        return [f"unknown route: {name}"]

    names = _parse_opcode_names(" ".join(rest))
    if not names:
        return ["missing opcode name"]

    current = _capture_focus_list(state, scope, name)
    if remove:
        updated = [item for item in current if item not in names]
    else:
        updated = current[:]
        for item in names:
            if item not in updated:
                updated.append(item)
    _set_nested_value(_proxy_scope_config(state, scope, name), "capture.focus", updated)
    return [f"focus ({_scope_display_name(scope, name)}) = {_joined_names(updated)}"]


def cmd_focus_add(state, args):
    return _cmd_focus_update(state, args, remove=False)


def cmd_focus_rm(state, args):
    return _cmd_focus_update(state, args, remove=True)


def cmd_promote(state, args):
    _ = state
    if not args:
        return ["usage: promote <capture-name>"]

    source = _resolve_capture_debug_file(args[0], profile=_active_capture_profile(state))
    if source is None:
        return [f"missing capture debug: {args[0]}"]

    case_name = _normalize_capture_case_name(source.name)
    def_path, json_path, debug_path = _promoted_paths(case_name)

    _write_text(def_path, "{}\n")
    _write_json(json_path, {})
    debug_path.parent.mkdir(parents=True, exist_ok=True)
    debug_path.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    return [
        f"promoted {source.name} -> {case_name}",
        f"def   = {def_path.name}",
        f"json  = {json_path.name}",
        f"debug = {debug_path.name}",
    ]


def cmd_demote(state, args):
    _ = state
    if not args:
        return ["usage: demote <case-name>"]

    case_name = _normalize_capture_case_name(args[0])
    removed: list[str] = []

    for path in _promoted_paths(case_name):
        if path.exists():
            path.unlink()
            removed.append(path.name)

    if not removed:
        return [f"nothing to demote for {case_name}"]

    return [f"demoted {case_name}", *[f" - {name}" for name in removed]]


def cmd_captures_clear(state, args):
    removed = 0
    profile = _active_capture_profile(state)
    for directory in [*_capture_debug_dirs_for_profile(profile), *_capture_json_dirs_for_profile(profile)]:
        if not directory.exists():
            continue
        for entry in directory.iterdir():
            if not entry.is_file():
                continue
            entry.unlink()
            removed += 1
    label = profile or "default"
    return [f"cleared captures ({label}): removed {removed} files"]


def cmd_protocol_add(state, args):
    return cmd_promote(state, args)


def cmd_protocol_rm(state, args):
    return cmd_demote(state, args)


def cmd_protocol_list(state, args):
    _ = state
    if args:
        return ["usage: protocol list"]
    names = _protocol_cases()
    if not names:
        return ["no promoted protocol artifacts"]
    return ["protocol artifacts:"] + [f" - {name}" for name in names]


def cmd_protocol_sync(state, args):
    if args:
        return ["usage: protocol sync"]

    updated_debug = 0
    updated_json = 0
    lines: list[str] = []
    profile = _active_capture_profile(state)
    capture_root = get_captures_root(profile=profile)

    for debug_path in sorted(get_debug_root().glob("*.json")):
        case_name = debug_path.stem
        capture_debug = capture_root / "debug" / f"{case_name}.json"
        capture_json = capture_root / "json" / f"{case_name}.json"
        target_json = get_json_root() / f"{case_name}.json"

        if not capture_debug.exists():
            lines.append(f"[SKIP] no capture debug for {case_name}")
            continue

        debug_path.write_bytes(capture_debug.read_bytes())
        updated_debug += 1
        lines.append(f"[OK] synced debug for {case_name}")

        if capture_json.exists():
            target_json.parent.mkdir(parents=True, exist_ok=True)
            target_json.write_bytes(capture_json.read_bytes())
            updated_json += 1
            lines.append(f"[OK] synced json for {case_name}")
        else:
            lines.append(f"[SKIP] no capture json for {case_name}")

    if not lines:
        return ["no promoted debug artifacts to sync"]

    lines.append(f"sync complete ({profile or 'default'}): debug={updated_debug} json={updated_json}")
    return lines


def cmd_protocol_view(state, args):
    _ = state
    if len(args) != 2:
        return ["usage: protocol view <def|debug|json> <opcode>"]
    view_type = str(args[0]).strip().lower()
    if view_type not in _PROTOCOL_VIEW_TYPES:
        return ["usage: protocol view <def|debug|json> <opcode>"]
    path = _protocol_view_path(view_type, args[1])
    if not path.exists():
        return [f"missing {view_type}: {path.name}"]
    return [f"{view_type} {path.name}:"] + path.read_text(encoding="utf-8").splitlines()


def resolve_effective_kind(ctx: ParseContext) -> str | None:
    if ctx.active_arg is None:
        return None

    if ctx.command_path == ["proxy", "set"] and ctx.active_arg.name == "value":
        setting = ctx.parsed_args.get("setting")
        if setting in {"filter.whitelist", "filter.blacklist", "capture.focus"}:
            return "csv[opcode_name]"
        if _PROXY_SETTING_TYPES.get(setting) is bool:
            return "bool"
        return "proxy_value"

    if ctx.command_path == ["proxy", "rm"] and ctx.active_arg.name == "value":
        setting = ctx.parsed_args.get("setting")
        if setting in {"filter.whitelist", "filter.blacklist", "capture.focus"}:
            return "csv[opcode_name]"
        return "proxy_value"

    if ctx.command_path[:2] in (["focus", "add"], ["focus", "rm"]) and ctx.active_arg.name == "opcode_names":
        return "csv[opcode_name]"

    if ctx.command_path and ctx.command_path[0] == "help":
        return "command_path"

    if ctx.command_path[:2] in (
        ["proxy", "show"],
        ["proxy", "get"],
        ["proxy", "set"],
    ):
        if ctx.active_arg.name == "scope":
            return "proxy_scope_or_setting"
        if ctx.active_arg.name == "route_name":
            return "route_name"

    if ctx.command_path[:1] in (["status"], ["reset"]) or ctx.command_path[:2] in (
        ["focus", "list"],
        ["focus", "clear"],
        ["focus", "add"],
        ["focus", "rm"],
    ):
        if ctx.active_arg.name == "scope":
            return "proxy_scope"
        if ctx.active_arg.name == "route_name":
            return "route_name"

    if ctx.command_path[:2] == ["protocol", "view"] and ctx.active_arg.name == "view_type":
        return "protocol_view_type"

    return ctx.active_arg.kind


def first_missing_context_arg(ctx: ParseContext) -> ArgSpec | None:
    if ctx.parsed_args.get("scope") == "route" and "route_name" not in ctx.parsed_args:
        for arg in ctx.node.args:
            if arg.name == "route_name":
                return arg
    return None


ROOT_COMMAND = CommandNode(
    name="",
    children={
        "help": CommandNode(
            name="help",
            handler=cmd_help,
            help="Show help for commands",
            args=[
                ArgSpec(
                    name="path",
                    kind="command_path",
                    optional=True,
                    help="command path",
                    remainder=True,
                )
            ],
        ),
        "exit": CommandNode(
            name="exit",
            handler=cmd_exit,
            help="Shut down the CLI",
        ),
        "quit": CommandNode(
            name="quit",
            handler=cmd_exit,
            help="Shut down the CLI",
        ),
        "clear": CommandNode(
            name="clear",
            handler=cmd_clear,
            help="Clear the screen",
        ),
        "status": CommandNode(
            name="status",
            handler=cmd_status,
            help="Show compact proxy runtime status",
            args=[
                ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                ArgSpec(
                    name="route_name",
                    kind="route_name",
                    optional=True,
                    help="configured route name",
                ),
            ],
        ),
        "reload": CommandNode(
            name="reload",
            handler=cmd_reload,
            help="Reload route listeners from the current runtime state; use 'reload log' to clear proxy.log first",
            args=[
                ArgSpec(
                    name="mode",
                    kind="proxy_value",
                    optional=True,
                    help="optional: log",
                )
            ],
        ),
        "log": CommandNode(
            name="log",
            help="Inspect or reset proxy log output",
            children={
                "reset": CommandNode(
                    name="reset",
                    handler=cmd_log_reset,
                    help="Clear the active proxy log file",
                ),
            },
        ),
        "save": CommandNode(
            name="save",
            handler=cmd_save,
            help="Save current runtime settings into the active state in proxy.json",
        ),
        "default": CommandNode(
            name="default",
            handler=cmd_default,
            help="Switch to the default state",
        ),
        "reset": CommandNode(
            name="reset",
            handler=cmd_reset,
            help="Reset runtime settings to the active state's defaults",
            args=[
                ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                ArgSpec(
                    name="route_name",
                    kind="route_name",
                    optional=True,
                    help="configured route name",
                ),
            ],
        ),
        "state": CommandNode(
            name="state",
            help="Inspect or modify state",
            children={
                "show": CommandNode(
                    name="show",
                    handler=cmd_state_show,
                    help="Show current state",
                ),
                "use": CommandNode(
                    name="use",
                    handler=cmd_state_use,
                    help="Switch active state",
                    args=[
                        ArgSpec(
                            name="state",
                            kind="state_name",
                            help="configured state name",
                        )
                    ],
                ),
                "list": CommandNode(
                    name="list",
                    handler=cmd_state_list,
                    help="List available states",
                ),
            },
        ),
        "routes": CommandNode(
            name="routes",
            help="Inspect proxy routes",
            children={
                "show": CommandNode(
                    name="show",
                    handler=cmd_routes_show,
                    help="Show active routes",
                ),
            },
        ),
        "route": CommandNode(
            name="route",
            help="Inspect or modify one route",
            children={
                "show": CommandNode(
                    name="show",
                    handler=cmd_route_show,
                    help="Show one route or one route setting",
                    args=[
                        ArgSpec(
                            name="route_name",
                            kind="route_config_name",
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="setting",
                            kind="route_setting",
                            optional=True,
                            help="listen | forward.host | forward.port",
                        ),
                    ],
                ),
                "set": CommandNode(
                    name="set",
                    handler=cmd_route_set,
                    help="Set one route setting",
                    args=[
                        ArgSpec(
                            name="route_name",
                            kind="route_config_name",
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="setting",
                            kind="route_setting",
                            help="listen | forward.host | forward.port",
                        ),
                        ArgSpec(
                            name="value",
                            kind="route_value",
                            help="new route value",
                            remainder=True,
                        ),
                    ],
                ),
            },
        ),
        "promote": CommandNode(
            name="promote",
            handler=cmd_promote,
            help="Promote a capture debug file into data/debug, data/json, and data/def",
            args=[
                ArgSpec(
                    name="capture_name",
                    kind="capture_name",
                    help="capture debug file from captures/debug or captures/focus/debug",
                )
            ],
        ),
        "demote": CommandNode(
            name="demote",
            handler=cmd_demote,
            help="Remove a promoted packet from data/debug, data/json, and data/def",
            args=[
                ArgSpec(
                    name="case_name",
                    kind="promoted_case",
                    help="promoted opcode name",
                )
            ],
        ),
        "captures": CommandNode(
            name="captures",
            help="Manage packet captures",
            children={
                "clear": CommandNode(
                    name="clear",
                    handler=cmd_captures_clear,
                    help="Remove all files under captures/json, captures/debug, and focus captures",
                ),
            },
        ),
        "focus": CommandNode(
            name="focus",
            help="Manage capture focus lists by scope",
            children={
                "list": CommandNode(
                    name="list",
                    handler=cmd_focus_list,
                    help="Show the current focus list",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                    ],
                ),
                "clear": CommandNode(
                    name="clear",
                    handler=cmd_focus_clear,
                    help="Clear the current focus list",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                    ],
                ),
                "add": CommandNode(
                    name="add",
                    handler=cmd_focus_add,
                    help="Add one or more opcodes to the focus list",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="opcode_names",
                            kind="csv[opcode_name]",
                            help="comma-separated opcode names",
                            remainder=True,
                        ),
                    ],
                ),
                "rm": CommandNode(
                    name="rm",
                    handler=cmd_focus_rm,
                    help="Remove one or more opcodes from the focus list",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="opcode_names",
                            kind="csv[opcode_name]",
                            help="comma-separated opcode names",
                            remainder=True,
                        ),
                    ],
                ),
            },
        ),
        "protocol": CommandNode(
            name="protocol",
            help="Inspect or modify promoted protocol artifacts",
            children={
                "add": CommandNode(
                    name="add",
                    handler=cmd_protocol_add,
                    help="Promote a capture file into protocol artifacts",
                    args=[
                        ArgSpec(
                            name="capture_name",
                            kind="capture_name",
                            help="capture debug file from captures/debug or captures/focus/debug",
                        )
                    ],
                ),
                "rm": CommandNode(
                    name="rm",
                    handler=cmd_protocol_rm,
                    help="Remove promoted protocol artifacts",
                    args=[
                        ArgSpec(
                            name="case_name",
                            kind="promoted_case",
                            help="promoted opcode name",
                        )
                    ],
                ),
                "list": CommandNode(
                    name="list",
                    handler=cmd_protocol_list,
                    help="List promoted protocol artifacts",
                ),
                "sync": CommandNode(
                    name="sync",
                    handler=cmd_protocol_sync,
                    help="Refresh promoted debug/json artifacts from latest captures",
                ),
                "view": CommandNode(
                    name="view",
                    handler=cmd_protocol_view,
                    help="View a promoted def/debug/json artifact",
                    args=[
                        ArgSpec(
                            name="view_type",
                            kind="protocol_view_type",
                            help="def | debug | json",
                        ),
                        ArgSpec(
                            name="case_name",
                            kind="promoted_case",
                            help="promoted opcode name",
                        ),
                    ],
                ),
            },
        ),
        "proxy": CommandNode(
            name="proxy",
            help="Inspect or modify proxy packet settings",
            children={
                "show": CommandNode(
                    name="show",
                    handler=cmd_proxy_show,
                    help="Show current proxy settings",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="setting",
                            kind="proxy_setting",
                            optional=True,
                            help="proxy setting path",
                        ),
                    ],
                ),
                "get": CommandNode(
                    name="get",
                    handler=cmd_proxy_get,
                    help="Read one proxy setting",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="setting",
                            kind="proxy_setting",
                            optional=True,
                            help="proxy setting path",
                        ),
                    ],
                ),
                "set": CommandNode(
                    name="set",
                    handler=cmd_proxy_set,
                    help="Set one proxy setting, appending to list settings",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="setting",
                            kind="proxy_setting",
                            help="proxy setting path",
                        ),
                        ArgSpec(
                            name="value",
                            kind="proxy_value",
                            help="depends on setting",
                            remainder=True,
                        ),
                    ],
                ),
                "rm": CommandNode(
                    name="rm",
                    handler=cmd_proxy_rm,
                    help="Remove one or more values from a list proxy setting",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="setting",
                            kind="proxy_setting",
                            help="list proxy setting path",
                        ),
                        ArgSpec(
                            name="value",
                            kind="proxy_value",
                            help="comma-separated values for list settings",
                            remainder=True,
                        ),
                    ],
                ),
                "clear": CommandNode(
                    name="clear",
                    handler=cmd_proxy_clear,
                    help="Clear a list proxy setting",
                    args=[
                        ArgSpec(name="scope", kind="proxy_scope", optional=True, help="world | auth | route"),
                        ArgSpec(
                            name="route_name",
                            kind="route_name",
                            optional=True,
                            help="configured route name",
                        ),
                        ArgSpec(
                            name="setting",
                            kind="proxy_setting",
                            help="list proxy setting path",
                        ),
                    ],
                ),
            },
        ),
    },
)

COMMANDS = ROOT_COMMAND.children
