from __future__ import annotations

from proxy.cli.commands import (
    _PROTOCOL_VIEW_TYPES,
    ROOT_COMMAND,
    _PROXY_PHASES,
    _PROXY_SETTING_CHOICES,
    _PROXY_SETTING_TYPES,
    resolve_effective_kind,
)
from proxy.cli.core import CompletionEngine, ParseContext, register_completion
from proxy.config import CONFIG as DEFAULT_CONFIG
from shared.PathUtils import get_captures_root, get_debug_root, get_def_root, get_json_root, normalize_capture_profile_name
from proxy.utils.route_scope import route_phase
from server.modules.opcodes.AuthOpcodes import AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES
from server.modules.opcodes.WorldOpcodes import WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES


_AUTH_OPCODE_NAMES = sorted({
    *AUTH_CLIENT_OPCODES.values(),
    *AUTH_SERVER_OPCODES.values(),
})
_WORLD_OPCODE_NAMES = sorted({
    *WORLD_CLIENT_OPCODES.values(),
    *WORLD_SERVER_OPCODES.values(),
})
_ALL_OPCODE_NAMES = sorted(set(_AUTH_OPCODE_NAMES) | set(_WORLD_OPCODE_NAMES))
_STATE = None


def _match_prefix(values, prefix: str):
    return sorted(value for value in values if value.startswith(prefix))


def _route_phase_name(route_name: str | None) -> str | None:
    if not route_name:
        return None
    if _STATE is not None:
        routes = getattr(_STATE, "routes", None)
        if isinstance(routes, dict):
            return route_phase(route_name, routes.get(route_name))
    return route_phase(route_name)


def _opcode_names_for_scope(scope: str | None, route_name: str | None = None):
    if scope == "route":
        scope = _route_phase_name(route_name)
    if scope == "auth":
        return _AUTH_OPCODE_NAMES
    if scope == "world":
        return _WORLD_OPCODE_NAMES
    return _ALL_OPCODE_NAMES


def set_completion_state(state) -> None:
    global _STATE
    _STATE = state


def _route_names():
    if _STATE is not None:
        routes = getattr(_STATE, "routes", None)
        if isinstance(routes, dict) and routes:
            return sorted(routes.keys())
    default_routes = DEFAULT_CONFIG.get("states", {}).get("default", {}).get("routes", {})
    return sorted(default_routes.keys())


def _capture_names() -> list[str]:
    profile = None
    if _STATE is not None:
        capture_cfg = ((getattr(_STATE, "proxy", None) or {}).get("capture") or {})
        try:
            profile = normalize_capture_profile_name(capture_cfg.get("profile"))
        except Exception:
            profile = None
    names: set[str] = set()
    for directory in (
        get_captures_root(profile=profile) / "debug",
        get_captures_root(profile=profile, focus=True) / "debug",
    ):
        if not directory.exists():
            continue
        names.update(
            entry.name
            for entry in directory.iterdir()
            if entry.is_file() and entry.suffix == ".json"
        )
    return sorted(names)


def _promoted_case_names() -> list[str]:
    names: set[str] = set()
    for directory, suffix in (
        (get_def_root(), ".def"),
        (get_json_root(), ".json"),
        (get_debug_root(), ".json"),
    ):
        if not directory.exists():
            continue
        names.update(
            entry.stem
            for entry in directory.iterdir()
            if entry.is_file() and entry.suffix == suffix
        )
    return sorted(names)


def complete_route(ctx: ParseContext) -> list[str]:
    return _match_prefix(sorted(_PROXY_PHASES), ctx.current_prefix)


def complete_proxy_scope(ctx: ParseContext) -> list[str]:
    return _match_prefix(sorted(_PROXY_PHASES | {"route"}), ctx.current_prefix)


def complete_route_name(ctx: ParseContext) -> list[str]:
    return _match_prefix(_route_names(), ctx.current_prefix)


def complete_state_name(ctx: ParseContext) -> list[str]:
    states = sorted(DEFAULT_CONFIG.get("states", {}).keys())
    return _match_prefix(states, ctx.current_prefix)


def complete_capture_name(ctx: ParseContext) -> list[str]:
    return _match_prefix(_capture_names(), ctx.current_prefix)


def complete_promoted_case(ctx: ParseContext) -> list[str]:
    return _match_prefix(_promoted_case_names(), ctx.current_prefix)


def complete_proxy_setting(ctx: ParseContext) -> list[str]:
    return _match_prefix(sorted(_PROXY_SETTING_TYPES), ctx.current_prefix)


def complete_proxy_scope_or_setting(ctx: ParseContext) -> list[str]:
    values = sorted(set(_PROXY_PHASES) | {"route"} | set(_PROXY_SETTING_TYPES))
    return _match_prefix(values, ctx.current_prefix)


def complete_bool(ctx: ParseContext) -> list[str]:
    return _match_prefix(("off", "on"), ctx.current_prefix.lower())


def complete_proxy_value(ctx: ParseContext) -> list[str]:
    setting = ctx.parsed_args.get("setting")
    if setting in _PROXY_SETTING_CHOICES:
        return _match_prefix(sorted(_PROXY_SETTING_CHOICES[setting]), ctx.current_prefix.lower())
    return []


def complete_protocol_view_type(ctx: ParseContext) -> list[str]:
    return _match_prefix(sorted(_PROTOCOL_VIEW_TYPES), ctx.current_prefix.lower())


def complete_opcode(ctx: ParseContext) -> list[str]:
    scope = ctx.parsed_args.get("scope")
    route_name = ctx.parsed_args.get("route_name")
    return _match_prefix(_opcode_names_for_scope(scope, route_name), ctx.current_prefix.upper())


def complete_csv_opcode(ctx: ParseContext) -> list[str]:
    scope = ctx.parsed_args.get("scope")
    route_name = ctx.parsed_args.get("route_name")
    opcode_names = _opcode_names_for_scope(scope, route_name)
    prefix = ctx.current_prefix.upper()

    if "," in prefix:
        existing, _, tail = prefix.rpartition(",")
        matches = _match_prefix(opcode_names, tail)
        return [f"{existing},{match}" for match in matches]

    return _match_prefix(opcode_names, prefix)


def complete_command_path(ctx: ParseContext) -> list[str]:
    path = str(ctx.parsed_args.get("path", "")).strip()
    node = ROOT_COMMAND

    if path:
        for token in path.split():
            child = node.children.get(token)
            if child is None:
                return []
            node = child

    return _match_prefix(sorted(node.children), ctx.current_prefix)


register_completion("route", complete_route)
register_completion("proxy_scope", complete_proxy_scope)
register_completion("route_name", complete_route_name)
register_completion("state_name", complete_state_name)
register_completion("capture_name", complete_capture_name)
register_completion("promoted_case", complete_promoted_case)
register_completion("proxy_setting", complete_proxy_setting)
register_completion("proxy_scope_or_setting", complete_proxy_scope_or_setting)
register_completion("bool", complete_bool)
register_completion("proxy_value", complete_proxy_value)
register_completion("protocol_view_type", complete_protocol_view_type)
register_completion("opcode_name", complete_opcode)
register_completion("csv[opcode_name]", complete_csv_opcode)
register_completion("command_path", complete_command_path)


ENGINE = CompletionEngine(ROOT_COMMAND, resolve_effective_kind)


def complete(line: str):
    return ENGINE.complete(line)
