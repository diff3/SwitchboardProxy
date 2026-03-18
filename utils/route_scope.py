from __future__ import annotations

from typing import Any


def route_phase(route_name: str | None, route: dict[str, Any] | None = None) -> str:
    route_name = str(route_name or "").strip()
    route = route or {}

    for key in ("phase", "type", "kind"):
        value = str(route.get(key, "")).strip().lower()
        if value in {"auth", "world"}:
            return value

    name = route_name.lower()
    if name == "auth" or name.startswith("auth_") or name.startswith("auth-") or name.startswith("auth"):
        return "auth"
    if name == "world" or name.startswith("world_") or name.startswith("world-") or name.startswith("world"):
        return "world"
    return ""


def merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def scoped_proxy_config(
    proxy_cfg: dict[str, Any] | None,
    *,
    phase: str | None = None,
    route_name: str | None = None,
) -> dict[str, Any]:
    proxy_cfg = proxy_cfg if isinstance(proxy_cfg, dict) else {}
    phase = str(phase or "").strip().lower()
    route_name = str(route_name or "").strip()

    merged = dict(proxy_cfg)

    legacy_phase_cfg = {}
    if phase in {"auth", "world"}:
        legacy_phase_cfg = ((proxy_cfg.get("routes") or {}).get(phase) or {})
    phase_cfg = ((proxy_cfg.get("phases") or {}).get(phase) or {})
    route_cfg = ((proxy_cfg.get("routes") or {}).get(route_name) or {})

    if legacy_phase_cfg:
        merged = merge_dicts(merged, legacy_phase_cfg)
    if phase_cfg:
        merged = merge_dicts(merged, phase_cfg)
    if route_cfg:
        merged = merge_dicts(merged, route_cfg)

    return merged
