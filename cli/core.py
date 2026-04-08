from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable


AcceptsFunc = Callable[[str, dict[str, object]], bool]
ProviderFunc = Callable[["ParseContext"], list[str]]


@dataclass(slots=True)
class ArgSpec:
    name: str
    kind: str
    optional: bool = False
    help: str = ""
    remainder: bool = False


@dataclass(slots=True)
class CommandNode:
    name: str
    children: dict[str, "CommandNode"] = field(default_factory=dict)
    args: list[ArgSpec] = field(default_factory=list)
    handler: Callable | None = None
    help: str = ""


@dataclass(slots=True)
class ParseContext:
    command_path: list[str]
    node: CommandNode
    parsed_args: dict[str, object]
    active_arg: ArgSpec | None
    current_prefix: str
    ends_with_space: bool
    tokens: list[str] = field(default_factory=list)
    raw_args: list[str] = field(default_factory=list)
    pending_args: list[ArgSpec] = field(default_factory=list)
    error_token: str | None = None


ARG_TYPES: dict[str, dict[str, Any]] = {}
COMPLETION_PROVIDERS: dict[str, ProviderFunc] = {}


def register_arg_type(kind: str, *, accepts: AcceptsFunc | None = None):
    ARG_TYPES[kind] = {"accepts": accepts or _accept_any}


def register_completion(kind: str, provider: ProviderFunc):
    COMPLETION_PROVIDERS[kind] = provider


def _accept_any(_token: str, _parsed_args: dict[str, object]) -> bool:
    return True


def _arg_accepts(kind: str, token: str, parsed_args: dict[str, object]) -> bool:
    spec = ARG_TYPES.get(kind)
    if spec is None:
        return True
    accepts = spec.get("accepts")
    if accepts is None:
        return True
    return bool(accepts(token, parsed_args))


def split_command_line(buffer: str) -> tuple[list[str], bool]:
    stripped = buffer.strip()
    tokens = stripped.split() if stripped else []
    return tokens, buffer.endswith(" ")


def resolve_context(root: CommandNode, buffer: str) -> ParseContext:
    tokens, ends_with_space = split_command_line(buffer)
    node = root
    command_path: list[str] = []
    index = 0

    while index < len(tokens):
        token = tokens[index]
        child = node.children.get(token)
        if child is None:
            break
        node = child
        command_path.append(token)
        index += 1

    raw_args = tokens[index:]

    if node.children and not node.args and raw_args:
        current_prefix = "" if ends_with_space else raw_args[-1]
        return ParseContext(
            command_path=command_path,
            node=node,
            parsed_args={},
            active_arg=None,
            current_prefix=current_prefix,
            ends_with_space=ends_with_space,
            tokens=tokens,
            raw_args=raw_args,
            pending_args=[],
            error_token=raw_args[0],
        )

    parsed_args, active_arg, pending_args = _resolve_args(node.args, raw_args, ends_with_space)
    current_prefix = "" if ends_with_space or not raw_args else raw_args[-1]

    return ParseContext(
        command_path=command_path,
        node=node,
        parsed_args=parsed_args,
        active_arg=active_arg,
        current_prefix=current_prefix,
        ends_with_space=ends_with_space,
        tokens=tokens,
        raw_args=raw_args,
        pending_args=pending_args,
    )


def _resolve_args(
    arg_specs: list[ArgSpec],
    raw_args: list[str],
    ends_with_space: bool,
) -> tuple[dict[str, object], ArgSpec | None, list[ArgSpec]]:
    parsed_args: dict[str, object] = {}
    completed = raw_args if ends_with_space else raw_args[:-1]
    arg_index = 0
    token_index = 0
    active_arg: ArgSpec | None = None
    remainder_arg: ArgSpec | None = None

    while arg_index < len(arg_specs):
        arg = arg_specs[arg_index]

        if arg.remainder:
            if token_index < len(completed):
                parsed_args[arg.name] = " ".join(completed[token_index:])
            remainder_arg = arg
            token_index = len(completed)
            arg_index += 1
            break

        if token_index >= len(completed):
            break

        token = completed[token_index]
        if arg.optional and not _arg_accepts(arg.kind, token, parsed_args):
            arg_index += 1
            continue

        parsed_args[arg.name] = token
        token_index += 1
        arg_index += 1

    if arg_index < len(arg_specs) and token_index > 0:
        probe_token = raw_args[-1] if raw_args and not ends_with_space else "__value__"
        while arg_index < len(arg_specs):
            probe_arg = arg_specs[arg_index]
            if not probe_arg.optional:
                break
            if _arg_accepts(probe_arg.kind, probe_token, parsed_args):
                break
            arg_index += 1

    pending_args = list(arg_specs[arg_index:])

    if remainder_arg is not None and not ends_with_space and raw_args:
        active_arg = remainder_arg
    elif remainder_arg is not None and ends_with_space:
        active_arg = remainder_arg
    elif raw_args and not ends_with_space:
        active_arg = arg_specs[arg_index] if arg_index < len(arg_specs) else None
    elif ends_with_space:
        active_arg = arg_specs[arg_index] if arg_index < len(arg_specs) else None

    return parsed_args, active_arg, pending_args


def first_missing_required_arg(ctx: ParseContext) -> ArgSpec | None:
    for arg in ctx.pending_args:
        if not arg.optional:
            return arg
    return None


def has_prefix_matches(values: list[str] | tuple[str, ...], prefix: str) -> bool:
    if prefix == "":
        return bool(values)
    return any(value.startswith(prefix) for value in values)


def is_incomplete(ctx: ParseContext) -> bool:
    if ctx.node.children and ctx.current_prefix:
        return has_prefix_matches(sorted(ctx.node.children), ctx.current_prefix)
    if ctx.active_arg is not None and ctx.current_prefix:
        return True
    return first_missing_required_arg(ctx) is not None


class CompletionEngine:
    def __init__(
        self,
        root: CommandNode,
        kind_resolver: Callable[[ParseContext], str | None],
    ):
        self.root = root
        self.kind_resolver = kind_resolver

    def complete(self, buffer: str) -> list[str]:
        ctx = resolve_context(self.root, buffer)
        return self.complete_for_context(ctx)

    def complete_for_context(self, ctx: ParseContext) -> list[str]:
        if ctx.active_arg is None:
            return _match_prefix(sorted(ctx.node.children), ctx.current_prefix)

        kind = self.kind_resolver(ctx)
        if not kind:
            return []

        provider = COMPLETION_PROVIDERS.get(kind)
        if provider is None:
            return []

        return provider(ctx)


def _match_prefix(values: list[str] | tuple[str, ...], prefix: str) -> list[str]:
    return sorted(value for value in values if value.startswith(prefix))


def render_help(
    root: CommandNode,
    ctx: ParseContext,
    kind_resolver: Callable[[ParseContext], str | None],
) -> list[str]:
    lines = [f"Usage: {build_usage(ctx)}"]

    if ctx.node.args:
        lines.append("")
        lines.append("Arguments:")
        for arg in ctx.node.args:
            lines.append(f"  {arg.name.ljust(10)}: {describe_arg(ctx, arg, kind_resolver)}")

    suggestions = suggest_values(ctx, kind_resolver)
    if suggestions:
        lines.append("")
        lines.append("Suggestions:")
        lines.extend(f"  {item}" for item in suggestions)
    elif ctx.node.children:
        lines.append("")
        lines.append("Commands:")
        width = max(len(name) for name in ctx.node.children)
        for name, child in sorted(ctx.node.children.items()):
            lines.append(f"  {name.ljust(width)}  {child.help}".rstrip())

    return lines


def build_usage(ctx: ParseContext) -> str:
    parts = ctx.command_path.copy()
    if ctx.node.children:
        parts.append("<command>")
    for arg in ctx.node.args:
        label = f"<{arg.name}>"
        if arg.optional:
            label = f"[{arg.name}]"
        parts.append(label)
    return " ".join(parts) if parts else "<command>"


def describe_arg(
    ctx: ParseContext,
    arg: ArgSpec,
    kind_resolver: Callable[[ParseContext], str | None],
) -> str:
    if arg.help:
        return arg.help

    kind = arg.kind
    if ctx.active_arg is arg:
        kind = kind_resolver(ctx) or kind

    if kind == "route":
        return "world | auth"
    if kind == "proxy_scope":
        return "world | auth | route"
    if kind == "proxy_scope_or_setting":
        return "world | auth | route | <proxy setting>"
    if kind == "route_name":
        return "configured route name"
    if kind == "state_name":
        return "configured state name"
    if kind == "state_flag":
        return "enable_log | enable_view | enable_decode"
    if kind == "state_db_key":
        return "auth_db | world_db | characters_db"
    if kind == "state_mode":
        return "legacy | srp6"
    if kind == "proxy_setting":
        return "proxy setting path"
    if kind == "proxy_value":
        return "depends on setting"
    if kind == "protocol_view_type":
        return "def | debug | json"
    if kind == "csv[opcode_name]":
        return "comma-separated opcode names"
    if kind == "command_path":
        return "command path"
    return kind


def suggest_values(
    ctx: ParseContext,
    kind_resolver: Callable[[ParseContext], str | None],
) -> list[str]:
    if ctx.active_arg is None:
        return sorted(ctx.node.children)

    probe = deepcopy(ctx)
    probe.current_prefix = ""
    kind = kind_resolver(probe)
    if not kind:
        return []
    provider = COMPLETION_PROVIDERS.get(kind)
    if provider is None:
        return []
    return provider(probe)
