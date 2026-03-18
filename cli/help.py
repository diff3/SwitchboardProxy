from proxy.cli.commands import ROOT_COMMAND, resolve_effective_kind
from proxy.cli.core import ParseContext, render_help as render_context_help


class HelpError(Exception):
    pass


def get_node(path_tokens):
    node = ROOT_COMMAND
    for tok in path_tokens:
        child = node.children.get(tok)
        if child is None:
            raise HelpError(f"Unknown command: {' '.join(path_tokens)}")
        node = child
    return node


def _help_context(args):
    node = get_node(args)
    return ParseContext(
        command_path=list(args),
        node=node,
        parsed_args={},
        active_arg=None,
        current_prefix="",
        ends_with_space=False,
        tokens=list(args),
        raw_args=[],
        pending_args=list(node.args),
    )


def render_help(args):
    return render_context_help(ROOT_COMMAND, _help_context(args), resolve_effective_kind)
