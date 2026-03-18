from proxy.cli.commands import ROOT_COMMAND, first_missing_context_arg
from proxy.cli.core import first_missing_required_arg, resolve_context


class CommandError(Exception):
    pass


class IncompleteCommand(CommandError):
    def __init__(self, ctx):
        self.ctx = ctx
        super().__init__("Incomplete command")


def get_context(line: str):
    return resolve_context(ROOT_COMMAND, line)


def parse_command(line: str):
    ctx = get_context(line)
    if not ctx.tokens:
        return None, []

    if ctx.error_token is not None:
        if ctx.node.children and ctx.current_prefix:
            matches = [name for name in ctx.node.children if name.startswith(ctx.current_prefix)]
            if matches:
                raise IncompleteCommand(ctx)
        raise CommandError(f"Unknown command: {ctx.error_token}")

    if ctx.current_prefix:
        from proxy.cli.completion import ENGINE

        matches = ENGINE.complete_for_context(ctx)
        if matches and ctx.current_prefix not in matches:
            raise IncompleteCommand(ctx)

    committed = get_context(f"{line} ")

    if committed.error_token is not None:
        raise CommandError(f"Unknown command: {committed.error_token}")

    if committed.node.handler is None:
        raise IncompleteCommand(ctx)

    if first_missing_required_arg(committed) is not None:
        raise IncompleteCommand(ctx)
    if first_missing_context_arg(committed) is not None:
        raise IncompleteCommand(ctx)

    return committed.node.handler, committed.raw_args
