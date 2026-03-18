# cli/repl.py

from proxy.cli.commands import ROOT_COMMAND, resolve_effective_kind
from proxy.cli.completion import complete, set_completion_state
from proxy.cli.core import render_help as render_context_help
from proxy.cli.editor import LineEditor
from proxy.cli.help import render_help
from proxy.cli.parser import CommandError, IncompleteCommand, parse_command


class StdIO:
    """
    Local adapter that matches TelnetIO semantics (bytes).
    """

    def read_byte(self):
        ch = input()
        if ch == "":
            return None
        return ch.encode()

    def write(self, data: bytes):
        print(data.decode(errors="replace"), end="", flush=True)


def _write_rows(io, rows):
    for row in rows:
        io.write(row.encode() + b"\r\n")


def _dispatch_result(io, result):
    if isinstance(result, tuple):
        intent, payload = result

        if intent == "__help__":
            _write_rows(io, render_help(payload))
            return True

        if intent == "__exit__":
            io.write(b"Bye.\r\n")
            return False

        io.write(f"Unknown intent: {intent}\r\n".encode())
        return True

    if isinstance(result, str):
        io.write(result.encode() + b"\r\n")
    elif isinstance(result, list):
        _write_rows(io, result)

    return True


def _run_loop(state, editor):
    set_completion_state(state)
    editor.completer = complete

    while True:
        line = editor.read_line()

        if line is None:
            break

        line = line.strip()
        if not line:
            continue

        try:
            action, args = parse_command(line)
        except IncompleteCommand as exc:
            rows = render_context_help(ROOT_COMMAND, exc.ctx, resolve_effective_kind)
            _write_rows(editor.io, rows)
            continue
        except CommandError as exc:
            editor.io.write(str(exc).encode() + b"\r\n")
            continue

        keep_running = _dispatch_result(editor.io, action(state, args))
        if not keep_running:
            break


def run_repl_old(state, io, interactive=True):
    editor = None
    if interactive:
        editor = LineEditor(
            io=io,
            prompt="€ ".encode("utf-8"),
            completer=complete,
        )

    if editor is None:
        return

    try:
        _run_loop(state, editor)
    except (BrokenPipeError, OSError):
        pass


def run_repl(state, editor):
    try:
        _run_loop(state, editor)
    except (BrokenPipeError, OSError):
        pass
