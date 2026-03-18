from proxy.cli.editor import LineEditor
from proxy.cli.commands import ROOT_COMMAND, resolve_effective_kind
from proxy.cli.core import render_help as render_context_help
from proxy.cli.help import render_help
from proxy.cli.parser import CommandError, IncompleteCommand, parse_command

ed = LineEditor(completer=None)

try:
    while True:
        line = ed.read_line()
        if line is None:
            break

        line = line.strip()
        if not line:
            continue

        try:
            action, args = parse_command(line)
        except IncompleteCommand as exc:
            for row in render_context_help(ROOT_COMMAND, exc.ctx, resolve_effective_kind):
                print(row)
            continue
        except CommandError as exc:
            print(exc)
            continue

        result = action(None, args)

        if isinstance(result, tuple):
            intent, payload = result
            if intent == "__help__":
                for row in render_help(payload):
                    print(row)
                continue
            if intent == "__exit__":
                break

        if isinstance(result, str):
            print(result)
        elif isinstance(result, list):
            for row in result:
                print(row)

except KeyboardInterrupt:
    print("\n^C")

print("Bye.")
