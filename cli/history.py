from __future__ import annotations

from pathlib import Path
from threading import Lock

from shared.PathUtils import get_logs_root


_HISTORY_LOCK = Lock()
_MAX_HISTORY = 1000


def _history_file() -> Path:
    return get_logs_root() / "proxy_history.txt"


def load_history() -> list[str]:
    with _HISTORY_LOCK:
        try:
            lines = _history_file().read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
    return [line for line in lines if line.strip()][-_MAX_HISTORY:]


def append_history(line: str) -> None:
    text = str(line or "").strip()
    if not text:
        return

    with _HISTORY_LOCK:
        history_file = _history_file()
        history_file.parent.mkdir(parents=True, exist_ok=True)
        with history_file.open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")
