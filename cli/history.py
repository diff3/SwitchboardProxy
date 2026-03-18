from __future__ import annotations

from pathlib import Path
from threading import Lock

from shared.PathUtils import get_logs_root


_HISTORY_LOCK = Lock()
_HISTORY_FILE = get_logs_root() / "proxy_history.txt"
_MAX_HISTORY = 1000


def load_history() -> list[str]:
    with _HISTORY_LOCK:
        try:
            lines = _HISTORY_FILE.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
    return [line for line in lines if line.strip()][-_MAX_HISTORY:]


def append_history(line: str) -> None:
    text = str(line or "").strip()
    if not text:
        return

    with _HISTORY_LOCK:
        _HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _HISTORY_FILE.open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")
