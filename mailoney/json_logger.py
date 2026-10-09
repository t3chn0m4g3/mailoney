"""
Append-only JSON Lines logging for Mailoney events.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]


_EMPTY = object()


def _prune_empty(value: Any) -> Any:
    if value is None or value == "":
        return _EMPTY
    if isinstance(value, dict):
        pruned = {}
        for key, item in value.items():
            pruned_item = _prune_empty(item)
            if pruned_item is not _EMPTY:
                pruned[key] = pruned_item
        return pruned if pruned else _EMPTY
    if isinstance(value, list):
        pruned_list = []
        for item in value:
            pruned_item = _prune_empty(item)
            if pruned_item is not _EMPTY:
                pruned_list.append(pruned_item)
        return pruned_list if pruned_list else _EMPTY
    return value


class JsonlLogger:
    """
    Write one JSON document per line.

    The file is opened for every write so external log rotation can rename
    the active file without Mailoney keeping a stale file descriptor open.
    """

    def __init__(self, log_file: str):
        self.log_file = Path(log_file)
        self._thread_lock = threading.Lock()

    def write(self, event: Dict[str, Any]) -> None:
        pruned_event = _prune_empty(event)
        if pruned_event is _EMPTY:
            return

        self.log_file.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        existed = self.log_file.exists()

        with self._thread_lock:
            with self.log_file.open("a", encoding="utf-8") as f:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(
                        pruned_event,
                        f,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    f.write("\n")
                    f.flush()
                finally:
                    if fcntl is not None:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        if not existed:
            os.chmod(self.log_file, 0o640)
