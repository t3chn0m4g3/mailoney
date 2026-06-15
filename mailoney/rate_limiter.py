"""
Sliding-window rate limiting for Mailoney.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .config import RateLimitConfig

logger = logging.getLogger(__name__)


@dataclass
class RateLimitDecision:
    allowed: bool
    scope: Optional[str] = None
    key: Optional[str] = None
    limit: Optional[int] = None
    window_seconds: Optional[int] = None
    block_seconds: Optional[int] = None
    blocked_from: Optional[float] = None
    blocked_until: Optional[float] = None
    should_log: bool = False


class RateLimiter:
    def __init__(
        self,
        config: RateLimitConfig,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        self._clock = clock
        self._lock = threading.Lock()
        self._events: Dict[str, Dict[str, List[float]]] = {"ip": {}, "sender": {}}
        self._blocks: Dict[str, Dict[str, Dict[str, float]]] = {
            "ip": {},
            "sender": {},
        }
        self._load_state()

    def check(self, scope: str, key: Optional[str]) -> RateLimitDecision:
        if not self.config.enabled or not key:
            return RateLimitDecision(allowed=True)

        normalized_key = self._normalize_key(scope, key)
        limit = self._limit_for_scope(scope)
        if limit <= 0:
            return RateLimitDecision(allowed=True)

        now = self._clock()
        with self._lock:
            block = self._blocks[scope].get(normalized_key)
            if block and block["until"] > now:
                return RateLimitDecision(
                    allowed=False,
                    scope=scope,
                    key=normalized_key,
                    limit=limit,
                    window_seconds=self.config.window_seconds,
                    block_seconds=self.config.block_seconds,
                    blocked_from=block["from"],
                    blocked_until=block["until"],
                    should_log=not self.config.log_block_once,
                )

            if block:
                self._blocks[scope].pop(normalized_key, None)

            events = self._active_events(scope, normalized_key, now)
            if len(events) >= limit:
                blocked_until = now + self.config.block_seconds
                self._blocks[scope][normalized_key] = {
                    "from": now,
                    "until": blocked_until,
                }
                self._save_state()
                return RateLimitDecision(
                    allowed=False,
                    scope=scope,
                    key=normalized_key,
                    limit=limit,
                    window_seconds=self.config.window_seconds,
                    block_seconds=self.config.block_seconds,
                    blocked_from=now,
                    blocked_until=blocked_until,
                    should_log=True,
                )

            self._events[scope][normalized_key] = events
            return RateLimitDecision(allowed=True)

    def record_message(self, src_ip: str, sender: Optional[str]) -> None:
        if not self.config.enabled:
            return

        now = self._clock()
        with self._lock:
            self._record("ip", src_ip, now)
            if sender:
                self._record("sender", sender, now)
            self._save_state()

    def _record(self, scope: str, key: str, now: float) -> None:
        normalized_key = self._normalize_key(scope, key)
        events = self._active_events(scope, normalized_key, now)
        events.append(now)
        self._events[scope][normalized_key] = events

    def _active_events(self, scope: str, key: str, now: float) -> List[float]:
        cutoff = now - self.config.window_seconds
        return [ts for ts in self._events[scope].get(key, []) if ts >= cutoff]

    def _limit_for_scope(self, scope: str) -> int:
        if scope == "ip":
            return self.config.max_messages_per_ip
        if scope == "sender":
            return self.config.max_messages_per_sender
        raise ValueError(f"Unknown rate limit scope: {scope}")

    def _normalize_key(self, scope: str, key: str) -> str:
        if scope == "sender":
            return key.strip().lower()
        return key.strip()

    def _load_state(self) -> None:
        if not self.config.state_file:
            return

        path = Path(self.config.state_file)
        if not path.exists():
            return

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            events = data.get("events", {})
            blocks = data.get("blocks", {})
            if isinstance(events, dict):
                for scope in ("ip", "sender"):
                    scope_events = events.get(scope, {})
                    if isinstance(scope_events, dict):
                        self._events[scope] = {
                            str(key): [float(ts) for ts in value]
                            for key, value in scope_events.items()
                            if isinstance(value, list)
                        }
            if isinstance(blocks, dict):
                for scope in ("ip", "sender"):
                    scope_blocks = blocks.get(scope, {})
                    if isinstance(scope_blocks, dict):
                        self._blocks[scope] = {
                            str(key): {
                                "from": float(value["from"]),
                                "until": float(value["until"]),
                            }
                            for key, value in scope_blocks.items()
                            if isinstance(value, dict)
                            and "from" in value
                            and "until" in value
                        }
        except Exception as exc:
            logger.warning("Could not load rate limit state: %s", exc)

    def _save_state(self) -> None:
        if not self.config.state_file:
            return

        path = Path(self.config.state_file)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        data = {"events": self._events, "blocks": self._blocks}

        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, sort_keys=True)
                f.write("\n")
            os.replace(tmp_name, path)
            os.chmod(path, 0o640)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
