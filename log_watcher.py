"""Background local file watcher that forwards appended lines to M & M Lab rules."""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from app import BASE_DIR, record_event


def watch(path: Path, interval: float = 1.0) -> None:
    path = path.resolve()
    path.relative_to(BASE_DIR)
    cursor = path.stat().st_size if path.exists() else 0
    while True:
        if path.exists():
            content = path.read_text(errors="replace")
            if len(content) < cursor:
                cursor = 0
            for line in content[cursor:].splitlines():
                if "LOGIN_FAILED" in line or "failed password" in line.lower():
                    record_event("Live log alert", "127.0.0.1",
                                 "HIGH", line[:180], "watcher")
                elif any(word in line.lower() for word in ("malware", "ransomware", "trojan")):
                    record_event("Live malware alert", "127.0.0.1",
                                 "CRITICAL", line[:180], "watcher")
            cursor = len(content)
        time.sleep(max(interval, 0.1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Watch a local M & M Lab log file.")
    parser.add_argument("path", nargs="?", default="lab-events.log")
    args = parser.parse_args()
    watch(Path(args.path))
