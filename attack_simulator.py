"""Generate harmless security events for the local M & M Lab demo."""
from __future__ import annotations

import argparse
import random
import time
from datetime import datetime, timezone
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent / "lab-events.log"


def write_event(kind: str) -> None:
    ip = random.choice(("127.0.0.1", "192.168.1.25", "10.0.0.15"))
    if kind == "failed":
        line = f"{datetime.now(timezone.utc).isoformat()} LOGIN_FAILED user=admin from {ip}"
    elif kind == "scan":
        line = f"{datetime.now(timezone.utc).isoformat()} PORT_SCAN source={ip} ports=22,80,443"
    elif kind == "http":
        line = f"{datetime.now(timezone.utc).isoformat()} HTTP_ERROR source={ip} status=500 user_agent=lab-simulator"
    else:
        line = f"{datetime.now(timezone.utc).isoformat()} LOGIN_SUCCESS user=analyst from 127.0.0.1"
    with OUTPUT.open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")
    print(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate safe events for your own local M & M Lab.")
    parser.add_argument("--kind", choices=("failed", "scan",
                        "http", "normal"), default="failed")
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    if args.count < 1 or args.count > 100:
        raise SystemExit("count must be between 1 and 100")
    for index in range(args.count):
        write_event(args.kind)
        if index + 1 < args.count:
            time.sleep(max(0, args.interval))


if __name__ == "__main__":
    main()
