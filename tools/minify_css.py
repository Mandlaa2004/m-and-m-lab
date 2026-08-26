"""Generate the production stylesheet without requiring a Node build step."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "static" / "styles.css"
TARGET = ROOT / "static" / "styles.min.css"


def minify(stylesheet: str) -> str:
    stylesheet = re.sub(r"/\*(?!\!)[\s\S]*?\*/", "", stylesheet)
    stylesheet = re.sub(r"\s+", " ", stylesheet)
    stylesheet = re.sub(r"\s*([{}:;,>])\s*", r"\1", stylesheet)
    return stylesheet.replace(";}", "}").strip() + "\n"


TARGET.write_text(minify(SOURCE.read_text(encoding="utf-8")), encoding="utf-8")
