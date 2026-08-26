"""Patch older Wapiti builds that pass removed gettext codeset= on Python 3.11."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    root = Path(sys.prefix) / "lib"
    patched = 0
    for path in root.rglob("wapitiCore/language/language.py"):
        text = path.read_text(encoding="utf-8")
        if "codeset" not in text:
            continue
        updated = re.sub(r",\s*codeset\s*=\s*[^,\)]+", "", text)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            patched += 1
            print(f"patched {path}")
    print(f"wapiti gettext patches applied: {patched}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
