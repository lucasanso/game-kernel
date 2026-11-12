"""Generate signatures/internal/indicators.yar from gamekernel/engines/indicators.py (owner: Agent A).

The capability indicators are maintained as a Python table (easy review) and shipped as YARA source
consumed by the C++ engine. Literal strings are written as \\xNN escapes so the shipped file does not
contain plaintext offensive-tool strings that other antivirus products might flag.

Usage:  python tools/core_gen_indicators.py [--check]
  --check   exit 1 if the committed file is out of date (used by the test suite)
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gamekernel.engines.indicators import INDICATORS, PACKER_MARKERS  # noqa: E402

OUTPUT = ROOT / "signatures" / "internal" / "indicators.yar"


def _escaped_literal(text: str) -> str:
    return '"' + "".join(f"\\x{b:02x}" for b in text.encode("utf-8")) + '"'


def _regex(pattern: str) -> str:
    return "/" + pattern.replace("/", "\\/") + "/"


def _meta(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_source() -> str:
    table_digest = hashlib.sha256(repr((INDICATORS, PACKER_MARKERS)).encode()).hexdigest()[:16]
    out = [
        "// Game Kernel — capability indicators (generated, do not edit).",
        "// Source: gamekernel/engines/indicators.py  ·  generator: tools/core_gen_indicators.py",
        f"// table digest: {table_digest}",
        "",
    ]
    for ind in INDICATORS:
        mods = " ascii" + (" wide" if ind.wide else "") + (" nocase" if ind.nocase else "")
        strings = []
        for i, pattern in enumerate(ind.patterns):
            body = _regex(pattern[3:]) if pattern.startswith("re:") else _escaped_literal(pattern)
            strings.append(f"        $s{i} = {body}{mods}")
        condition = "any of them" if ind.min_matches <= 1 else f"{min(ind.min_matches, len(ind.patterns))} of them"
        out.append(
            f"rule IND_{ind.id} {{\n    meta:\n        kind = \"indicator\"\n        group = {_meta(ind.group)}\n"
            f"        description = {_meta(ind.description)}\n    strings:\n" + "\n".join(strings)
            + f"\n    condition:\n        {condition}\n}}\n"
        )
    for idx, (name, patterns) in enumerate(PACKER_MARKERS):
        safe = "".join(c if c.isalnum() else "_" for c in name)
        strings = "\n".join(f"        $s{i} = {_escaped_literal(p)} ascii wide" for i, p in enumerate(patterns))
        out.append(
            f"rule PKR_{idx}_{safe} {{\n    meta:\n        kind = \"marker\"\n        marker = {_meta(name)}\n"
            f"    strings:\n{strings}\n    condition:\n        any of them\n}}\n"
        )
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = build_source()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != source:
            print(f"{OUTPUT} está desatualizado; rode: python tools/core_gen_indicators.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(source, encoding="utf-8", newline="\n")
    print(f"{OUTPUT} ({len(INDICATORS)} indicadores, {len(PACKER_MARKERS)} marcadores)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
