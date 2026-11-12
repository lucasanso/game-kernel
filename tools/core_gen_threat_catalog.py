"""Export gamekernel/core/threat_catalog.py to contracts/threat_catalog.json (owner: Agent A).

The Python catalog stays the single source; the JSON is what the C++ risk engine, the Qt interface and any
other consumer read. Usage: python tools/core_gen_threat_catalog.py [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gamekernel.core.models import Classification, CrackStatus, EvidenceSource, RiskLevel  # noqa: E402
from gamekernel.core.threat_catalog import CATALOG  # noqa: E402

OUTPUT = ROOT / "contracts" / "threat_catalog.json"


def build() -> str:
    doc = {
        "format": "gamekernel-threat-catalog",
        "version": 1,
        "categories": {
            cat.value: {
                "label": info.label,
                "summary": info.summary,
                "can_do": info.can_do,
                "data_at_risk": info.data_at_risk,
                "detection": info.detection,
                "limitations": info.limitations,
                "recommendations": list(info.recommendations),
            }
            for cat, info in CATALOG.items()
        },
        "risk_levels": {r.name: {"label": r.label, "meaning": r.meaning} for r in RiskLevel},
        "classifications": {c.value: c.label for c in Classification},
        "crack_status": {c.value: c.label for c in CrackStatus},
        "evidence_sources": {s.value: s.label for s in EvidenceSource},
    }
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = build()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != text:
            print(f"{OUTPUT} desatualizado; rode tools/core_gen_threat_catalog.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
