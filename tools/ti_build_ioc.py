"""Build a ``gamekernel-ioc`` file from local sources (offline threat-intelligence preparation).

    python tools/ti_build_ioc.py --version 2026.11.12 --out dist/ioc/local.json \
        fontes/hashes-ruins.txt:bad:trojan fontes/exportacao.csv fontes/anterior.json

Each source is ``path[:default_verdict[:default_category]]`` — the defaults apply to plain hash
lists and to rows without those fields. Entries are normalised (SHA-256 only, lowercase),
de-duplicated (highest severity kept, sources merged) and checked for conflicts (the same hash
marked good and bad). Conflicts abort the build unless --prefer-bad is given. A JSON summary is
printed (and written with --report). Nothing is looked up online.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gamekernel.ti import ioc  # noqa: E402


def parse_source(spec: str) -> tuple[Path, str | None, str]:
    """``path[:verdict[:category]]``, read from the right so Windows drive letters ("C:\\...") work."""
    parts = spec.rsplit(":", 2)
    if len(parts) == 3 and parts[1] in ("bad", "good"):
        return Path(parts[0]), parts[1], parts[2]
    if len(parts) >= 2 and parts[-1] in ("bad", "good"):
        return Path(":".join(parts[:-1])), parts[-1], ""
    return Path(spec), None, ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="+")
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--prefer-bad", action="store_true", help="resolve conflitos como 'bad' (com nota)")
    ap.add_argument("--report", type=Path)
    args = ap.parse_args(argv)

    indicators, rejected = [], []
    for spec in args.sources:
        path, verdict, category = parse_source(spec)
        try:
            found, bad = ioc.read_source(path, default_verdict=verdict, default_category=category)
        except (ioc.IocError, OSError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": f"{path}: {exc}"}, ensure_ascii=False))
            return 1
        indicators += found
        rejected += bad
    merged, report = ioc.merge(indicators, prefer_bad_on_conflict=args.prefer_bad)
    report.rejected += rejected
    summary = dict(report.to_dict(), output=str(args.out))
    if args.report:
        args.report.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if report.conflicts or rejected:
        summary["ok"] = False
        print(json.dumps(summary, ensure_ascii=False))
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    ioc.write_document(merged, args.version, args.out)
    ok, messages, count = ioc.validate_ioc_file(args.out)
    summary.update(ok=ok, written_entries=count, validation=messages)
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
