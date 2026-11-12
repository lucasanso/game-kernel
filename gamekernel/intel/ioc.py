"""Threat-intelligence preparation of local indicators (``gamekernel-ioc`` v1).

Everything here is offline and publisher-side: indicators are collected from local files
(other ``gamekernel-ioc`` files, CSV exports, plain hash lists), normalised, de-duplicated,
checked for conflicts and written as a deterministic ``gamekernel-ioc`` JSON file that goes
into an update package. Nothing is ever looked up or sent anywhere.

Format (contract, docs/WORK_SPLIT.md §3.3)::

    {"format": "gamekernel-ioc", "version": "2026.11.12",
     "entries": [{"sha256": "<64 lowercase hex>", "verdict": "bad|good", "name": "...",
                  "category": "<ThreatCategory>", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
                  "source": "...", "note": "..."}]}

The C++ installer validates the same rules (gk::updates::validateIocDir) — the equivalence is
tested in tests/ti/test_ioc.py.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..core.models import ThreatCategory

FORMAT = "gamekernel-ioc"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {name: i for i, name in enumerate(reversed(SEVERITIES))}   # INFO=0 … CRITICAL=4
VERDICTS = ("bad", "good")
TEXT_FIELDS = ("name", "source", "note")
MAX_TEXT = 512
MAX_FILE = 256 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CATEGORY_RE = re.compile(r"[a-z_]{1,40}")
KNOWN_CATEGORIES = {c.value for c in ThreatCategory}
HEX_RE = re.compile(r"[0-9a-fA-F]+")


class IocError(Exception):
    pass


@dataclass
class Indicator:
    sha256: str
    verdict: str
    name: str = ""
    category: str = ""
    severity: str = ""
    sources: list[str] = field(default_factory=list)
    note: str = ""

    def to_entry(self) -> dict:
        entry: dict = {"sha256": self.sha256, "verdict": self.verdict}
        if self.name:
            entry["name"] = self.name[:MAX_TEXT]
        if self.category:
            entry["category"] = self.category
        if self.severity:
            entry["severity"] = self.severity
        if self.sources:
            entry["source"] = "; ".join(self.sources)[:MAX_TEXT]
        if self.note:
            entry["note"] = self.note[:MAX_TEXT]
        return entry


@dataclass
class MergeReport:
    total_input: int = 0
    unique: int = 0
    duplicates_merged: int = 0
    rejected: list[str] = field(default_factory=list)       # invalid input lines/entries
    conflicts: list[dict] = field(default_factory=list)     # same hash, different verdicts
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.conflicts and not self.rejected

    def to_dict(self) -> dict:
        return {"total_input": self.total_input, "unique": self.unique, "duplicates_merged": self.duplicates_merged,
                "rejected": self.rejected, "conflicts": self.conflicts, "warnings": self.warnings, "ok": self.ok}


# ---------------------------------------------------------------------------- normalisation
def normalize_hash(value: str) -> str:
    """Return a lowercase SHA-256 or raise IocError (MD5/SHA-1 are refused explicitly)."""
    text = (value or "").strip().replace(" ", "").replace(":", "")
    if text.lower().startswith("sha256="):
        text = text[7:]
    if not HEX_RE.fullmatch(text or "x"):
        raise IocError(f"hash inválido: {value!r}")
    if len(text) in (32, 40):
        raise IocError(f"{'MD5' if len(text) == 32 else 'SHA-1'} não é aceito (use SHA-256): {value!r}")
    if len(text) != 64:
        raise IocError(f"hash com tamanho inválido ({len(text)}): {value!r}")
    return text.lower()


def normalize_entry(raw: dict, default_verdict: str | None = None, default_source: str = "") -> Indicator:
    if not isinstance(raw, dict):
        raise IocError("entrada não é um objeto")
    sha = normalize_hash(str(raw.get("sha256", "")))
    verdict = str(raw.get("verdict") or default_verdict or "").strip().lower()
    if verdict in ("malicious", "malware", "ruim"):
        verdict = "bad"
    elif verdict in ("benign", "clean", "legit", "bom"):
        verdict = "good"
    if verdict not in VERDICTS:
        raise IocError(f"veredito inválido para {sha}: {raw.get('verdict')!r}")
    category = str(raw.get("category") or "").strip().lower()
    if category and category not in KNOWN_CATEGORIES:
        raise IocError(f"categoria desconhecida para {sha}: {category!r}")
    severity = str(raw.get("severity") or "").strip().upper()
    if severity and severity not in SEVERITIES:
        raise IocError(f"severidade inválida para {sha}: {severity!r}")
    if not severity:
        severity = "HIGH" if verdict == "bad" else "INFO"
    source = str(raw.get("source") or default_source).strip()
    texts = {k: str(raw.get(k) or "").strip() for k in ("name", "note")}
    for key, value in texts.items():
        if any(ord(ch) < 32 for ch in value):
            raise IocError(f"caractere de controle no campo {key} de {sha}")
    return Indicator(sha, verdict, texts["name"], category, severity, [source] if source else [], texts["note"])


# ---------------------------------------------------------------------------- readers
def read_source(path: str | Path, default_verdict: str | None = None, default_category: str = "",
                source_label: str | None = None) -> tuple[list[Indicator], list[str]]:
    """Read a local source file. Returns (indicators, rejected_messages).

    Supported: ``gamekernel-ioc`` JSON, CSV with a ``sha256`` header, plain text (one hash per
    line, ``#`` comments; needs ``default_verdict``).
    """
    path = Path(path)
    if path.stat().st_size > MAX_FILE:
        raise IocError(f"{path.name}: arquivo acima de 256 MB")
    text = path.read_text(encoding="utf-8-sig")
    label = source_label or path.name
    out: list[Indicator] = []
    rejected: list[str] = []

    def take(raw: dict, where: str) -> None:
        if default_category and not raw.get("category"):
            raw = dict(raw, category=default_category)
        try:
            out.append(normalize_entry(raw, default_verdict, label))
        except IocError as exc:
            rejected.append(f"{path.name}:{where}: {exc}")

    stripped = text.lstrip()
    if stripped.startswith("{"):
        data = json.loads(text)
        if data.get("format") != FORMAT or not isinstance(data.get("entries"), list):
            raise IocError(f"{path.name}: JSON não está no formato {FORMAT}")
        for i, entry in enumerate(data["entries"]):
            take(entry if isinstance(entry, dict) else {}, f"entrada {i}")
    elif "sha256" in stripped.splitlines()[0].lower() and ("," in stripped.splitlines()[0] or ";" in stripped.splitlines()[0]):
        dialect = csv.Sniffer().sniff(stripped.splitlines()[0], delimiters=",;")
        for i, row in enumerate(csv.DictReader(io.StringIO(text), dialect=dialect), start=2):
            take({(k or "").strip().lower(): v for k, v in row.items()}, f"linha {i}")
    else:
        if not default_verdict:
            raise IocError(f"{path.name}: lista de hashes sem veredito (use default_verdict)")
        for i, line in enumerate(text.splitlines(), start=1):
            line = line.split("#", 1)[0].strip()
            if line:
                take({"sha256": line.split()[0]}, f"linha {i}")
    return out, rejected


# ---------------------------------------------------------------------------- merge
def merge(indicators: Iterable[Indicator], prefer_bad_on_conflict: bool = False) -> tuple[list[Indicator], MergeReport]:
    """De-duplicate by SHA-256. Same verdict: keep the highest severity, merge sources/names.
    Different verdicts: a conflict — reported and excluded, unless ``prefer_bad_on_conflict``."""
    report = MergeReport()
    by_hash: dict[str, Indicator] = {}
    conflicting: dict[str, set[str]] = {}
    for ind in indicators:
        report.total_input += 1
        cur = by_hash.get(ind.sha256)
        if cur is None:
            by_hash[ind.sha256] = Indicator(ind.sha256, ind.verdict, ind.name, ind.category, ind.severity,
                                            list(ind.sources), ind.note)
            continue
        if cur.verdict != ind.verdict:
            conflicting.setdefault(ind.sha256, {cur.verdict}).add(ind.verdict)
            if ind.verdict == "bad":
                # keep the "bad" side as the candidate so prefer_bad can resolve to it
                cur.verdict, cur.name, cur.category, cur.severity = "bad", ind.name or cur.name, ind.category, ind.severity
            for s in ind.sources:
                if s not in cur.sources:
                    cur.sources.append(s)
            continue
        report.duplicates_merged += 1
        if SEVERITY_RANK.get(ind.severity, 0) > SEVERITY_RANK.get(cur.severity, 0):
            cur.severity = ind.severity
        cur.name = cur.name or ind.name
        cur.category = cur.category or ind.category
        cur.note = cur.note or ind.note
        for s in ind.sources:
            if s not in cur.sources:
                cur.sources.append(s)
    for sha, verdicts in sorted(conflicting.items()):
        conflict = {"sha256": sha, "verdicts": sorted(verdicts), "sources": by_hash[sha].sources}
        if prefer_bad_on_conflict:
            by_hash[sha].verdict = "bad"
            by_hash[sha].note = (by_hash[sha].note + " " if by_hash[sha].note else "") + \
                "Conflito entre fontes resolvido como 'bad'."
            report.warnings.append(f"conflito resolvido como 'bad': {sha}")
        else:
            report.conflicts.append(conflict)
            del by_hash[sha]
    merged = sorted(by_hash.values(), key=lambda i: i.sha256)
    report.unique = len(merged)
    for ind in merged:
        if ind.verdict == "bad" and not ind.category:
            report.warnings.append(f"{ind.sha256}: indicador 'bad' sem categoria (aparecerá como genérico)")
    return merged, report


def to_document(indicators: list[Indicator], version: str) -> dict:
    return {"format": FORMAT, "version": version, "entries": [i.to_entry() for i in indicators]}


def write_document(indicators: list[Indicator], version: str, path: str | Path) -> dict:
    doc = to_document(indicators, version)
    Path(path).write_text(json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc


# ---------------------------------------------------------------------------- validation (contract)
def validate_ioc_file(path: str | Path) -> tuple[bool, list[str], int]:
    """Validate one gamekernel-ioc file exactly as the C++ installer does. -> (ok, messages, entries)."""
    ok, messages, count, _ = _validate_files([Path(path)])
    return ok, messages, count


def validate_ioc_dir(directory: str | Path) -> tuple[bool, list[str], int]:
    """Validate every file of an ``ioc`` component (cross-file conflicts included)."""
    files = sorted((p for p in Path(directory).iterdir() if p.is_file()), key=lambda p: p.name)
    if not files:
        return False, ["componente IOC sem arquivos"], 0
    ok, messages, count, _ = _validate_files(files)
    return ok, messages, count


def _validate_files(files: list[Path]) -> tuple[bool, list[str], int, dict[str, str]]:
    messages: list[str] = []
    failed = False
    verdicts: dict[str, str] = {}
    for path in files:
        name = path.name
        if path.suffix.lower() != ".json":
            messages.append(f"{name}: extensão não permitida")
            failed = True
            continue
        if path.stat().st_size > MAX_FILE:
            messages.append(f"{name}: arquivo acima de 256 MB")
            failed = True
            continue
        try:
            root = json.loads(path.read_bytes().decode("utf-8"), parse_constant=_reject)
        except (UnicodeDecodeError, ValueError) as exc:
            messages.append(f"{name}: JSON inválido ({exc})")
            failed = True
            continue
        if not isinstance(root, dict) or root.get("format") != FORMAT:
            messages.append(f"{name}: formato não é {FORMAT}")
            failed = True
            continue
        if not isinstance(root.get("version"), str) or not root["version"]:
            messages.append(f"{name}: campo 'version' ausente")
            failed = True
        entries = root.get("entries")
        if not isinstance(entries, list):
            messages.append(f"{name}: campo 'entries' precisa ser uma lista")
            failed = True
            continue
        for i, e in enumerate(entries):
            where = f"{name}: entrada {i}"
            if not isinstance(e, dict):
                messages.append(f"{where} não é um objeto")
                failed = True
                continue
            sha, verdict = e.get("sha256"), e.get("verdict")
            if not isinstance(sha, str) or not SHA256_RE.fullmatch(sha):
                messages.append(f"{where}: sha256 inválido (64 caracteres hexadecimais minúsculos)")
                failed = True
                continue
            if verdict not in VERDICTS:
                messages.append(f"{where}: verdict precisa ser 'bad' ou 'good'")
                failed = True
                continue
            if "severity" in e and e["severity"] not in SEVERITIES:
                messages.append(f"{where}: severity inválida")
                failed = True
            if "category" in e and not (isinstance(e["category"], str) and CATEGORY_RE.fullmatch(e["category"])):
                messages.append(f"{where}: category inválida")
                failed = True
            for key in TEXT_FIELDS:
                if key in e and (not isinstance(e[key], str) or _utf16_len(e[key]) > MAX_TEXT):
                    messages.append(f"{where}: campo '{key}' precisa ser texto (até {MAX_TEXT} caracteres)")
                    failed = True
            if sha in verdicts and verdicts[sha] != verdict:
                messages.append(f"hash {sha} aparece como 'good' e como 'bad'")
                failed = True
            verdicts[sha] = verdict
    return not failed, messages[:21], len(verdicts), verdicts


def _utf16_len(text: str) -> int:
    """Length in UTF-16 code units — the unit QString::size() uses in the C++ validator."""
    return len(text.encode("utf-16-le", errors="surrogatepass")) // 2


def _reject(name: str):
    raise ValueError(f"constante não permitida: {name}")
