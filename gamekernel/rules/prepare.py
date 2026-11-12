"""Preparation and lint of YARA rule sets before they are packaged.

Compilation uses yara-python with the same constraints as the C++ installer
(gk::updates::validateYaraDir): one namespace per file, ``include`` refused, external
variables ``filename``, ``filepath``, ``extension``, ``filetype`` defined as strings.
Metadata lint makes every rule explainable in the UI and reports (spec: show the rule
responsible for a detection, its category and the false-positive possibility).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.models import RiskLevel, ThreatCategory

EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": ""}
REQUIRED_META = ("description", "category", "severity", "author")
RECOMMENDED_META = ("fp_note", "reference_date")
SEVERITIES = {lvl.name for lvl in RiskLevel if lvl != RiskLevel.NONE}
CATEGORIES = {c.value for c in ThreatCategory}
MAX_FILE = 64 * 1024 * 1024


@dataclass
class YaraReport:
    ok: bool = False
    rule_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)   # {namespace, identifier, category, severity}

    def to_dict(self) -> dict:
        return {"ok": self.ok, "rule_count": self.rule_count, "errors": self.errors, "warnings": self.warnings,
                "rules": self.rules}


def check_rules_dir(directory: str | Path, strict_meta: bool = False) -> YaraReport:
    try:
        import yara
    except ImportError as exc:  # pragma: no cover - yara-python is a pinned dependency
        return YaraReport(errors=[f"yara-python indisponível: {exc}"])
    report = YaraReport()
    files = sorted((p for p in Path(directory).iterdir() if p.is_file()), key=lambda p: p.name)
    if not files:
        report.errors.append("componente YARA sem arquivos")
        return report
    sources: dict[str, str] = {}
    per_file: list[tuple[str, object]] = []
    for path in files:
        if path.suffix.lower() not in (".yar", ".yara"):
            report.errors.append(f"{path.name}: extensão não permitida")
            continue
        if path.stat().st_size > MAX_FILE:
            report.errors.append(f"{path.name}: acima de 64 MB")
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            report.errors.append(f"{path.name}: byte nulo no arquivo de regras")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            report.errors.append(f"{path.name}: não está em UTF-8")
            continue
        sources[path.stem] = text
        try:
            per_file.append((path.stem, yara.compile(source=text, includes=False, externals=EXTERNALS)))
        except yara.SyntaxError as exc:
            report.errors.append(f"{path.name}: {exc}")
        except yara.Error as exc:
            report.errors.append(f"{path.name}: {exc}")
    if report.errors:
        return report
    try:   # the whole set, as the engine loads it (one namespace per file)
        yara.compile(sources=sources, includes=False, externals=EXTERNALS)
    except yara.Error as exc:
        report.errors.append(str(exc))
        return report
    seen: dict[str, str] = {}
    for namespace, compiled in per_file:
        for rule in compiled:
            _lint_rule(report, namespace, rule, seen, strict_meta)
    report.rule_count = len(report.rules)
    if report.rule_count == 0:
        report.errors.append("nenhuma regra encontrada")
    report.ok = not report.errors
    return report


def _lint_rule(report: YaraReport, namespace: str, rule, seen: dict[str, str], strict_meta: bool) -> None:
    meta = dict(rule.meta)
    entry = {"namespace": namespace, "identifier": rule.identifier,
             "category": meta.get("category"), "severity": meta.get("severity")}
    report.rules.append(entry)
    where = f"{namespace}:{rule.identifier}"
    missing = [k for k in REQUIRED_META if not meta.get(k)]
    if missing:
        (report.errors if strict_meta else report.warnings).append(f"{where}: meta ausente: {', '.join(missing)}")
    if meta.get("category") and meta["category"] not in CATEGORIES:
        report.errors.append(f"{where}: categoria desconhecida {meta['category']!r}")
    if meta.get("severity") and str(meta["severity"]).upper() not in SEVERITIES:
        report.errors.append(f"{where}: severidade inválida {meta['severity']!r}")
    for key in RECOMMENDED_META:
        if not meta.get(key):
            report.warnings.append(f"{where}: meta recomendada ausente: {key}")
    if rule.identifier in seen and seen[rule.identifier] != namespace:
        report.warnings.append(f"{where}: identificador repetido em {seen[rule.identifier]} (namespaces diferentes)")
    seen.setdefault(rule.identifier, namespace)
