"""YARA engine: detection rules (signatures/yara, updatable) + internal capability indicators.

Detection rule metadata contract (see docs/DETECTION_RULES.md)::

    meta:
        description = "texto em pt-BR"
        category    = "<ThreatCategory value>"      # e.g. cryptominer, rat, test_file
        severity    = "CRITICAL|HIGH|MEDIUM|LOW|INFO"
        confidence  = "HIGH|MEDIUM|LOW"
        verdict     = "malware|pua|suspicious|crack|mod|info|test"
        fp_note     = "quando pode ser falso positivo"
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yara

from .. import app_paths
from ..core.models import Confidence, Evidence, EvidenceSource, Location, RiskLevel, ThreatCategory, printable_excerpt
from .indicators import INDICATORS, PACKER_MARKERS

log = logging.getLogger(__name__)

RULE_EXTENSIONS = (".yar", ".yara")
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": ""}
MATCH_TIMEOUT = 60
MAX_INSTANCES_PER_STRING = 3
MAX_LOCATIONS = 8

yara.set_config(max_match_data=96)

Locator = Callable[[int], tuple[str | None, int | None]]   # offset -> (section, rva)


@dataclass
class RulesetInfo:
    files: list[str] = field(default_factory=list)
    rule_count: int = 0
    fingerprint: str = ""
    errors: list[str] = field(default_factory=list)
    version: str = ""


@dataclass
class IndicatorHit:
    id: str
    group: str
    description: str
    locations: list[Location] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)      # distinct matched texts (excerpts)


# ---------------------------------------------------------------- rule sources

def rule_sources(extra_dirs: list[Path] | None = None) -> dict[str, Path]:
    """Base rules + rules from the active update package (same file name overrides)."""
    sources: dict[str, Path] = {}
    dirs = [app_paths.builtin_signatures_dir() / "yara", app_paths.active_signatures_dir() / "yara"]
    dirs += list(extra_dirs or [])
    for directory in dirs:
        if directory.is_dir():
            for path in sorted(directory.rglob("*")):
                if path.suffix.lower() in RULE_EXTENSIONS and path.is_file():
                    sources[path.name] = path
    return sources


def _fingerprint(sources: dict[str, Path]) -> str:
    h = hashlib.sha256()
    for name in sorted(sources):
        h.update(name.encode())
        h.update(sources[name].read_bytes())
    return h.hexdigest()[:16]


def _count_rules(rules: yara.Rules) -> int:
    return sum(1 for _ in rules)


def compile_detection_rules(sources: dict[str, Path] | None = None) -> tuple[yara.Rules | None, RulesetInfo]:
    sources = rule_sources() if sources is None else sources
    info = RulesetInfo(files=sorted(sources))
    if not sources:
        info.errors.append("nenhum arquivo de regras YARA encontrado")
        return None, info
    good: dict[str, str] = {}
    for name, path in sources.items():
        try:
            yara.compile(filepath=str(path), externals=EXTERNALS)
        except yara.Error as exc:  # isolate broken files instead of losing the whole ruleset
            info.errors.append(f"{name}: {exc}")
            continue
        good[name] = str(path)
    if not good:
        return None, info
    rules = yara.compile(filepaths={f"ns{i}": p for i, p in enumerate(good.values())}, externals=EXTERNALS)
    info.rule_count = _count_rules(rules)
    info.fingerprint = _fingerprint({k: Path(v) for k, v in good.items()})
    manifest_version = _active_version()
    info.version = manifest_version or f"base-{info.fingerprint[:8]}"
    return rules, info


def _active_version() -> str:
    manifest = app_paths.active_signatures_dir() / "manifest.json"
    if manifest.is_file():
        import json

        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            return str(data.get("components", {}).get("yara", {}).get("version") or data.get("version") or "")
        except (OSError, ValueError):
            return ""
    return ""


def validate_rules_dir(path: str | Path) -> tuple[bool, list[str], int]:
    """Used by the update installer on a staged package: every file must compile."""
    directory = Path(path)
    files = [p for p in sorted(directory.rglob("*")) if p.suffix.lower() in RULE_EXTENSIONS and p.is_file()]
    if not files:
        return False, ["o pacote não contém arquivos .yar/.yara"], 0
    messages, total = [], 0
    for f in files:
        try:
            rules = yara.compile(filepath=str(f), externals=EXTERNALS)
        except yara.Error as exc:
            messages.append(f"{f.name}: erro de compilação: {exc}")
            continue
        n = _count_rules(rules)
        total += n
        missing = [r.identifier for r in rules if "category" not in r.meta or "severity" not in r.meta]
        if missing:
            messages.append(f"{f.name}: regras sem metadados obrigatórios (category/severity): {', '.join(missing[:5])}")
    ok = not messages
    if ok:
        messages.append(f"{len(files)} arquivo(s), {total} regra(s) válidas")
    return ok, messages, total


# ---------------------------------------------------------------- indicator ruleset

def _yara_literal(text: str) -> str:
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("".join(f"\\x{b:02x}" for b in ch.encode("utf-8")))
    return '"' + "".join(out) + '"'


def _yara_regex(pattern: str) -> str:
    return "/" + pattern.replace("/", "\\/") + "/"


def indicator_source() -> str:
    lines = []
    for ind in INDICATORS:
        mods = " ascii" + (" wide" if ind.wide else "") + (" nocase" if ind.nocase else "")
        strings = []
        for i, pat in enumerate(ind.patterns):
            if pat.startswith("re:"):
                strings.append(f"        $s{i} = {_yara_regex(pat[3:])}{mods}")
            else:
                strings.append(f"        $s{i} = {_yara_literal(pat)}{mods}")
        cond = "any of them" if ind.min_matches <= 1 else f"{min(ind.min_matches, len(ind.patterns))} of them"
        lines.append(f"rule IND_{ind.id} {{\n    strings:\n" + "\n".join(strings) + f"\n    condition:\n        {cond}\n}}")
    for idx, (name, pats) in enumerate(PACKER_MARKERS):
        strings = "\n".join(f"        $s{i} = {_yara_literal(p)} ascii wide" for i, p in enumerate(pats))
        safe = "".join(c if c.isalnum() else "_" for c in name)
        lines.append(f"rule PKR_{idx}_{safe} {{\n    meta:\n        marker = {_yara_literal(name)}\n    strings:\n"
                     f"{strings}\n    condition:\n        any of them\n}}")
    return "\n\n".join(lines)


_INDICATOR_BY_ID = {ind.id: ind for ind in INDICATORS}


def compile_indicator_rules() -> yara.Rules:
    return yara.compile(source=indicator_source())


# ---------------------------------------------------------------- engine

class YaraEngine:
    """Holds compiled rulesets. Instantiated once per worker process."""

    def __init__(self, detection: yara.Rules | None, indicators: yara.Rules | None, info: RulesetInfo | None = None):
        self.detection = detection
        self.indicators = indicators
        self.info = info or RulesetInfo()

    @classmethod
    def load(cls) -> "YaraEngine":
        detection, info = compile_detection_rules()
        return cls(detection, compile_indicator_rules(), info)

    @classmethod
    def from_files(cls, detection_path: str | None, indicator_path: str | None) -> "YaraEngine":
        det = yara.load(detection_path) if detection_path else None
        ind = yara.load(indicator_path) if indicator_path else None
        return cls(det, ind)

    def _match(self, rules: yara.Rules, path: str | None, data: bytes | None, externals: dict) -> list:
        if data is not None:
            return rules.match(data=data, externals=externals, timeout=MATCH_TIMEOUT)
        return rules.match(filepath=path, externals=externals, timeout=MATCH_TIMEOUT)

    @staticmethod
    def _externals(name: str, path: str, file_type: str) -> dict:
        ext = Path(name).suffix.lower().lstrip(".")
        return {"filename": name, "filepath": path, "extension": ext, "filetype": file_type}

    def scan(self, *, path: str | None = None, data: bytes | None = None, name: str = "", display_path: str = "",
             file_type: str = "", locator: Locator | None = None
             ) -> tuple[list[Evidence], list[IndicatorHit], list[str], list[str]]:
        """Return (detection evidences, indicator hits, packer markers, errors)."""
        externals = self._externals(name, display_path or path or "", file_type)
        evidences: list[Evidence] = []
        hits: list[IndicatorHit] = []
        markers: list[str] = []
        errors: list[str] = []
        if self.detection is not None:
            try:
                for m in self._match(self.detection, path, data, externals):
                    evidences.append(self._detection_evidence(m, locator))
            except yara.TimeoutError:
                errors.append("YARA: tempo limite excedido nas regras de detecção")
            except yara.Error as exc:
                errors.append(f"YARA: {exc}")
        if self.indicators is not None:
            try:
                for m in self._match(self.indicators, path, data, externals):
                    if m.rule.startswith("PKR_"):
                        markers.append(str(m.meta.get("marker", m.rule)))
                        continue
                    ind = _INDICATOR_BY_ID.get(m.rule[4:])
                    if ind is None:
                        continue
                    hit = IndicatorHit(ind.id, ind.group, ind.description)
                    seen = set()
                    for sm in m.strings:
                        for inst in sm.instances[:MAX_INSTANCES_PER_STRING]:
                            text = _decode_match(inst.matched_data)
                            if text.lower() not in seen:
                                seen.add(text.lower())
                                hit.matched.append(text)
                            if len(hit.locations) < MAX_LOCATIONS:
                                section, rva = locator(inst.offset) if locator else (None, None)
                                hit.locations.append(Location(kind="string", section=section, offset=inst.offset,
                                                              rva=rva, length=inst.matched_length, excerpt=text))
                    hits.append(hit)
            except yara.TimeoutError:
                errors.append("YARA: tempo limite excedido nos indicadores de capacidade")
            except yara.Error as exc:
                errors.append(f"YARA (indicadores): {exc}")
        return evidences, hits, markers, errors

    @staticmethod
    def _detection_evidence(match, locator: Locator | None) -> Evidence:
        meta = match.meta
        try:
            category = ThreatCategory(str(meta.get("category", "generic_malware")))
        except ValueError:
            category = ThreatCategory.GENERIC_MALWARE
        verdict = str(meta.get("verdict", "suspicious")).lower()
        locations: list[Location] = []
        for sm in match.strings:
            for inst in sm.instances[:MAX_INSTANCES_PER_STRING]:
                if len(locations) >= MAX_LOCATIONS:
                    break
                section, rva = locator(inst.offset) if locator else (None, None)
                locations.append(Location(kind="yara_match", description=sm.identifier, section=section,
                                          offset=inst.offset, rva=rva, length=inst.matched_length,
                                          excerpt=_decode_match(inst.matched_data)))
        if not locations:
            locations.append(Location(kind="yara_match", description="condição estrutural (sem strings)"))
        return Evidence(
            rule_id=f"YARA.{match.rule}",
            title=str(meta.get("title") or meta.get("description") or match.rule),
            source=EvidenceSource.YARA,
            category=category,
            severity=RiskLevel.parse(meta.get("severity", "MEDIUM"), RiskLevel.MEDIUM),
            confidence=Confidence.parse(meta.get("confidence", "MEDIUM")),
            description=str(meta.get("description", "")),
            engine="yara",
            locations=locations,
            details={"rule": match.rule, "namespace": match.namespace, "verdict": verdict,
                     "reference": str(meta.get("reference", "")), "tags": list(match.tags)},
            fp_note=str(meta.get("fp_note", "")),
            tags=[f"verdict:{verdict}", *match.tags],
        )


def _decode_match(data: bytes) -> str:
    if len(data) >= 4 and data[1:2] == b"\x00" and data[3:4] == b"\x00":
        try:
            return printable_excerpt(data.decode("utf-16-le", errors="replace"), 96)
        except Exception:  # pragma: no cover
            pass
    return printable_excerpt(data, 96)


def yara_version() -> str:
    return getattr(yara, "__version__", "?")
