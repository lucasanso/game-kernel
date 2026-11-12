"""Forensic reports (JSON, self-contained HTML, PDF) for one scan.

Runs inside the helper process (service ``reports.generate``, see gamekernel/helper/services/reports.py)
and from Python tools. The database is opened **read-only** (``PRAGMA query_only``): report
generation can never modify scan data.

Report content (``gamekernel-report`` v1), as required by the product specification §16:
 1 computer information (minimal, no personal data) · 2 analysed targets · 3 date and duration ·
 4 files found · 5 files examined · 6 files not examined (with reasons) · 7 threats · 8 suspicious
 files · 9 technical evidence (rule, source, location: section/offset/RVA/line/excerpt) · 10 full
 paths · 11 SHA-256 · 12 risk level · 13 explanation · 14 recommendations · 15 limitations —
 plus one individual report per crack component (special module).

Personal data: user-name path segments and the host name are redacted unless the user opts in
(settings ``reports.redact_username`` / ``reports.include_hostname``).
"""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import json
import logging
import os
import re
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .. import APP_NAME, __version__
from ..database.db import _row_to_result
from ..core import threat_catalog
from ..core.models import AnalysisStatus, Classification, CrackStatus, EvidenceSource, FileResult, RiskLevel, ThreatCategory
from ..core.scan_api import ScanMode, ScanStatus
from . import sysinfo

log = logging.getLogger(__name__)

REPORT_FORMAT = "gamekernel-report"
REPORT_FORMAT_VERSION = 1
FORMATS = ("json", "html", "pdf")
MAX_LISTED_FINDINGS = 20000

GENERAL_LIMITATIONS = (
    "O Game Kernel funciona sem internet: as assinaturas só são atualizadas por pacotes importados manualmente. "
    "Ameaças surgidas depois da última atualização podem não ser reconhecidas por assinatura.",
    "A análise estática não executa os arquivos. Cargas baixadas da internet em tempo de execução, código cifrado "
    "ou empacotado e comportamentos ativados por condições específicas podem não ser visíveis.",
    "Indicadores heurísticos (entropia alta, ausência de assinatura digital, empacotamento, APIs sensíveis) são "
    "sinais que pedem investigação, não provas de malware. Jogos, launchers, DRM e cracks usam técnicas semelhantes.",
    "A ausência de detecções não garante que um arquivo seja seguro.",
    "Arquivos não examinados (excluídos, ilegíveis, acima dos limites ou protegidos por senha) podem conter ameaças.",
    "Os níveis de risco são classificações qualitativas baseadas em evidências; não são probabilidades de infecção.",
)

_CLEAN_CLASSES = (Classification.UNKNOWN.value, Classification.KNOWN_LEGIT.value)


class ReportError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code   # matches gk-ipc error codes: not_found, invalid_params, io_error, cancelled


@dataclass
class ReportOptions:
    include_clean: bool = False
    redact_username: bool = True
    include_hostname: bool = False
    max_listed: int = MAX_LISTED_FINDINGS


# ---------------------------------------------------------------------------- redaction
class Redactor:
    """Removes the user name (as a path segment) and the host name from every string."""

    def __init__(self, usernames: Iterable[str] = (), hostname: str | None = None):
        names = sorted({u for u in usernames if u and len(u) >= 2}, key=len, reverse=True)
        self._user_re = (
            re.compile(r"(?i)(?<=[\\/])(" + "|".join(re.escape(u) for u in names) + r")(?=[\\/]|$)") if names else None
        )
        self._host_re = (
            re.compile(r"(?i)(?<![\w.-])" + re.escape(hostname) + r"(?![\w.-])") if hostname and len(hostname) >= 2
            else None
        )

    @classmethod
    def for_current_user(cls, redact_username: bool, include_hostname: bool) -> "Redactor":
        users: set[str] = set()
        if redact_username:
            for candidate in (os.environ.get("USERNAME"), os.environ.get("USER")):
                if candidate:
                    users.add(candidate)
            try:
                users.add(getpass.getuser())
            except (OSError, KeyError):  # pragma: no cover - no passwd entry
                pass
            users.add(Path.home().name)
        hostname = None
        if not include_hostname:
            import platform

            hostname = platform.node() or None
        return cls(users, hostname)

    def text(self, value: str) -> str:
        if self._user_re is not None:
            value = self._user_re.sub("<usuário>", value)
        if self._host_re is not None:
            value = self._host_re.sub("<computador>", value)
        return value

    def apply(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, list):
            return [self.apply(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.apply(v) for k, v in obj.items()}
        return obj


# ---------------------------------------------------------------------------- database access
class ReadOnlyStore:
    """Read-only view of the Game Kernel database (never creates or modifies it)."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        if not self.path.is_file():
            raise ReportError("not_found", f"banco de dados não encontrado: {self.path}")
        self.conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA query_only=ON")
        self.conn.execute("PRAGMA busy_timeout=30000")

    def close(self) -> None:
        self.conn.close()

    def scan(self, scan_id: int) -> dict:
        row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            raise ReportError("not_found", f"varredura {scan_id} não encontrada")
        d = dict(row)
        d["targets"] = json.loads(d["targets"] or "[]")
        d["options"] = json.loads(d["options"]) if d.get("options") else {}
        d["summary"] = json.loads(d["summary"]) if d.get("summary") else {}
        d["max_risk"] = RiskLevel(d["max_risk"] or 0)
        return d

    def grouped(self, scan_id: int, column: str) -> dict[str, int]:
        if column not in ("classification", "risk", "status", "crack_status"):
            raise ValueError(column)
        rows = self.conn.execute(f"SELECT {column}, COUNT(*) FROM scan_files WHERE scan_id=? GROUP BY {column}",
                                 (scan_id,)).fetchall()
        if column == "risk":
            return {RiskLevel(r[0]).name: r[1] for r in rows}
        return {r[0]: r[1] for r in rows}

    def findings(self, scan_id: int, limit: int) -> list[FileResult]:
        rows = self.conn.execute(
            "SELECT * FROM scan_files WHERE scan_id=? AND (risk>=? OR classification NOT IN (?,?) OR status<>?"
            " OR crack_status<>'none' OR possible_fp=1) ORDER BY risk DESC, path LIMIT ?",
            (scan_id, int(RiskLevel.INFO), *_CLEAN_CLASSES, AnalysisStatus.COMPLETE.value, limit),
        ).fetchall()
        return [_row_to_result(r) for r in rows]

    def count_findings(self, scan_id: int) -> int:
        return int(self.conn.execute(
            "SELECT COUNT(*) FROM scan_files WHERE scan_id=? AND (risk>=? OR classification NOT IN (?,?) OR status<>?"
            " OR crack_status<>'none' OR possible_fp=1)",
            (scan_id, int(RiskLevel.INFO), *_CLEAN_CLASSES, AnalysisStatus.COMPLETE.value),
        ).fetchone()[0])

    def clean(self, scan_id: int, limit: int) -> list[FileResult]:
        rows = self.conn.execute(
            "SELECT * FROM scan_files WHERE scan_id=? AND risk<? AND classification IN (?,?) AND status=?"
            " AND crack_status='none' AND possible_fp=0 ORDER BY path LIMIT ?",
            (scan_id, int(RiskLevel.INFO), *_CLEAN_CLASSES, AnalysisStatus.COMPLETE.value, limit),
        ).fetchall()
        return [_row_to_result(r) for r in rows]

    def count_clean(self, scan_id: int) -> int:
        return int(self.conn.execute(
            "SELECT COUNT(*) FROM scan_files WHERE scan_id=? AND risk<? AND classification IN (?,?) AND status=?"
            " AND crack_status='none' AND possible_fp=0",
            (scan_id, int(RiskLevel.INFO), *_CLEAN_CLASSES, AnalysisStatus.COMPLETE.value),
        ).fetchone()[0])


# ---------------------------------------------------------------------------- data model
def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _label(enum_cls, value, default: str = "") -> str:
    try:
        return enum_cls(value).label
    except (ValueError, KeyError):
        return default or str(value)


def _evidence_entry(ev) -> dict[str, Any]:
    return {
        "rule_id": ev.rule_id,
        "title": ev.title,
        "source": ev.source.value,
        "source_label": ev.source.label,
        "engine": ev.engine,
        "category": ev.category.value,
        "category_label": threat_catalog.info(ev.category).label,
        "severity": ev.severity.name,
        "severity_label": ev.severity.label,
        "effective_severity": ev.effective_severity.name,
        "effective_severity_label": ev.effective_severity.label,
        "confidence": ev.confidence.name,
        "confidence_label": ev.confidence.label,
        "description": ev.description,
        "locations": [dict(loc.to_dict(), summary=loc.short()) for loc in ev.locations],
        "fp_note": ev.fp_note,
        "adjustment_reason": ev.adjustment_reason,
        "details": ev.details,
        "generic_indicator": ev.source in (EvidenceSource.HEURISTIC, EvidenceSource.CONTEXT),
    }


def _detections(r: FileResult) -> list[str]:
    names = []
    for ev in r.evidences:
        if ev.source in (EvidenceSource.SIGNATURE, EvidenceSource.YARA, EvidenceSource.REPUTATION):
            names.append(f"{ev.engine or ev.source.value}: {ev.rule_id}")
    return names


def file_entry(r: FileResult) -> dict[str, Any]:
    category = r.primary_category
    info = threat_catalog.info(category) if category else None
    return {
        "name": r.name,
        "path": r.path,
        "directory": r.directory,
        "extension": r.extension,
        "size": r.size,
        "sha256": r.sha256,
        "md5": r.md5,
        "file_type": r.file_type,
        "container": r.container,
        "member_path": r.member_path,
        "physical_file": r.container or r.path,
        "depth": r.depth,
        "status": r.status.value,
        "status_label": r.status.label,
        "status_reasons": r.status_reasons,
        "risk": r.risk.name,
        "risk_label": r.risk.label,
        "risk_meaning": r.risk.meaning,
        "classification": r.classification.value,
        "classification_label": r.classification.label,
        "crack_status": r.crack_status.value,
        "crack_status_label": r.crack_status.label,
        "category": category.value if category else None,
        "category_label": info.label if info else None,
        "threat_info": {
            "summary": info.summary, "can_do": info.can_do, "data_at_risk": info.data_at_risk,
            "detection": info.detection, "limitations": info.limitations,
        } if info else None,
        "detections": _detections(r),
        "evidences": [_evidence_entry(ev) for ev in sorted(r.evidences, key=lambda e: -int(e.effective_severity))],
        "explanation": r.explanation,
        "recommendations": r.recommendations or (list(info.recommendations) if info else []),
        "possible_false_positive": r.possible_false_positive,
        "fp_notes": sorted({ev.fp_note for ev in r.evidences if ev.fp_note}),
        "signer": r.features.signer,
        "signed": r.features.signed,
        "signature_valid": r.features.signature_valid,
        "analyzed_at": _iso(r.analyzed_at),
        "engines": r.engines,
    }


_CRACK_MODIFICATION = {
    "emulator": "Emulador de plataforma (Steam/Epic/Ubisoft/GOG) substituindo a API original",
    "steam_emu": "Emulador de Steam",
    "patched_exe": "Executável do jogo modificado (patch de DRM)",
    "dll_proxy": "DLL proxy/substituída",
    "loader": "Loader/injetor de mod",
    "keygen": "Gerador de chaves (keygen)",
    "unlocker": "Desbloqueador de conteúdo (DLC unlocker)",
    "repack_installer": "Instalador de repack",
}


def crack_entry(r: FileResult) -> dict[str, Any]:
    """Individual crack report (special module §5): name/location, SHA-256, modification type,
    signature, evidence, potential risks, false-positive possibility, recommendation."""
    entry = file_entry(r)
    kinds = []
    for ev in r.evidences:
        if ev.category in (ThreatCategory.CRACK_COMPONENT, ThreatCategory.MOD_COMPONENT) or ev.source == EvidenceSource.CONTEXT:
            kind = str(ev.details.get("modification") or ev.details.get("kind") or "")
            kinds.append(_CRACK_MODIFICATION.get(kind, ev.title))
    threats = [e for e in entry["evidences"]
               if e["category"] not in (ThreatCategory.CRACK_COMPONENT.value, ThreatCategory.MOD_COMPONENT.value)
               and RiskLevel[e["effective_severity"]] >= RiskLevel.LOW]
    if r.crack_status == CrackStatus.MALWARE:
        recommendation = ("Não execute este crack. Há detecção de malware: coloque-o em quarentena e obtenha o jogo "
                          "por uma fonte confiável.")
    elif r.crack_status == CrackStatus.SUSPICIOUS:
        recommendation = ("Não execute antes de investigar: o crack apresenta indicadores além do esperado para "
                          "contornar DRM. Considere a análise comportamental na sandbox isolada.")
    elif r.crack_status == CrackStatus.RECOGNIZED_CLEAN:
        recommendation = ("Componente reconhecido, sem evidência de ameaça nos mecanismos executados. Isso não é "
                          "garantia de segurança; mantenha o Microsoft Defender ativo.")
    else:
        recommendation = ("Evidências insuficientes para uma conclusão. Compare o SHA-256 com fontes confiáveis e, "
                          "se possível, use a análise comportamental na sandbox isolada.")
    entry.update({
        "modification_types": sorted(set(kinds)) or ["Modificação não identificada"],
        "potential_risks": sorted({e["category_label"] for e in threats}),
        "threat_evidence_count": len(threats),
        "crack_recommendation": recommendation,
    })
    return entry


def _global_recommendations(threats: int, suspicious: int, pua: int, not_examined: int, cracks: int,
                            stale: bool) -> list[str]:
    out = []
    if threats:
        out.append("Não execute os arquivos classificados como malware. Coloque-os em quarentena (ação reversível) "
                   "e não restaure sem certeza de que se trata de falso positivo.")
        out.append("Se algum desses arquivos já foi executado: desconecte o computador da rede, execute a verificação "
                   "offline do Microsoft Defender e troque suas senhas a partir de outro dispositivo confiável.")
    if suspicious:
        out.append("Arquivos suspeitos exigem investigação: leia as evidências técnicas, compare os hashes com fontes "
                   "confiáveis e, se possível, use a análise comportamental na sandbox isolada antes de executá-los.")
    if pua:
        out.append("Programas potencialmente indesejados podem instalar componentes extras ou exibir anúncios; "
                   "remova-os se não forem necessários.")
    if cracks:
        out.append("Componentes de crack foram identificados. A presença de um crack não indica malware por si só, "
                   "mas cracks são um veículo comum de ameaças; revise o relatório individual de cada um.")
    if not_examined:
        out.append("Alguns arquivos não foram examinados por completo (veja a seção correspondente). Eles podem "
                   "esconder ameaças; ajuste os limites nas configurações ou analise-os separadamente.")
    if stale:
        out.append("As assinaturas estão desatualizadas. Importe um pacote de atualização offline verificado e "
                   "repita a análise.")
    out.append("Mantenha o Microsoft Defender ativo: o Game Kernel é complementar e não substitui a proteção do Windows.")
    return out


def build_report(store: ReadOnlyStore, scan_id: int, options: ReportOptions,
                 check: Callable[[], None] | None = None) -> dict[str, Any]:
    check = check or (lambda: None)
    scan = store.scan(scan_id)
    summary = scan.get("summary") or {}
    by_class = store.grouped(scan_id, "classification")
    by_risk = store.grouped(scan_id, "risk")
    by_status = store.grouped(scan_id, "status")
    check()

    total_findings = store.count_findings(scan_id)
    findings = store.findings(scan_id, options.max_listed)
    check()

    threats, suspicious, pua, others, not_examined, cracks = [], [], [], [], [], []
    possible_fp = 0
    for r in findings:
        entry = file_entry(r)
        if r.possible_false_positive:
            possible_fp += 1
        if r.crack_status != CrackStatus.NONE:
            cracks.append(crack_entry(r))
        if r.status in (AnalysisStatus.SKIPPED, AnalysisStatus.ERROR, AnalysisStatus.PARTIAL):
            not_examined.append({
                "path": r.path, "name": r.name, "size": r.size, "sha256": r.sha256, "file_type": r.file_type,
                "status": r.status.value, "status_label": r.status.label, "reasons": r.status_reasons,
                "container": r.container,
            })
            if r.status != AnalysisStatus.PARTIAL and r.classification.value in _CLEAN_CLASSES and r.risk < RiskLevel.LOW:
                continue
        if r.classification == Classification.MALWARE:
            threats.append(entry)
        elif r.classification == Classification.SUSPICIOUS:
            suspicious.append(entry)
        elif r.classification == Classification.PUA:
            pua.append(entry)
        elif r.risk >= RiskLevel.INFO or r.classification.value not in _CLEAN_CLASSES or r.possible_false_positive:
            others.append(entry)
        check()

    clean_count = store.count_clean(scan_id)
    clean_files = []
    if options.include_clean:
        clean_files = [{"path": r.path, "size": r.size, "sha256": r.sha256, "file_type": r.file_type,
                        "classification_label": r.classification.label}
                       for r in store.clean(scan_id, options.max_listed)]

    signatures = summary.get("signatures") or {}
    stale = bool(signatures.get("stale")) if signatures else False
    limitations = list(dict.fromkeys(list(summary.get("limitations") or []) + list(GENERAL_LIMITATIONS)))
    if total_findings > len(findings):
        limitations.insert(0, f"O relatório lista as {len(findings)} ocorrências de maior risco de um total de "
                              f"{total_findings}; a lista completa está no banco local do Game Kernel.")
    started, finished = scan["started_at"], scan.get("finished_at")
    mode = scan.get("mode") or "deep"
    status = scan.get("status") or "completed"

    report = {
        "format": REPORT_FORMAT,
        "format_version": REPORT_FORMAT_VERSION,
        "generated_at": _iso(time.time()),
        "generator": {"application": APP_NAME, "version": __version__},
        "computer": sysinfo.collect(include_hostname=options.include_hostname),
        "scan": {
            "id": scan["id"],
            "label": scan.get("label") or "",
            "origin": scan.get("origin") or "manual",
            "mode": mode,
            "mode_label": _label(ScanMode, mode),
            "status": status,
            "status_label": _label(ScanStatus, status),
            "targets": scan["targets"],
            "started_at": _iso(started),
            "finished_at": _iso(finished),
            "duration_seconds": round(max(0.0, (finished or started) - started), 1),
            "error": scan.get("error"),
        },
        "counts": {
            "files_found": scan.get("files_found", 0),
            "files_analyzed": scan.get("files_analyzed", 0),
            "files_skipped": scan.get("files_skipped", 0),
            "files_errors": scan.get("files_errors", 0),
            "members_analyzed": scan.get("members_analyzed", 0),
            "bytes_scanned": scan.get("bytes_scanned", 0),
            "threats": by_class.get(Classification.MALWARE.value, 0),
            "suspicious": by_class.get(Classification.SUSPICIOUS.value, 0),
            "pua": by_class.get(Classification.PUA.value, 0),
            "possible_false_positives": possible_fp,
            "not_examined": sum(v for k, v in by_status.items() if k != AnalysisStatus.COMPLETE.value),
            "cracks": len(cracks),
            "clean": clean_count,
            "by_classification": {k: {"count": v, "label": _label(Classification, k)} for k, v in by_class.items()},
            "by_risk": {k: {"count": v, "label": RiskLevel[k].label} for k, v in by_risk.items()},
            "by_status": {k: {"count": v, "label": _label(AnalysisStatus, k)} for k, v in by_status.items()},
        },
        "max_risk": {"level": scan["max_risk"].name, "label": scan["max_risk"].label,
                     "meaning": scan["max_risk"].meaning},
        "engines": summary.get("engines") or [],
        "signatures": signatures,
        "threats": threats,
        "suspicious": suspicious,
        "pua": pua,
        "other_findings": others,
        "not_examined": not_examined,
        "cracks": cracks,
        "clean_files": clean_files,
        "recommendations": _global_recommendations(len(threats), len(suspicious), len(pua), len(not_examined),
                                                   len(cracks), stale),
        "limitations": limitations,
        "warnings": list(summary.get("warnings") or []),
        "risk_scale": [{"level": lvl.name, "label": lvl.label, "meaning": lvl.meaning}
                       for lvl in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO)],
        "evidence_sources": [{"source": s.value, "label": s.label} for s in EvidenceSource],
        "privacy": {
            "username_redacted": options.redact_username,
            "hostname_included": options.include_hostname,
            "note": "Nenhum dado deste relatório foi enviado a serviços externos.",
        },
    }
    redactor = Redactor.for_current_user(options.redact_username, options.include_hostname)
    return redactor.apply(report)


# ---------------------------------------------------------------------------- output
def _atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".gk-report-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def render_json(report: dict[str, Any]) -> bytes:
    return json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")


def report_basename(report: dict[str, Any]) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return f"GameKernel-varredura-{report['scan']['id']}-{stamp}"


def generate(db_path: str | os.PathLike, scan_id: int, formats: Iterable[str], output_dir: str | os.PathLike,
             options: ReportOptions | None = None, check: Callable[[], None] | None = None,
             progress: Callable[[str, dict], None] | None = None) -> dict[str, Any]:
    """Generate the requested formats. Returns {"files": [...], "counts": {...}, "warnings": [...]}."""
    formats = list(dict.fromkeys(formats))
    unknown = [f for f in formats if f not in FORMATS]
    if not formats or unknown:
        raise ReportError("invalid_params", f"formatos inválidos: {unknown or formats}")
    out_dir = Path(output_dir)
    if not out_dir.is_absolute() or not out_dir.is_dir():
        raise ReportError("invalid_params", f"pasta de saída inválida: {out_dir}")
    options = options or ReportOptions()
    progress = progress or (lambda stage, data: None)
    check = check or (lambda: None)

    progress("load", {"scan_id": scan_id})
    store = ReadOnlyStore(db_path)
    try:
        report = build_report(store, scan_id, options, check)
    finally:
        store.close()

    base = report_basename(report)
    files = []
    warnings: list[str] = []
    for fmt in formats:
        check()
        progress(fmt, {"scan_id": scan_id})
        target = out_dir / f"{base}.{fmt}"
        if fmt == "json":
            data = render_json(report)
        elif fmt == "html":
            from .render_html import render_html

            data = render_html(report).encode("utf-8")
        else:
            from .render_pdf import render_pdf

            data, pdf_warnings = render_pdf(report)
            warnings.extend(pdf_warnings)
        try:
            _atomic_write(target, data)
        except OSError as exc:
            raise ReportError("io_error", f"não foi possível gravar {target}: {exc}") from None
        files.append({"format": fmt, "path": str(target), "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()})
    return {"scan_id": scan_id, "files": files, "counts": report["counts"], "max_risk": report["max_risk"],
            "warnings": warnings}
