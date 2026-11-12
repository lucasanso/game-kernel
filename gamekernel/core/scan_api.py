"""Public contract between the scanning core (Agent A) and its consumers: UI, real-time
monitor, CLI, reports (Agent B).

The *implementation* lives in ``gamekernel.core.scanner.Scanner``. Consumers must only
depend on the names defined here (plus ``core.models``) so both sides can evolve
independently. Changing this file requires agreement of both agents (see docs/WORK_SPLIT.md).

Threading contract
------------------
* ``Scanner.run(options)`` is **blocking**; call it from a background thread (the UI wraps
  it in a QThread). It returns a ``ScanSummary``.
* Callbacks (``on_progress``, ``on_result``, ``on_log``) are invoked from the thread that
  called ``run`` — never from worker processes. The UI must re-emit them as Qt signals.
* ``pause()``, ``resume()`` and ``cancel()`` are thread-safe and may be called from any thread.
* ``on_progress`` is rate limited by the scanner (≈ 10 calls/s at most).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Callable, Protocol

from .models import FileResult, RiskLevel


class ScanMode(str, Enum):
    QUICK = "quick"     # executables, scripts, shortcuts, small archives; header sniff of data files
    DEEP = "deep"       # everything incl. nested archives, embedded payloads, extra heuristics

    @property
    def label(self) -> str:
        return {"quick": "Análise rápida", "deep": "Análise profunda"}[self.value]


class ScanPhase(str, Enum):
    PREPARING = "preparing"
    ENUMERATING = "enumerating"
    ANALYZING = "analyzing"
    SIGNATURES = "signatures"      # ClamAV batch passes
    CONTEXT = "context"            # folder-level game/crack correlation + risk aggregation
    SAVING = "saving"
    DONE = "done"

    @property
    def label(self) -> str:
        return {
            "preparing": "Preparando",
            "enumerating": "Enumerando arquivos",
            "analyzing": "Analisando arquivos",
            "signatures": "Verificando assinaturas (ClamAV)",
            "context": "Correlacionando contexto e riscos",
            "saving": "Salvando resultados",
            "done": "Concluído",
        }[self.value]


class ScanStatus(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"   # process ended unexpectedly; can be resumed
    FAILED = "failed"

    @property
    def label(self) -> str:
        return {
            "running": "Em andamento",
            "paused": "Pausada",
            "completed": "Concluída",
            "cancelled": "Cancelada",
            "interrupted": "Interrompida",
            "failed": "Falhou",
        }[self.value]


@dataclass
class ScanOptions:
    targets: list[str]                     # folders and/or files (absolute paths)
    mode: ScanMode = ScanMode.DEEP
    label: str = ""                        # e.g. "Jogo completo", "Arquivos selecionados", "Tempo real"
    origin: str = "manual"                 # manual | realtime | resume | cli
    use_cache: bool = True                 # reuse verdicts of unchanged files (same engine fingerprint)
    resume_of: int | None = None           # scan id being resumed (history "Retomar")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["mode"] = self.mode.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ScanOptions":
        return cls(
            targets=list(d.get("targets", [])),
            mode=ScanMode(d.get("mode", "deep")),
            label=d.get("label", ""),
            origin=d.get("origin", "manual"),
            use_cache=bool(d.get("use_cache", True)),
            resume_of=d.get("resume_of"),
        )


@dataclass
class ScanProgress:
    scan_id: int
    phase: ScanPhase
    files_total: int = 0
    files_done: int = 0
    bytes_total: int = 0
    bytes_done: int = 0
    current_path: str = ""
    threats: int = 0              # classification == MALWARE
    suspicious: int = 0           # classification == SUSPICIOUS
    pua: int = 0
    errors: int = 0
    skipped: int = 0
    members_done: int = 0         # archive members analysed
    elapsed: float = 0.0
    paused: bool = False
    message: str = ""

    @property
    def fraction(self) -> float:
        if self.files_total <= 0:
            return 0.0
        return min(1.0, self.files_done / self.files_total)


@dataclass
class EngineStatus:
    key: str                      # clamav | yara | pe | authenticode | strings | scripts | archives | pyinstaller | reputation | game_context | sandbox
    name: str                     # display name (pt-BR)
    available: bool               # dependency/binary present and working
    enabled: bool                 # enabled in settings
    version: str = ""
    detail: str = ""              # human explanation, e.g. why unavailable


@dataclass
class SignatureOverview:
    clamav_engine_version: str = ""
    clamav_databases: list[dict] = field(default_factory=list)   # [{name, version, signatures, build_time}]
    clamav_signature_count: int = 0
    yara_rule_count: int = 0
    yara_ruleset_version: str = ""
    ioc_count: int = 0
    ioc_version: str = ""
    last_update: float | None = None    # epoch seconds of last verified package install
    newest_signature_date: float | None = None
    stale: bool = True
    stale_reason: str = ""


@dataclass
class ScanSummary:
    scan_id: int
    status: ScanStatus
    mode: ScanMode
    targets: list[str]
    started_at: float
    finished_at: float
    files_found: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    files_errors: int = 0
    members_analyzed: int = 0
    bytes_scanned: int = 0
    counts_by_classification: dict[str, int] = field(default_factory=dict)
    counts_by_risk: dict[str, int] = field(default_factory=dict)
    max_risk: RiskLevel = RiskLevel.NONE
    engines: list[EngineStatus] = field(default_factory=list)
    signatures: SignatureOverview = field(default_factory=SignatureOverview)
    limitations: list[str] = field(default_factory=list)   # what this scan could NOT do (shown in UI/report)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["mode"] = self.mode.value
        d["max_risk"] = self.max_risk.name
        return d


ProgressCallback = Callable[[ScanProgress], None]
ResultCallback = Callable[[FileResult], None]
LogCallback = Callable[[str, str], None]          # (level, message)


class ScannerProtocol(Protocol):
    """Implemented by gamekernel.core.scanner.Scanner(settings, db, on_progress=None, on_result=None, on_log=None)."""

    def run(self, options: ScanOptions) -> ScanSummary: ...

    def pause(self) -> None: ...

    def resume(self) -> None: ...

    def cancel(self) -> None: ...

    @property
    def is_paused(self) -> bool: ...

    @property
    def is_running(self) -> bool: ...
