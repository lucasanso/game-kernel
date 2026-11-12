"""Core data model shared by engines, the risk engine, persistence, UI and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any


class RiskLevel(IntEnum):
    NONE = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return {
            RiskLevel.NONE: "Nenhum",
            RiskLevel.INFO: "Informativo",
            RiskLevel.LOW: "Baixo",
            RiskLevel.MEDIUM: "Médio",
            RiskLevel.HIGH: "Alto",
            RiskLevel.CRITICAL: "Crítico",
        }[self]

    @property
    def meaning(self) -> str:
        return {
            RiskLevel.NONE: "Nenhum indicador de risco foi encontrado pelos mecanismos executados.",
            RiskLevel.INFO: "Informação técnica relevante, sem evidência suficiente de risco.",
            RiskLevel.LOW: "Anomalia ou característica que merece atenção, mas não é prova de ameaça.",
            RiskLevel.MEDIUM: "Comportamento suspeito que exige investigação adicional.",
            RiskLevel.HIGH: "Indicadores fortes de comportamento potencialmente malicioso.",
            RiskLevel.CRITICAL: "Evidência forte de ameaça capaz de comprometer o sistema ou informações pessoais.",
        }[self]

    def down(self, steps: int = 1) -> "RiskLevel":
        return RiskLevel(max(RiskLevel.INFO, self - steps)) if self > RiskLevel.NONE else self

    @classmethod
    def parse(cls, value: Any, default: "RiskLevel" = None) -> "RiskLevel":
        if isinstance(value, RiskLevel):
            return value
        if isinstance(value, int):
            return RiskLevel(value)
        try:
            return cls[str(value).upper()]
        except KeyError:
            return default if default is not None else cls.INFO


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return {Confidence.LOW: "Baixa", Confidence.MEDIUM: "Média", Confidence.HIGH: "Alta"}[self]

    @classmethod
    def parse(cls, value: Any) -> "Confidence":
        if isinstance(value, Confidence):
            return value
        if isinstance(value, int):
            return Confidence(max(1, min(3, value)))
        try:
            return cls[str(value).upper()]
        except KeyError:
            return cls.LOW


class EvidenceSource(str, Enum):
    SIGNATURE = "signature"        # ClamAV signature match
    YARA = "yara"                  # YARA rule
    STATIC = "static"              # concrete structural fact (PE, certificate, file type)
    BEHAVIORAL = "behavioral"      # observed inside the isolated sandbox
    REPUTATION = "reputation"      # local hash database (known good / known bad)
    HEURISTIC = "heuristic"        # inferred capability / correlation of weak indicators
    CONTEXT = "context"            # game / crack / mod context (folder level)

    @property
    def label(self) -> str:
        return {
            "signature": "Detecção confirmada por assinatura",
            "yara": "Detecção por regra YARA",
            "static": "Evidência estática",
            "behavioral": "Evidência comportamental",
            "reputation": "Reputação local",
            "heuristic": "Suspeita heurística",
            "context": "Contexto de jogo/crack",
        }[self.value]


class ThreatCategory(str, Enum):
    TROJAN = "trojan"
    RAT = "rat"
    KEYLOGGER = "keylogger"
    SPYWARE = "spyware"
    PASSWORD_STEALER = "password_stealer"
    COOKIE_STEALER = "cookie_stealer"
    RANSOMWARE = "ransomware"
    CRYPTOMINER = "cryptominer"
    BACKDOOR = "backdoor"
    ROOTKIT = "rootkit"
    LOADER = "loader"
    DROPPER = "dropper"
    DOWNLOADER = "downloader"
    DLL_HIJACKING = "dll_hijacking"
    PROCESS_INJECTION = "process_injection"
    PERSISTENCE = "persistence"
    MALICIOUS_SCRIPT = "malicious_script"
    OBFUSCATION = "obfuscation"
    SYSTEM_MODIFICATION = "system_modification"
    CREDENTIAL_ACCESS = "credential_access"
    STEALTH = "stealth"
    NETWORK_COMMUNICATION = "network_communication"
    DEFENSE_EVASION = "defense_evasion"
    PUA = "pua"
    GENERIC_MALWARE = "generic_malware"
    CRACK_COMPONENT = "crack_component"
    MOD_COMPONENT = "mod_component"
    STRUCTURAL_ANOMALY = "structural_anomaly"
    TEST_FILE = "test_file"
    INFORMATIONAL = "informational"


class Classification(str, Enum):
    KNOWN_LEGIT = "known_legit"
    UNKNOWN = "unknown"
    MODIFIED = "modified"
    PUA = "pua"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"
    INCONCLUSIVE = "inconclusive"

    @property
    def label(self) -> str:
        return {
            "known_legit": "Arquivo legítimo conhecido",
            "unknown": "Arquivo desconhecido",
            "modified": "Arquivo modificado",
            "pua": "Potencialmente indesejado",
            "suspicious": "Arquivo suspeito",
            "malware": "Malware detectado",
            "inconclusive": "Resultado inconclusivo",
        }[self.value]


class CrackStatus(str, Enum):
    NONE = "none"
    RECOGNIZED_CLEAN = "recognized_clean"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"
    INSUFFICIENT = "insufficient"
    MODIFIED_NO_THREAT = "modified_no_threat"

    @property
    def label(self) -> str:
        return {
            "none": "—",
            "recognized_clean": "Crack reconhecido e sem evidência de ameaça",
            "unknown": "Crack desconhecido",
            "suspicious": "Crack com comportamento suspeito",
            "malware": "Crack com detecção de malware",
            "insufficient": "Crack com evidências insuficientes",
            "modified_no_threat": "Arquivo modificado sem ameaça confirmada",
        }[self.value]


class AnalysisStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"       # some engines could not run / limits reached
    SKIPPED = "skipped"       # excluded or not selected by the scan mode
    ERROR = "error"           # could not be read

    @property
    def label(self) -> str:
        return {"complete": "Completa", "partial": "Parcial", "skipped": "Não analisado", "error": "Erro de leitura"}[
            self.value
        ]


@dataclass
class Location:
    """Where an indicator sits *inside* a file (distinct from the file's physical path)."""

    kind: str                          # string | import | export | section | overlay | resource | header | line | member | certificate | yara_match
    description: str = ""
    section: str | None = None
    offset: int | None = None          # raw file offset
    rva: int | None = None             # relative virtual address (PE)
    length: int | None = None
    line: int | None = None            # 1-based line for scripts
    excerpt: str | None = None         # printable, truncated

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}

    @classmethod
    def from_dict(cls, data: dict) -> "Location":
        return cls(**{k: data.get(k) for k in cls.__dataclass_fields__ if k in data})

    def short(self) -> str:
        parts = [self.kind]
        if self.section:
            parts.append(f"seção {self.section}")
        if self.offset is not None:
            parts.append(f"offset 0x{self.offset:X}")
        if self.rva is not None:
            parts.append(f"RVA 0x{self.rva:X}")
        if self.line is not None:
            parts.append(f"linha {self.line}")
        return ", ".join(parts)


@dataclass
class Evidence:
    rule_id: str
    title: str
    source: EvidenceSource
    category: ThreatCategory
    severity: RiskLevel
    confidence: Confidence
    description: str = ""
    engine: str = ""
    locations: list[Location] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    fp_note: str = ""                  # why this could be a false positive
    tags: list[str] = field(default_factory=list)
    adjusted_severity: RiskLevel | None = None   # set by the risk engine (context mitigation)
    adjustment_reason: str = ""

    @property
    def effective_severity(self) -> RiskLevel:
        return self.adjusted_severity if self.adjusted_severity is not None else self.severity

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "source": self.source.value,
            "category": self.category.value,
            "severity": self.severity.name,
            "confidence": self.confidence.name,
            "description": self.description,
            "engine": self.engine,
            "locations": [loc.to_dict() for loc in self.locations],
            "details": self.details,
            "fp_note": self.fp_note,
            "tags": list(self.tags),
            "adjusted_severity": self.adjusted_severity.name if self.adjusted_severity is not None else None,
            "adjustment_reason": self.adjustment_reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Evidence":
        adj = data.get("adjusted_severity")
        return cls(
            rule_id=data["rule_id"],
            title=data.get("title", data["rule_id"]),
            source=EvidenceSource(data["source"]),
            category=ThreatCategory(data["category"]),
            severity=RiskLevel.parse(data.get("severity")),
            confidence=Confidence.parse(data.get("confidence")),
            description=data.get("description", ""),
            engine=data.get("engine", ""),
            locations=[Location.from_dict(x) for x in data.get("locations", [])],
            details=data.get("details", {}) or {},
            fp_note=data.get("fp_note", ""),
            tags=list(data.get("tags", [])),
            adjusted_severity=RiskLevel.parse(adj) if adj else None,
            adjustment_reason=data.get("adjustment_reason", ""),
        )


@dataclass
class FileFeatures:
    """Context-free facts about a file extracted by the worker; consumed by folder-level context."""

    file_type: str = "unknown"
    is_pe: bool = False
    is_dll: bool = False
    is_driver: bool = False
    is_dotnet: bool = False
    machine: str | None = None
    signed: bool = False
    signature_valid: bool | None = None
    signer: str | None = None
    version_info: dict[str, str] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    export_forwarders: list[str] = field(default_factory=list)
    imports_dlls: list[str] = field(default_factory=list)
    packers: list[str] = field(default_factory=list)
    installer: str | None = None
    marker_strings: list[str] = field(default_factory=list)   # crack / mod markers found in content
    text_head: str | None = None                              # first bytes of small text configs (ini/json)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict | None) -> "FileFeatures":
        data = data or {}
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


@dataclass
class FileResult:
    path: str                          # physical path (or container path "archive.zip::inner/file.exe")
    name: str
    directory: str
    extension: str
    size: int
    sha256: str | None
    file_type: str
    container: str | None = None       # top-level physical file when this is an archive member
    member_path: str | None = None     # path inside the container chain
    depth: int = 0
    status: AnalysisStatus = AnalysisStatus.COMPLETE
    status_reasons: list[str] = field(default_factory=list)
    evidences: list[Evidence] = field(default_factory=list)
    features: FileFeatures = field(default_factory=FileFeatures)
    engines: list[str] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.NONE
    classification: Classification = Classification.UNKNOWN
    crack_status: CrackStatus = CrackStatus.NONE
    primary_category: ThreatCategory | None = None
    explanation: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    possible_false_positive: bool = False
    analyzed_at: float = 0.0
    md5: str | None = None
    from_cache: bool = False

    @property
    def is_member(self) -> bool:
        return self.container is not None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "directory": self.directory,
            "extension": self.extension,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "file_type": self.file_type,
            "container": self.container,
            "member_path": self.member_path,
            "depth": self.depth,
            "status": self.status.value,
            "status_reasons": self.status_reasons,
            "evidences": [e.to_dict() for e in self.evidences],
            "features": self.features.to_dict(),
            "engines": self.engines,
            "risk": self.risk.name,
            "classification": self.classification.value,
            "crack_status": self.crack_status.value,
            "primary_category": self.primary_category.value if self.primary_category else None,
            "explanation": self.explanation,
            "recommendations": self.recommendations,
            "possible_false_positive": self.possible_false_positive,
            "analyzed_at": self.analyzed_at,
            "from_cache": self.from_cache,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileResult":
        return cls(
            path=d["path"],
            name=d["name"],
            directory=d.get("directory", ""),
            extension=d.get("extension", ""),
            size=int(d.get("size", 0)),
            sha256=d.get("sha256"),
            md5=d.get("md5"),
            file_type=d.get("file_type", "unknown"),
            container=d.get("container"),
            member_path=d.get("member_path"),
            depth=int(d.get("depth", 0)),
            status=AnalysisStatus(d.get("status", "complete")),
            status_reasons=list(d.get("status_reasons", [])),
            evidences=[Evidence.from_dict(e) for e in d.get("evidences", [])],
            features=FileFeatures.from_dict(d.get("features")),
            engines=list(d.get("engines", [])),
            risk=RiskLevel.parse(d.get("risk", "NONE")),
            classification=Classification(d.get("classification", "unknown")),
            crack_status=CrackStatus(d.get("crack_status", "none")),
            primary_category=ThreatCategory(d["primary_category"]) if d.get("primary_category") else None,
            explanation=list(d.get("explanation", [])),
            recommendations=list(d.get("recommendations", [])),
            possible_false_positive=bool(d.get("possible_false_positive", False)),
            analyzed_at=float(d.get("analyzed_at", 0.0)),
            from_cache=bool(d.get("from_cache", False)),
        )


def printable_excerpt(data: bytes | str, limit: int = 160) -> str:
    """Render untrusted bytes as a safe, single-line, truncated excerpt."""
    if isinstance(data, bytes):
        text = data.decode("latin-1", errors="replace")
    else:
        text = data
    out = []
    for ch in text[:limit]:
        code = ord(ch)
        if ch in "\r\n\t":
            out.append(" ")
        elif 32 <= code < 127 or code >= 160:
            out.append(ch)
        else:
            out.append(".")
    suffix = "…" if len(text) > limit else ""
    return "".join(out) + suffix
