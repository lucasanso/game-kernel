"""Optional behavioural analysis inside a disposable, network-less virtual machine.

Backend: **Windows Sandbox** (Hyper-V based, discarded on close; Windows 10/11 Pro, Enterprise or
Education with the "Windows Sandbox" feature). The suspicious file is **never** executed on the
host: Game Kernel copies it into a private job folder as ``sample.bin`` (not runnable), maps that
folder **read-only** into the VM, and the in-VM monitor (``gamekernel/sandbox/monitor.ps1``) restores the
original name, runs it and records what happens. Networking, clipboard, GPU, audio, video and
printer redirection are disabled. If isolation is not available, nothing is executed and the
reason is reported.

Honest limitations (also returned with every report):
* only behaviour that happens during the observation window is seen;
* malware may detect the virtual machine and stay dormant;
* with networking disabled, command-and-control behaviour cannot unfold (attempts are recorded);
* the sample runs with administrator rights *inside the VM* and could tamper with the monitor's
  report; results are evidence, never proof of safety;
* without Sysmon (user-provided), process-injection visibility is limited.

The risk re-assessment of a file with these behavioural evidences belongs to the core
(``risk_engine.reassess`` — Agent A); this module only produces ``Evidence`` objects with
``source=EvidenceSource.BEHAVIORAL``.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from xml.sax.saxutils import escape

from .. import app_paths
from ..core.models import Confidence, Evidence, EvidenceSource, Location, RiskLevel, ThreatCategory

log = logging.getLogger(__name__)

REPORT_FORMAT = "gamekernel-sandbox-report"
SUPPORTED_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"}
MAX_SAMPLE_BYTES = 1024 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
BOOT_MARGIN_SECONDS = 180
SANDBOX_PROCESSES = ("windowssandbox.exe", "windowssandboxclient.exe", "windowssandboxremotesession.exe",
                     "windowssandboxserver.exe")
IN_VM_INPUT = r"C:\GKIn"
IN_VM_OUTPUT = r"C:\GKOut"
MONITOR_SCRIPT = Path(__file__).with_name("monitor.ps1")

LIMITATIONS = (
    "Somente o comportamento ocorrido durante o tempo de observação é registrado.",
    "Malwares podem detectar a máquina virtual e permanecer inativos; ausência de comportamento suspeito não "
    "prova que o arquivo é seguro.",
    "A rede da máquina virtual fica desativada: tentativas de conexão são registradas, mas o comportamento "
    "posterior à comunicação com servidores não acontece.",
    "A amostra roda como administrador dentro da máquina virtual e poderia adulterar o relatório do monitor.",
    "Sem o Sysmon (fornecido pelo usuário), a detecção de injeção em processos é limitada.",
)


class SandboxUnavailable(Exception):
    """Isolation is not available: the file was NOT executed."""


class SandboxError(Exception):
    pass


@dataclass
class SandboxReport:
    sample_path: str
    sha256: str
    available: bool
    executed: bool = False
    started_at: float = 0.0
    finished_at: float = 0.0
    timed_out: bool = False
    cancelled: bool = False
    evidences: list[Evidence] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))
    error: str | None = None
    report_path: str | None = None

    def to_dict(self) -> dict:
        return {
            "sample_path": self.sample_path, "sha256": self.sha256, "available": self.available,
            "executed": self.executed, "started_at": self.started_at, "finished_at": self.finished_at,
            "timed_out": self.timed_out, "cancelled": self.cancelled,
            "evidences": [e.to_dict() for e in self.evidences], "observations": self.observations,
            "limitations": self.limitations, "error": self.error, "report_path": self.report_path,
        }


# ---------------------------------------------------------------------------- availability
def sandbox_executable() -> Path:
    root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
    return Path(root) / "System32" / "WindowsSandbox.exe"


def _running_sandbox_processes() -> list[str]:
    try:
        import psutil
    except ImportError:  # pragma: no cover
        return []
    names = []
    for proc in psutil.process_iter(["name"]):
        name = (proc.info.get("name") or "").lower()
        if name in SANDBOX_PROCESSES:
            names.append(name)
    return names


def check_availability() -> tuple[bool, str]:
    """(available, reason). Never executes anything."""
    if sys.platform != "win32":
        return False, ("A análise comportamental usa o Windows Sandbox e só está disponível no Windows 10/11 "
                       "Pro, Enterprise ou Education. Nada foi executado.")
    exe = sandbox_executable()
    if not exe.is_file():
        return False, ("O recurso 'Área Restrita do Windows' (Windows Sandbox) não está habilitado. Ative-o em "
                       "'Ativar ou desativar recursos do Windows' (requer virtualização ativa no firmware). "
                       "Sem isolamento real, o arquivo não é executado.")
    running = _running_sandbox_processes()
    if running:
        return False, ("Já existe uma Área Restrita do Windows em execução; o Windows permite apenas uma por vez. "
                       "Feche-a e tente novamente.")
    return True, "Windows Sandbox disponível (máquina virtual descartável, sem rede)."


# ---------------------------------------------------------------------------- job preparation
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._ -]")


def safe_sample_name(name: str) -> str:
    stem, ext = os.path.splitext(name)
    stem = SAFE_NAME_RE.sub("_", stem).strip(" .") or "amostra"
    return f"{stem[:80]}{ext.lower()}"


def build_wsb(job_in: Path, job_out: Path, memory_mb: int = 4096) -> str:
    """Windows Sandbox configuration: no network, no redirections, input read-only."""
    return f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>{int(memory_mb)}</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{escape(str(job_in))}</HostFolder>
      <SandboxFolder>{IN_VM_INPUT}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{escape(str(job_out))}</HostFolder>
      <SandboxFolder>{IN_VM_OUTPUT}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {IN_VM_INPUT}\\monitor.ps1</Command>
  </LogonCommand>
</Configuration>
"""


def _copy_and_hash(src: Path, dst: Path) -> str:
    h = hashlib.sha256()
    with src.open("rb") as fin, dst.open("wb") as fout:
        while chunk := fin.read(1024 * 1024):
            h.update(chunk)
            fout.write(chunk)
    return h.hexdigest()


def validate_sample(path: str | os.PathLike) -> Path:
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise SandboxError(f"não é um arquivo comum: {p}")
    if p.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise SandboxError(f"tipo não suportado na análise comportamental: {p.suffix or '(sem extensão)'}; "
                           f"suportados: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")
    if p.stat().st_size > MAX_SAMPLE_BYTES:
        raise SandboxError("arquivo acima de 1 GB")
    return p


# ---------------------------------------------------------------------------- launcher
def windows_sandbox_launcher(wsb_path: Path) -> None:
    """Start Windows Sandbox with the job configuration (absolute path, no shell)."""
    flags = 0x08000000 if sys.platform == "win32" else 0   # CREATE_NO_WINDOW
    subprocess.Popen([str(sandbox_executable()), str(wsb_path)], shell=False, close_fds=True,
                     cwd=str(sandbox_executable().parent), creationflags=flags)


def terminate_windows_sandbox(started_after: float) -> int:
    """Close the VM (discarding it) by ending the Windows Sandbox processes started for this job."""
    try:
        import psutil
    except ImportError:  # pragma: no cover
        return 0
    killed = 0
    for proc in psutil.process_iter(["name", "create_time"]):
        name = (proc.info.get("name") or "").lower()
        if name in SANDBOX_PROCESSES and (proc.info.get("create_time") or 0) >= started_after - 5:
            try:
                proc.kill()
                killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return killed


# ---------------------------------------------------------------------------- manager
class SandboxManager:
    def __init__(self, settings=None, launcher: Callable[[Path], None] | None = None,
                 terminator: Callable[[float], int] | None = None,
                 availability: Callable[[], tuple[bool, str]] | None = None,
                 jobs_dir: Path | None = None, poll_interval: float = 1.0):
        self.settings = settings
        self._launch = launcher or windows_sandbox_launcher
        self._terminate = terminator or terminate_windows_sandbox
        self._availability = availability or check_availability
        self.jobs_dir = Path(jobs_dir) if jobs_dir else app_paths.sandbox_dir()
        self.poll_interval = poll_interval

    def _setting(self, key: str, default: Any) -> Any:
        return self.settings.get(key, default) if self.settings is not None else default

    def reports_dir(self) -> Path:
        path = self.jobs_dir / "reports"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def analyze(self, path: str | os.PathLike, timeout_seconds: int | None = None,
                cancel: Callable[[], bool] | None = None,
                progress: Callable[[str, dict], None] | None = None) -> SandboxReport:
        progress = progress or (lambda stage, data: None)
        cancel = cancel or (lambda: False)
        sample = validate_sample(path)
        available, reason = self._availability()
        if not available:
            raise SandboxUnavailable(reason)
        timeout = int(timeout_seconds or self._setting("sandbox.timeout_seconds", 120))
        timeout = max(30, min(1800, timeout))

        job = self.jobs_dir / f"job-{uuid.uuid4().hex}"
        job_in, job_out = job / "in", job / "out"
        job_in.mkdir(parents=True)
        job_out.mkdir()
        report = SandboxReport(str(sample), "", True)
        try:
            # The host never holds a runnable copy: the sample is stored as sample.bin.
            report.sha256 = _copy_and_hash(sample, job_in / "sample.bin")
            shutil.copyfile(MONITOR_SCRIPT, job_in / "monitor.ps1")
            sysmon = self._prepare_sysmon(job_in)
            (job_in / "job.json").write_text(json.dumps({
                "format": "gamekernel-sandbox-job", "version": 1, "name": safe_sample_name(sample.name),
                "sha256": report.sha256, "timeout_seconds": timeout, "sysmon": sysmon,
            }), encoding="utf-8")
            wsb = job / "job.wsb"
            wsb.write_text(build_wsb(job_in, job_out, int(self._setting("sandbox.memory_mb", 4096))), encoding="utf-8")

            progress("boot", {"sha256": report.sha256, "timeout_seconds": timeout})
            report.started_at = time.time()
            self._launch(wsb)
            report.executed = True
            deadline = time.monotonic() + timeout + BOOT_MARGIN_SECONDS
            done = job_out / "done.json"
            while not done.exists():
                if cancel():
                    report.cancelled = True
                    break
                if time.monotonic() > deadline:
                    report.timed_out = True
                    break
                time.sleep(self.poll_interval)
                progress("running", {"elapsed": round(time.time() - report.started_at)})
            progress("collecting", {})
            self._terminate(report.started_at)
            report.finished_at = time.time()
            if report.cancelled:
                report.error = "análise cancelada; a máquina virtual foi descartada"
            elif report.timed_out:
                report.error = ("o monitor não concluiu dentro do prazo (a amostra pode ter travado a máquina "
                                "virtual ou o monitor foi interrompido); a máquina virtual foi descartada")
            else:
                data = load_monitor_report(job_out / "report.json")
                report.observations = data
                report.evidences = map_observations(data)
                if not data.get("sysmon_active"):
                    report.limitations = list(LIMITATIONS)
                else:
                    report.limitations = [x for x in LIMITATIONS if "Sysmon" not in x]
            stored = self.reports_dir() / f"{report.sha256[:16]}-{int(report.started_at)}.json"
            stored.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")
            report.report_path = str(stored)
            progress("done", {"evidences": len(report.evidences)})
            return report
        finally:
            shutil.rmtree(job, ignore_errors=True)

    def _prepare_sysmon(self, job_in: Path) -> bool:
        """Copy the user-provided Sysmon (Sysinternals, not redistributable) into the job, if configured."""
        configured = str(self._setting("sandbox.sysmon_path", "") or "")
        if not configured:
            return False
        src = Path(configured)
        if not src.is_file() or src.name.lower() not in ("sysmon64.exe", "sysmon.exe"):
            log.warning("Sysmon configurado não encontrado ou inválido: %s", src)
            return False
        target = job_in / "sysmon"
        target.mkdir()
        shutil.copyfile(src, target / src.name)
        return True

    def list_reports(self, limit: int = 100) -> list[dict]:
        out = []
        for path in sorted(self.reports_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            out.append({"path": str(path), "sample_path": data.get("sample_path"), "sha256": data.get("sha256"),
                        "started_at": data.get("started_at"), "executed": data.get("executed"),
                        "evidences": len(data.get("evidences") or []), "error": data.get("error")})
        return out


# ---------------------------------------------------------------------------- report parsing
def load_monitor_report(path: Path) -> dict:
    """Parse the in-VM monitor output defensively: it was written inside the VM, next to the sample."""
    if not path.is_file():
        raise SandboxError("o monitor não gerou o relatório")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise SandboxError("relatório do monitor acima do limite (8 MB)")
    try:
        data = json.loads(path.read_bytes().decode("utf-8-sig"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SandboxError(f"relatório do monitor ilegível: {exc}") from None
    if not isinstance(data, dict) or data.get("format") != REPORT_FORMAT:
        raise SandboxError("relatório do monitor em formato inesperado")
    return data


def _reject_constant(name: str):
    raise ValueError(name)


def _items(data: dict, *keys: str) -> list:
    node: Any = data
    for key in keys:
        node = node.get(key) if isinstance(node, dict) else None
    if isinstance(node, list):
        return node[:200]
    if isinstance(node, (dict, str, int, float)) and not isinstance(node, bool) and node != "":
        return [node]   # PowerShell's ConvertTo-Json may serialise a one-element list as a scalar
    return []


def _text(value: Any, limit: int = 300) -> str:
    return str(value if value is not None else "")[:limit]


def _ev(rule: str, title: str, cat: ThreatCategory, sev: RiskLevel, conf: Confidence, desc: str,
        locations: list[Location], fp: str = "", details: dict | None = None) -> Evidence:
    return Evidence(rule, title, EvidenceSource.BEHAVIORAL, cat, sev, conf, desc, engine="sandbox",
                    locations=locations[:20], details=details or {}, fp_note=fp)


def _loc(description: str, excerpt: Any = None) -> Location:
    return Location(kind="behavior", description=description, excerpt=_text(excerpt) if excerpt is not None else None)


SHADOW_RE = re.compile(r"vssadmin(\.exe)?\s+.*delete\s+shadows|wmic(\.exe)?\s+.*shadowcopy\s+delete|"
                       r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?\s+.*recoveryenabled\s+no",
                       re.IGNORECASE)
LOLBIN_RE = re.compile(r"powershell(\.exe)?\s.*-(e|en|enc|encodedcommand)\s|downloadstring|invoke-webrequest|"
                       r"net\.webclient|certutil(\.exe)?\s.*-urlcache|bitsadmin(\.exe)?\s.*/transfer|"
                       r"mshta(\.exe)?\s+(https?:|javascript:)|regsvr32(\.exe)?\s.*/i:https?:", re.IGNORECASE)
DEFENDER_RE = re.compile(r"(add|set)-mppreference|disablerealtimemonitoring|exclusionpath", re.IGNORECASE)
MINER_RE = re.compile(r"stratum\+(tcp|ssl)://|--donate-level|xmrig|cryptonight|randomx", re.IGNORECASE)
EXFIL_RE = re.compile(r"discord(app)?\.com/api/webhooks|api\.telegram\.org|pastebin\.com|transfer\.sh|anonfiles|"
                      r"ngrok\.io|gofile\.io", re.IGNORECASE)

CREDENTIAL_DECOYS = {
    "browser_passwords": (ThreatCategory.PASSWORD_STEALER, "banco de senhas de navegador"),
    "browser_cookies": (ThreatCategory.COOKIE_STEALER, "banco de cookies/sessões de navegador"),
    "browser_keys": (ThreatCategory.PASSWORD_STEALER, "chave de criptografia do navegador (Local State/key4.db)"),
    "discord_tokens": (ThreatCategory.COOKIE_STEALER, "armazenamento de tokens do Discord"),
    "steam_session": (ThreatCategory.CREDENTIAL_ACCESS, "sessão do Steam (loginusers.vdf/ssfn)"),
    "telegram_session": (ThreatCategory.CREDENTIAL_ACCESS, "sessão do Telegram (tdata)"),
    "crypto_wallet": (ThreatCategory.CREDENTIAL_ACCESS, "carteira de criptomoedas"),
}


def map_observations(data: dict) -> list[Evidence]:
    """Turn monitor observations into explainable behavioural evidence (pure function)."""
    out: list[Evidence] = []
    sample = data.get("sample") if isinstance(data.get("sample"), dict) else {}
    if sample.get("start_error"):
        out.append(_ev("GK_BEH_NotStarted", "A amostra não pôde ser iniciada na máquina virtual",
                       ThreatCategory.INFORMATIONAL, RiskLevel.INFO, Confidence.HIGH,
                       "Nenhum comportamento foi observado porque a execução falhou.",
                       [_loc("erro de inicialização", sample.get("start_error"))]))

    persistence = data.get("persistence") if isinstance(data.get("persistence"), dict) else {}
    fp_startup = "Launchers, atualizadores e clientes de jogos legítimos também se registram na inicialização."
    for key, rule, title, sev in (
        ("run_keys_added", "GK_BEH_RunKey", "Entrada criada em chave Run/RunOnce do registro", RiskLevel.HIGH),
        ("startup_files_added", "GK_BEH_StartupFolder", "Arquivo criado na pasta Inicializar", RiskLevel.HIGH),
        ("tasks_added", "GK_BEH_ScheduledTask", "Tarefa agendada criada", RiskLevel.MEDIUM),
        ("wmi_added", "GK_BEH_WmiPersistence", "Assinatura de evento WMI criada (persistência)", RiskLevel.HIGH),
        ("ifeo_added", "GK_BEH_IFEO", "Debugger de Image File Execution Options definido", RiskLevel.HIGH),
        ("winlogon_changed", "GK_BEH_Winlogon", "Shell/Userinit do Winlogon alterado", RiskLevel.HIGH),
    ):
        items = _items(persistence, key)
        if items:
            out.append(_ev(rule, title, ThreatCategory.PERSISTENCE, sev, Confidence.HIGH,
                           f"{len(items)} item(ns) observados durante a execução.",
                           [_loc(_text(i.get("name") if isinstance(i, dict) else i, 200),
                                 i.get("value") if isinstance(i, dict) else None) for i in items],
                           fp="" if key in ("wmi_added", "ifeo_added", "winlogon_changed") else fp_startup))
    services = _items(persistence, "services_added")
    if services:
        drivers = [s for s in services if isinstance(s, dict) and "kernel" in _text(s.get("type")).lower()]
        if drivers:
            out.append(_ev("GK_BEH_DriverService", "Serviço de driver de kernel instalado", ThreatCategory.ROOTKIT,
                           RiskLevel.HIGH, Confidence.HIGH, "A amostra instalou um driver de kernel.",
                           [_loc(_text(s.get("name")), s.get("path")) for s in drivers],
                           fp="Anti-cheats e ferramentas de hardware instalam drivers legítimos (assinados)."))
        others = [s for s in services if s not in drivers]
        if others:
            out.append(_ev("GK_BEH_ServiceCreated", "Serviço do Windows criado", ThreatCategory.PERSISTENCE,
                           RiskLevel.MEDIUM, Confidence.HIGH, "Serviços continuam ativos após o fechamento do jogo.",
                           [_loc(_text(s.get("name") if isinstance(s, dict) else s), s.get("path") if isinstance(s, dict) else None)
                            for s in others], fp="Launchers e serviços de atualização legítimos criam serviços."))

    for item in _items(data, "credential_access"):
        if not isinstance(item, dict):
            continue
        cat, what = CREDENTIAL_DECOYS.get(_text(item.get("decoy")), (ThreatCategory.CREDENTIAL_ACCESS, "credenciais"))
        in_tree = item.get("in_tree", True) is not False
        out.append(_ev("GK_BEH_CredentialDecoyRead", f"Leitura de {what}", cat,
                       RiskLevel.HIGH if in_tree else RiskLevel.MEDIUM, Confidence.HIGH if in_tree else Confidence.MEDIUM,
                       ("Um arquivo-isca com dados sensíveis falsos foi lido por um processo da amostra. Jogos não "
                        "têm motivo para ler esses arquivos.") if in_tree else
                       ("Um arquivo-isca foi lido por um processo fora da árvore da amostra durante a observação "
                        "(possível injeção, ou atividade do próprio Windows)."),
                       [_loc(f"isca lida por {_text(item.get('process'), 120)}", item.get("path"))],
                       details={"decoy": _text(item.get("decoy")), "in_tree": in_tree}))

    files = data.get("files") if isinstance(data.get("files"), dict) else {}
    touched = _items(files, "canaries_modified") + _items(files, "canaries_deleted")
    if touched:
        many = len(touched) >= 5
        out.append(_ev("GK_BEH_RansomwareCanaries", "Arquivos-isca de documentos alterados ou apagados",
                       ThreatCategory.RANSOMWARE, RiskLevel.CRITICAL if many else RiskLevel.MEDIUM,
                       Confidence.HIGH if many else Confidence.MEDIUM,
                       f"{len(touched)} documento(s)-isca do usuário foram modificados/apagados — comportamento típico "
                       "de ransomware quando ocorre em massa.",
                       [_loc("arquivo-isca", t.get("path") if isinstance(t, dict) else t) for t in touched]))
    dropped = _items(files, "dropped_executables")
    if dropped:
        out.append(_ev("GK_BEH_DroppedExecutable", "Executáveis gravados em pastas temporárias ou de perfil",
                       ThreatCategory.DROPPER, RiskLevel.MEDIUM, Confidence.MEDIUM,
                       f"{len(dropped)} executável(is) criado(s) durante a execução.",
                       [_loc(f"SHA-256 {_text(d.get('sha256'), 64)}" if isinstance(d, dict) else "arquivo",
                             d.get("path") if isinstance(d, dict) else d) for d in dropped],
                       fp="Instaladores e launchers legítimos extraem componentes em pastas temporárias."))
    if data.get("hosts_modified"):
        out.append(_ev("GK_BEH_HostsModified", "Arquivo hosts do Windows modificado", ThreatCategory.SYSTEM_MODIFICATION,
                       RiskLevel.HIGH, Confidence.HIGH, "Pode redirecionar ou bloquear sites (ex.: antivírus).",
                       [_loc("C:\\Windows\\System32\\drivers\\etc\\hosts")],
                       fp="Alguns cracks bloqueiam servidores de ativação pelo hosts; ainda assim é uma alteração do sistema."))

    registry = _items(data, "registry", "changed")
    policy = [r for r in registry if isinstance(r, dict) and re.search(r"policies|windows defender", _text(r.get("key")), re.I)]
    if policy:
        out.append(_ev("GK_BEH_SecurityPolicy", "Políticas de segurança do Windows alteradas", ThreatCategory.DEFENSE_EVASION,
                       RiskLevel.HIGH, Confidence.HIGH, "Alterações em políticas do sistema ou do Microsoft Defender.",
                       [_loc(_text(r.get("key")), f"{_text(r.get('value'))} = {_text(r.get('after'))}") for r in policy]))

    commands = [c for c in _items(data, "commands") if isinstance(c, dict)]
    shadow = [c for c in commands if SHADOW_RE.search(_text(c.get("command_line"), 2000))]
    if shadow:
        out.append(_ev("GK_BEH_ShadowCopyDelete", "Tentativa de apagar cópias de sombra/backups", ThreatCategory.RANSOMWARE,
                       RiskLevel.HIGH, Confidence.HIGH, "Comando usado para impedir a recuperação de arquivos.",
                       [_loc(f"processo {_text(c.get('process'), 80)}", c.get("command_line")) for c in shadow]))
    defender = [c for c in commands if DEFENDER_RE.search(_text(c.get("command_line"), 2000))]
    if defender:
        out.append(_ev("GK_BEH_DefenderTampering", "Tentativa de alterar o Microsoft Defender", ThreatCategory.DEFENSE_EVASION,
                       RiskLevel.HIGH, Confidence.HIGH, "Exclusões ou desativação de proteção do Defender.",
                       [_loc(f"processo {_text(c.get('process'), 80)}", c.get("command_line")) for c in defender]))
    lolbins = [c for c in commands if LOLBIN_RE.search(_text(c.get("command_line"), 2000))]
    if lolbins:
        out.append(_ev("GK_BEH_SuspiciousCommand", "Comandos típicos de download/execução de código",
                       ThreatCategory.DOWNLOADER, RiskLevel.HIGH, Confidence.MEDIUM,
                       "PowerShell codificado, download por certutil/bitsadmin/mshta/regsvr32 ou similares.",
                       [_loc(f"processo {_text(c.get('process'), 80)}", c.get("command_line")) for c in lolbins]))

    network = data.get("network") if isinstance(data.get("network"), dict) else {}
    destinations = [_text(x, 200) for x in _items(network, "dns")] + \
                   [_text(x.get("remote") if isinstance(x, dict) else x, 200) for x in _items(network, "connections")]
    exfil = [d for d in destinations if EXFIL_RE.search(d)]
    if exfil:
        out.append(_ev("GK_BEH_ExfiltrationChannel", "Tentativa de contato com serviço usado para exfiltração",
                       ThreatCategory.NETWORK_COMMUNICATION, RiskLevel.HIGH, Confidence.MEDIUM,
                       "Webhooks do Discord, API do Telegram e sites de colagem são canais comuns de stealers.",
                       [_loc("destino", d) for d in exfil]))
    elif destinations:
        out.append(_ev("GK_BEH_NetworkAttempt", "Tentativas de comunicação de rede (bloqueadas pela VM sem rede)",
                       ThreatCategory.NETWORK_COMMUNICATION, RiskLevel.LOW, Confidence.MEDIUM,
                       f"{len(destinations)} destino(s) consultado(s).", [_loc("destino", d) for d in destinations],
                       fp="Jogos e launchers contatam servidores de atualização, telemetria e partidas."))

    injections = [i for i in _items(data, "injection") if isinstance(i, dict)]
    if injections:
        out.append(_ev("GK_BEH_ProcessInjection", "Injeção em outro processo (Sysmon)", ThreatCategory.PROCESS_INJECTION,
                       RiskLevel.HIGH, Confidence.HIGH, "Criação de thread remota ou escrita na memória de outro processo.",
                       [_loc(f"{_text(i.get('source'), 80)} → {_text(i.get('target'), 80)}", i.get("kind")) for i in injections],
                       fp="Overlays, gravadores e anti-cheats injetam em jogos de forma legítima."))

    cpu = data.get("cpu") if isinstance(data.get("cpu"), dict) else {}
    miner_cmd = [c for c in commands if MINER_RE.search(_text(c.get("command_line"), 2000))]
    if miner_cmd:
        out.append(_ev("GK_BEH_Cryptominer", "Execução de minerador de criptomoedas", ThreatCategory.CRYPTOMINER,
                       RiskLevel.HIGH, Confidence.HIGH, "Parâmetros de mineração (stratum/XMRig) na linha de comando.",
                       [_loc(f"processo {_text(c.get('process'), 80)}", c.get("command_line")) for c in miner_cmd]))
    else:
        try:
            busy = float(cpu.get("high_usage_ratio", 0))
        except (TypeError, ValueError):
            busy = 0.0
        if busy >= 0.7 and not cpu.get("has_window", True):
            out.append(_ev("GK_BEH_SustainedCpu", "Uso alto e contínuo de CPU por processo sem janela",
                           ThreatCategory.CRYPTOMINER, RiskLevel.LOW, Confidence.LOW,
                           f"CPU acima de 85% em {busy:.0%} das amostras.", [_loc("uso de CPU", cpu.get("process"))],
                           fp="Instaladores (descompressão) e compilação de shaders também usam muita CPU."))

    lingering = _items(data, "lingering_processes")
    if lingering and sample.get("main_exited"):
        out.append(_ev("GK_BEH_Lingering", "Componentes continuam ativos após o fim do processo principal",
                       ThreatCategory.STEALTH, RiskLevel.MEDIUM, Confidence.MEDIUM,
                       "Processos iniciados pela amostra permaneceram em execução.",
                       [_loc("processo", x.get("name") if isinstance(x, dict) else x) for x in lingering],
                       fp="Launchers e serviços de atualização podem permanecer em segundo plano."))

    processes = _items(data, "processes")
    out.append(_ev("GK_BEH_Summary", "Resumo da observação na máquina virtual", ThreatCategory.INFORMATIONAL,
                   RiskLevel.INFO, Confidence.HIGH,
                   f"Observação de {data.get('observed_seconds', '?')} s; {len(processes)} processo(s) criados; "
                   f"Sysmon {'ativo' if data.get('sysmon_active') else 'não utilizado'}.",
                   [_loc("processo", p.get("command_line") if isinstance(p, dict) else p) for p in processes[:10]]))
    return out


def report_timestamp(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat(timespec="seconds") if ts else ""
