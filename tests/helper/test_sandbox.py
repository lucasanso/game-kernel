"""Behavioural analysis orchestration. Windows Sandbox itself cannot run here: the VM side is
replaced by a test double that writes what the in-VM monitor would write. Nothing is executed."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from gamekernel.core.models import EvidenceSource, RiskLevel, ThreatCategory
from gamekernel.sandbox import manager as SM
from gamekernel.helper.client import HelperClient, HelperError, sanitized_environment

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "Crack Launcher (v1.2).exe"
    path.write_bytes(b"MZ" + b"\x00" * 510 + b"inert test bytes")
    return path


def available():
    return True, "ok"


# ---------------------------------------------------------------------------- availability / config
def test_unavailable_outside_windows():
    if sys.platform == "win32":
        pytest.skip("teste do caminho não-Windows")
    ok, reason = SM.check_availability()
    assert not ok and "Windows" in reason and "Nada foi executado" in reason


def test_unavailable_when_feature_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(SM.sys, "platform", "win32")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    ok, reason = SM.check_availability()
    assert not ok and "não está habilitado" in reason
    exe = tmp_path / "System32" / "WindowsSandbox.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"")
    monkeypatch.setattr(SM, "_running_sandbox_processes", lambda: ["windowssandbox.exe"])
    ok, reason = SM.check_availability()
    assert not ok and "apenas uma" in reason
    monkeypatch.setattr(SM, "_running_sandbox_processes", lambda: [])
    assert SM.check_availability()[0] is True


def test_wsb_disables_network_and_maps_input_read_only(tmp_path):
    job_in, job_out = tmp_path / "a&b<in>", tmp_path / "out"
    root = ET.fromstring(SM.build_wsb(job_in, job_out, 2048))
    for tag in ("Networking", "VGpu", "AudioInput", "VideoInput", "ClipboardRedirection", "PrinterRedirection"):
        assert root.findtext(tag) == "Disable", tag
    assert root.findtext("ProtectedClient") == "Enable" and root.findtext("MemoryInMB") == "2048"
    folders = root.findall("MappedFolders/MappedFolder")
    assert len(folders) == 2
    assert (folders[0].findtext("HostFolder"), folders[0].findtext("ReadOnly")) == (str(job_in), "true")
    assert (folders[1].findtext("HostFolder"), folders[1].findtext("ReadOnly")) == (str(job_out), "false")
    assert "monitor.ps1" in root.findtext("LogonCommand/Command")


@pytest.mark.parametrize("name", ["notes.txt", "archive.zip", "noext"])
def test_unsupported_types_are_refused(tmp_path, name):
    (tmp_path / name).write_bytes(b"x")
    with pytest.raises(SM.SandboxError, match="não suportado"):
        SM.validate_sample(tmp_path / name)


def test_directories_and_symlinks_are_refused(tmp_path, sample):
    with pytest.raises(SM.SandboxError):
        SM.validate_sample(tmp_path)
    if sys.platform != "win32":
        link = tmp_path / "link.exe"
        link.symlink_to(sample)
        with pytest.raises(SM.SandboxError):
            SM.validate_sample(link)


def test_safe_sample_name():
    assert SM.safe_sample_name("Crack Launcher (v1.2).EXE") == "Crack Launcher _v1.2_.exe"
    assert SM.safe_sample_name("..\\..\\evil.exe") == "_.._evil.exe"
    assert SM.safe_sample_name("ゲーム.exe") == "___.exe"


# ---------------------------------------------------------------------------- orchestration
def test_nothing_runs_without_isolation(tmp_path, sample):
    launched = []
    mgr = SM.SandboxManager(launcher=launched.append, availability=lambda: (False, "sem Hyper-V"),
                            jobs_dir=tmp_path / "jobs")
    with pytest.raises(SM.SandboxUnavailable, match="sem Hyper-V"):
        mgr.analyze(sample)
    assert launched == [] and not any((tmp_path / "jobs").glob("job-*"))


class FakeVM:
    """Test double of the VM side: checks what the host prepared and writes a monitor report."""

    def __init__(self, observations: dict | None = None, write: bool = True):
        self.observations = observations or {}
        self.write = write
        self.seen: dict = {}

    def __call__(self, wsb: Path) -> None:
        job = wsb.parent
        root = ET.fromstring(wsb.read_text(encoding="utf-8"))
        self.seen["networking"] = root.findtext("Networking")
        self.seen["files"] = sorted(p.name for p in (job / "in").iterdir())
        self.seen["job"] = json.loads((job / "in" / "job.json").read_text(encoding="utf-8"))
        self.seen["sample_sha"] = hashlib.sha256((job / "in" / "sample.bin").read_bytes()).hexdigest()
        if self.write:
            report = {"format": SM.REPORT_FORMAT, "version": 1, "observed_seconds": 60, **self.observations}
            (job / "out" / "report.json").write_text("\ufeff" + json.dumps(report), encoding="utf-8")
            (job / "out" / "done.json").write_text('{"ok":true}', encoding="utf-8")


def test_full_flow_with_vm_double(tmp_path, sample):
    vm = FakeVM({"sample": {"started": True, "main_exited": True},
                 "persistence": {"run_keys_added": [{"name": "HKCU:\\...\\Run\\Updater", "value": "C:\\x.exe"}]},
                 "processes": [{"pid": 1, "name": "x.exe", "command_line": "x.exe"}]})
    terminated = []
    mgr = SM.SandboxManager(launcher=vm, terminator=terminated.append, availability=available,
                            jobs_dir=tmp_path / "jobs", poll_interval=0.01)
    stages = []
    report = mgr.analyze(sample, 60, progress=lambda stage, data: stages.append(stage))
    # What the host gave the VM: a non-runnable copy, the monitor, the job description.
    assert vm.seen["networking"] == "Disable"
    assert vm.seen["files"] == ["job.json", "monitor.ps1", "sample.bin"]
    assert vm.seen["sample_sha"] == hashlib.sha256(sample.read_bytes()).hexdigest() == report.sha256
    assert vm.seen["job"]["name"] == "Crack Launcher _v1.2_.exe" and vm.seen["job"]["timeout_seconds"] == 60
    assert vm.seen["job"]["sysmon"] is False
    # Result.
    assert report.executed and not report.timed_out and terminated
    rules = {e.rule_id for e in report.evidences}
    assert rules == {"GK_BEH_RunKey", "GK_BEH_Summary"}
    assert all(e.source == EvidenceSource.BEHAVIORAL and e.engine == "sandbox" for e in report.evidences)
    assert stages[0] == "boot" and stages[-1] == "done"
    assert not any((tmp_path / "jobs").glob("job-*"))           # job folder (and sample copy) removed
    stored = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
    assert stored["sha256"] == report.sha256 and mgr.list_reports()[0]["evidences"] == 2


def test_timeout_discards_vm(tmp_path, sample, monkeypatch):
    clock = iter(range(0, 10_000, 100))
    monkeypatch.setattr(SM.time, "monotonic", lambda: next(clock))
    terminated = []
    mgr = SM.SandboxManager(launcher=FakeVM(write=False), terminator=terminated.append, availability=available,
                            jobs_dir=tmp_path / "jobs", poll_interval=0)
    report = mgr.analyze(sample, 30)
    assert report.timed_out and terminated and report.evidences == [] and "descartada" in report.error


def test_cancel_discards_vm(tmp_path, sample):
    terminated = []
    mgr = SM.SandboxManager(launcher=FakeVM(write=False), terminator=terminated.append, availability=available,
                            jobs_dir=tmp_path / "jobs", poll_interval=0)
    report = mgr.analyze(sample, 30, cancel=lambda: True)
    assert report.cancelled and terminated and "cancelada" in report.error


def test_sysmon_is_copied_only_when_valid(tmp_path, sample, settings):
    sysmon = tmp_path / "Sysmon64.exe"
    sysmon.write_bytes(b"MZ")
    settings.set("sandbox.sysmon_path", str(sysmon))
    vm = FakeVM()
    SM.SandboxManager(settings, launcher=vm, terminator=lambda t: 0, availability=available,
                      jobs_dir=tmp_path / "jobs", poll_interval=0).analyze(sample, 30)
    assert vm.seen["job"]["sysmon"] is True and "sysmon" in vm.seen["files"]
    settings.set("sandbox.sysmon_path", str(sample))   # not a Sysmon binary
    vm = FakeVM()
    SM.SandboxManager(settings, launcher=vm, terminator=lambda t: 0, availability=available,
                      jobs_dir=tmp_path / "jobs", poll_interval=0).analyze(sample, 30)
    assert vm.seen["job"]["sysmon"] is False


# ---------------------------------------------------------------------------- report parsing
def test_monitor_report_is_parsed_defensively(tmp_path):
    p = tmp_path / "report.json"
    for content, message in ((None, "não gerou"), ("{x", "ilegível"), ('{"format": "other"}', "formato"),
                             ('{"format": "gamekernel-sandbox-report", "a": NaN}', "ilegível")):
        if content is not None:
            p.write_text(content, encoding="utf-8")
        with pytest.raises(SM.SandboxError, match=message):
            SM.load_monitor_report(p)
    p.write_bytes(b'{"format": "gamekernel-sandbox-report"}' + b" " * SM.MAX_REPORT_BYTES)
    with pytest.raises(SM.SandboxError, match="limite"):
        SM.load_monitor_report(p)


def _by_rule(data: dict) -> dict:
    return {e.rule_id: e for e in SM.map_observations(data)}


def test_mapping_persistence_and_drivers():
    ev = _by_rule({"persistence": {
        "run_keys_added": [{"name": "Run\\x", "value": "x.exe"}], "startup_files_added": [{"name": "s.lnk"}],
        "tasks_added": [{"name": "\\T"}], "wmi_added": [{"name": "__EventConsumer\\x"}],
        "ifeo_added": [{"name": "sethc.exe", "value": "cmd.exe"}], "winlogon_changed": [{"name": "Shell", "value": "x"}],
        "services_added": [{"name": "drv", "path": "C:\\d.sys", "type": "kernel driver"},
                           {"name": "svc", "path": "C:\\s.exe", "type": "service"}]}})
    assert ev["GK_BEH_RunKey"].fp_note and ev["GK_BEH_RunKey"].severity == RiskLevel.HIGH
    assert ev["GK_BEH_ScheduledTask"].severity == RiskLevel.MEDIUM
    assert ev["GK_BEH_WmiPersistence"].fp_note == ""
    assert ev["GK_BEH_DriverService"].category == ThreatCategory.ROOTKIT
    assert ev["GK_BEH_ServiceCreated"].category == ThreatCategory.PERSISTENCE
    assert {"GK_BEH_StartupFolder", "GK_BEH_IFEO", "GK_BEH_Winlogon"} <= set(ev)


def test_mapping_credential_decoys():
    ev = SM.map_observations({"credential_access": [
        {"decoy": "browser_passwords", "path": "C:\\...\\Login Data", "process": "x.exe", "in_tree": True},
        {"decoy": "discord_tokens", "path": "C:\\...\\000003.ldb", "process": "explorer.exe", "in_tree": False}]})
    reads = [e for e in ev if e.rule_id == "GK_BEH_CredentialDecoyRead"]
    assert (reads[0].category, reads[0].severity) == (ThreatCategory.PASSWORD_STEALER, RiskLevel.HIGH)
    assert (reads[1].category, reads[1].severity) == (ThreatCategory.COOKIE_STEALER, RiskLevel.MEDIUM)


def test_mapping_ransomware_and_commands():
    many = {"files": {"canaries_modified": [{"path": f"C:\\d{i}"} for i in range(4)],
                      "canaries_deleted": [{"path": "C:\\d9"}]},
            "commands": [{"process": "cmd.exe", "command_line": "vssadmin.exe Delete Shadows /All /Quiet"},
                         {"process": "powershell.exe", "command_line": "powershell -enc SQBFAFgA"},
                         {"process": "powershell.exe", "command_line": "Add-MpPreference -ExclusionPath C:\\"},
                         {"process": "x.exe", "command_line": "x.exe -o stratum+tcp://pool:3333 --donate-level 1"}]}
    ev = _by_rule(many)
    assert (ev["GK_BEH_RansomwareCanaries"].severity, ev["GK_BEH_ShadowCopyDelete"].category) == \
           (RiskLevel.CRITICAL, ThreatCategory.RANSOMWARE)
    assert ev["GK_BEH_SuspiciousCommand"].category == ThreatCategory.DOWNLOADER
    assert ev["GK_BEH_DefenderTampering"].category == ThreatCategory.DEFENSE_EVASION
    assert ev["GK_BEH_Cryptominer"].severity == RiskLevel.HIGH
    few = _by_rule({"files": {"canaries_modified": [{"path": "C:\\d1"}]}})
    assert few["GK_BEH_RansomwareCanaries"].severity == RiskLevel.MEDIUM


def test_mapping_network_cpu_injection_and_misc():
    ev = _by_rule({"network": {"dns": "update.gamestudio.com", "connections": []}})
    assert ev["GK_BEH_NetworkAttempt"].severity == RiskLevel.LOW and ev["GK_BEH_NetworkAttempt"].fp_note
    ev = _by_rule({"network": {"dns": ["discord.com/api/webhooks/1"], "connections": [{"remote": "1.2.3.4:443"}]}})
    assert "GK_BEH_ExfiltrationChannel" in ev and "GK_BEH_NetworkAttempt" not in ev
    ev = _by_rule({"cpu": {"high_usage_ratio": 0.9, "has_window": False, "process": "svc"},
                   "injection": [{"kind": "CreateRemoteThread", "source": "x.exe", "target": "explorer.exe"}],
                   "hosts_modified": True,
                   "registry": {"changed": [{"key": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                                             "value": "DisableAntiSpyware", "after": "1"}]},
                   "files": {"dropped_executables": {"path": "C:\\Temp\\a.exe", "sha256": "ab" * 32}},
                   "lingering_processes": [{"name": "updater"}], "sample": {"main_exited": True}})
    assert ev["GK_BEH_SustainedCpu"].severity == RiskLevel.LOW
    assert ev["GK_BEH_ProcessInjection"].category == ThreatCategory.PROCESS_INJECTION
    assert {"GK_BEH_HostsModified", "GK_BEH_SecurityPolicy", "GK_BEH_DroppedExecutable", "GK_BEH_Lingering"} <= set(ev)
    assert ev["GK_BEH_DroppedExecutable"].locations[0].excerpt == "C:\\Temp\\a.exe"   # scalar → list


def test_mapping_quiet_sample_only_produces_summary():
    ev = SM.map_observations({"sample": {"started": True}, "observed_seconds": 120})
    assert [e.rule_id for e in ev] == ["GK_BEH_Summary"] and ev[0].severity == RiskLevel.INFO
    ev = SM.map_observations({"sample": {"start_error": "not a valid Win32 application"}})
    assert ev[0].rule_id == "GK_BEH_NotStarted"


def test_evidence_roundtrips_through_the_data_contract():
    from gamekernel.core.models import Evidence

    for e in SM.map_observations({"persistence": {"run_keys_added": [{"name": "a", "value": "b"}]}}):
        assert Evidence.from_dict(e.to_dict()).to_dict() == e.to_dict()


# ---------------------------------------------------------------------------- monitor.ps1 (static)
MONITOR = SM.MONITOR_SCRIPT.read_bytes()


def test_monitor_script_is_ascii_and_has_no_network_or_dynamic_code():
    MONITOR.decode("ascii")   # PowerShell 5.1 reads BOM-less UTF-8 as ANSI
    text = MONITOR.decode("ascii")
    for forbidden in ("Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient", "DownloadString", "DownloadFile",
                      "Invoke-Expression", "Start-BitsTransfer", "System.Net.Sockets", "New-PSDrive"):
        assert forbidden.lower() not in text.lower(), forbidden
    assert not re.search(r"\biex\b", text, re.I)


def test_monitor_script_contract_with_parser():
    text = MONITOR.decode("ascii")
    assert "gamekernel-sandbox-report" in text and "done.json" in text and "finally" in text
    for key in ("persistence", "credential_access", "canaries_modified", "dropped_executables", "high_usage_ratio",
                "lingering_processes", "hosts_modified", "sysmon_active", "observed_seconds", "in_tree"):
        assert key in text, key
    for guid in ("0CCE921D", "0CCE922B", "0CCE9226"):   # File System, Process Creation, WFP connection
        assert guid in text
    assert text.count("{") == text.count("}") and text.count("(") == text.count(")")


# ---------------------------------------------------------------------------- helper service
@pytest.fixture
def helper(isolated_data_dir):
    client = HelperClient([sys.executable, "-I", str(ROOT / "gamekernel" / "helper" / "entry.py")],
                          env=sanitized_environment(isolated_data_dir), cwd=ROOT)
    client.start()
    yield client
    client.close()


def test_service_availability_and_refusal(helper, sample, settings):
    info = helper.call("sandbox.availability")
    if sys.platform != "win32":
        assert info["available"] is False and "Windows" in info["reason"]
    assert ".exe" in info["supported_extensions"] and info["limitations"]
    with pytest.raises(HelperError) as exc:   # disabled in settings (default)
        helper.call("sandbox.analyze", {"path": str(sample)})
    assert exc.value.details.get("field") == "settings"
    settings.set("sandbox.enabled", True)
    settings.save()
    if sys.platform != "win32":
        with pytest.raises(HelperError) as exc:
            helper.call("sandbox.analyze", {"path": str(sample)})
        assert exc.value.reason == "not_found" and exc.value.details["executed"] is False
    for params, field in (({"path": "rel.exe"}, "path"), ({"path": str(sample), "timeout_seconds": 5}, "timeout_seconds")):
        with pytest.raises(HelperError) as exc:
            helper.call("sandbox.analyze", params)
        assert exc.value.details.get("field") == field
    assert helper.call("sandbox.reports") == {"reports": []}
