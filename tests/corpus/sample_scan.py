"""Builds a realistic scan in the database exactly as the core would persist it (test data only).

No real malware is involved: results are FileResult objects describing what the engines would
report (EICAR test signature, YARA rule with offsets, crack context, read errors ...).
"""

from __future__ import annotations

import time

from gamekernel.core.models import (
    AnalysisStatus, Classification, Confidence, CrackStatus, Evidence, EvidenceSource, FileFeatures, FileResult,
    Location, RiskLevel, ThreatCategory,
)
from gamekernel.core.scan_api import EngineStatus, ScanMode, ScanStatus, ScanSummary, SignatureOverview

USER = "joaosilva"
GAME = f"C:\\Users\\{USER}\\Downloads\\SuperGame"


def _r(name: str, **kw) -> FileResult:
    path = kw.pop("path", f"{GAME}\\{name}")
    directory = path.rsplit("\\", 1)[0]
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return FileResult(path=path, name=name, directory=directory, extension=ext, size=kw.pop("size", 4096),
                      sha256=kw.pop("sha256", (name.encode().hex() * 8)[:64].ljust(64, "0")),
                      file_type=kw.pop("file_type", "pe_exe"), analyzed_at=time.time(), **kw)


def build(db) -> int:
    scan_id = db.create_scan("deep", [GAME], {"targets": [GAME], "mode": "deep"}, "fp1", "manual", "Jogo completo")
    eicar = _r("eicar_test.com", file_type="text", risk=RiskLevel.CRITICAL, classification=Classification.MALWARE,
               primary_category=ThreatCategory.TEST_FILE, evidences=[Evidence(
                   "Eicar-Signature", "Arquivo de teste EICAR", EvidenceSource.SIGNATURE, ThreatCategory.TEST_FILE,
                   RiskLevel.CRITICAL, Confidence.HIGH, "Assinatura ClamAV confirmada.", engine="clamav")],
               explanation=["Detecção confirmada por assinatura ClamAV (Eicar-Signature) → Crítico."])
    stealer = _r("launcher_patch.exe", risk=RiskLevel.HIGH, classification=Classification.SUSPICIOUS,
                 primary_category=ThreatCategory.PASSWORD_STEALER, possible_false_positive=True,
                 features=FileFeatures(file_type="pe_exe", is_pe=True, signed=False),
                 evidences=[Evidence(
                     "GK_Stealer_BrowserCredentials", "Acesso a credenciais de navegador", EvidenceSource.YARA,
                     ThreatCategory.PASSWORD_STEALER, RiskLevel.HIGH, Confidence.MEDIUM,
                     "Referências a Login Data + CryptUnprotectData.", engine="yara",
                     locations=[Location("string", "caminho do banco de senhas", section=".rdata", offset=0x1A2C0,
                                         rva=0x1C2C0, length=40, excerpt="\\Google\\Chrome\\User Data\\Default\\Login Data")],
                     fp_note="Gerenciadores de senha legítimos também acessam esses arquivos."),
                     Evidence("GK_HEUR_HighEntropy", "Seção com entropia alta", EvidenceSource.HEURISTIC,
                              ThreatCategory.OBFUSCATION, RiskLevel.LOW, Confidence.LOW, "Entropia 7.9 em .text",
                              locations=[Location("section", section=".text", offset=0x400, rva=0x1000)],
                              fp_note="Empacotadores e DRM produzem entropia alta.")],
                 explanation=["Regra YARA de alta severidade", "Sem assinatura digital"])
    xss = _r("<script>alert(1)</script>.dll", file_type="pe_dll", risk=RiskLevel.MEDIUM,
             classification=Classification.PUA, primary_category=ThreatCategory.PUA,
             evidences=[Evidence("PUA.Win.Adware", "Adware", EvidenceSource.SIGNATURE, ThreatCategory.PUA,
                                 RiskLevel.MEDIUM, Confidence.HIGH, engine="clamav")])
    crack_ok = _r("steam_api64.dll", file_type="pe_dll", risk=RiskLevel.INFO, classification=Classification.MODIFIED,
                  crack_status=CrackStatus.RECOGNIZED_CLEAN, primary_category=ThreatCategory.CRACK_COMPONENT,
                  evidences=[Evidence("GK_CTX_GoldbergEmu", "Emulador Goldberg reconhecido", EvidenceSource.CONTEXT,
                                      ThreatCategory.CRACK_COMPONENT, RiskLevel.INFO, Confidence.HIGH,
                                      details={"modification": "steam_emu"})])
    crack_bad = _r("crack/Game.exe", path=f"{GAME}\\crack\\Game.exe", risk=RiskLevel.HIGH,
                   classification=Classification.SUSPICIOUS, crack_status=CrackStatus.SUSPICIOUS,
                   primary_category=ThreatCategory.PERSISTENCE,
                   evidences=[Evidence("GK_CTX_PatchedExe", "Executável modificado", EvidenceSource.CONTEXT,
                                       ThreatCategory.CRACK_COMPONENT, RiskLevel.INFO, Confidence.MEDIUM,
                                       details={"modification": "patched_exe"}),
                              Evidence("GK_Persist_RunKey", "Persistência em Run", EvidenceSource.STATIC,
                                       ThreatCategory.PERSISTENCE, RiskLevel.HIGH, Confidence.MEDIUM,
                                       locations=[Location("string", offset=0x2200, excerpt="Software\\Microsoft\\Windows\\CurrentVersion\\Run")])])
    member = _r("payload.exe", path=f"{GAME}\\extras.zip::bin/payload.exe", container=f"{GAME}\\extras.zip",
                member_path="bin/payload.exe", depth=1, risk=RiskLevel.MEDIUM, classification=Classification.SUSPICIOUS,
                primary_category=ThreatCategory.DROPPER,
                evidences=[Evidence("GK_Dropper_EmbeddedPE", "PE embutido no overlay", EvidenceSource.STATIC,
                                    ThreatCategory.DROPPER, RiskLevel.MEDIUM, Confidence.MEDIUM,
                                    locations=[Location("overlay", offset=0x8000, length=0x3000)])])
    unreadable = _r("locked.pak", file_type="data", status=AnalysisStatus.ERROR, status_reasons=["Permissão negada"])
    skipped = _r("huge.iso", file_type="iso", status=AnalysisStatus.SKIPPED,
                 status_reasons=["Acima do limite de 512 MB (somente hash e ClamAV)"])
    partial = _r("setup.7z", file_type="7z", status=AnalysisStatus.PARTIAL, status_reasons=["Membro protegido por senha"],
                 risk=RiskLevel.LOW, classification=Classification.INCONCLUSIVE)
    unicode_name = _r("ゲーム.exe", risk=RiskLevel.NONE, classification=Classification.KNOWN_LEGIT)
    clean = [_r(f"data{i}.bin", file_type="data") for i in range(5)]
    db.add_file_results(scan_id, [eicar, stealer, xss, crack_ok, crack_bad, member, unreadable, skipped, partial,
                                  unicode_name, *clean])
    summary = ScanSummary(
        scan_id=scan_id, status=ScanStatus.COMPLETED, mode=ScanMode.DEEP, targets=[GAME], started_at=time.time() - 42,
        finished_at=time.time(), files_found=15, files_analyzed=13, files_skipped=1, files_errors=1, members_analyzed=1,
        engines=[EngineStatus("clamav", "ClamAV", True, True, "1.5.4"),
                 EngineStatus("yara", "YARA", True, True, "4.5.4"),
                 EngineStatus("sandbox", "Sandbox", False, False, detail="Windows Sandbox não instalado")],
        signatures=SignatureOverview(clamav_signature_count=1000, yara_rule_count=42, ioc_count=10, stale=True,
                                     stale_reason="última atualização há 30 dias"),
        limitations=["ClamAV executado sem as bases oficiais (somente assinaturas locais)."],
    )
    db.update_scan(scan_id, files_found=15, files_analyzed=13, files_skipped=1, files_errors=1, members_analyzed=1,
                   threats=1, suspicious=3, pua=1, bytes_scanned=15 * 4096, max_risk=RiskLevel.CRITICAL)
    db.finish_scan(scan_id, "completed", summary.to_dict())
    return scan_id
