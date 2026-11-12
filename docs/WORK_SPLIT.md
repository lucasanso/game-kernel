# Game Kernel — Divisão do trabalho entre dois agentes

Dois agentes desenvolvem o Game Kernel em paralelo no repositório `lucasanso/game-kernel`:

* **Agente A** (sessão original): **motor de detecção e dados**
* **Agente B** (outra conta): **aplicativo desktop, proteção e distribuição**

A divisão foi feita por **propriedade de arquivos**: cada arquivo tem um único dono. Assim, as
duas branches podem ser mescladas sem conflitos. Os pontos de contato entre as partes são
**contratos** já implementados e testados na fundação (seção 3).

> Requisitos completos do produto: o prompt original do projeto (seções 1–21, "software
> desktop nativo" e "módulo especial de cracks"). Este documento só define **quem faz o quê**
> e **como as partes se encaixam**.

---

## 1. Fundação já entregue (commit base para os dois agentes)

Implementado e coberto por testes (`tests/foundation/`, 23 testes passando):

| Arquivo | Conteúdo |
|---|---|
| `gamekernel/__init__.py` | Versão, nome do app |
| `gamekernel/app_paths.py` | Diretórios (instalado, portátil, dev), layout de assinaturas |
| `gamekernel/config.py` | Configurações persistentes com padrões e validação |
| `gamekernel/netguard.py` | Bloqueio de rede via *audit hook* + autoteste |
| `gamekernel/logging_setup.py` | Logs locais rotativos |
| `gamekernel/crypto_utils.py` | Ed25519: gerar/assinar/verificar, chaves confiáveis |
| `gamekernel/core/models.py` | `Evidence`, `Location`, `FileResult`, `FileFeatures`, enums de risco/classificação/crack |
| `gamekernel/core/threat_catalog.py` | O que cada ameaça faz, dados em risco, limitações, recomendações |
| `gamekernel/core/scan_api.py` | **Contrato do scanner**: `ScanOptions`, `ScanProgress`, `ScanSummary`, `EngineStatus`, `SignatureOverview`, `ScannerProtocol` |
| `gamekernel/core/filetypes.py` | Identificação por magic bytes, PE disfarçado |
| `gamekernel/core/hashing.py` | SHA-256/MD5 em streaming |
| `gamekernel/database/db.py` | SQLite WAL: varreduras, resultados, caches, reputação, quarentena, log de auditoria encadeado, estado de assinaturas, eventos de tempo real, recuperação de banco corrompido |
| `tests/conftest.py` | Fixtures `isolated_data_dir`, `settings`, `db` |
| `requirements*.txt`, `pyproject.toml`, `docs/ARCHITECTURE.md` | Dependências fixadas, config do pytest, arquitetura |

**Arquivos da fundação são congelados.** Qualquer mudança neles precisa ser combinada pelos
dois agentes (via o usuário) e registrada na seção 7 deste documento.

---

## 2. Propriedade dos arquivos

### Agente A — Motor de detecção e dados (FASES 3, 4, 5, 6, backend da 10, testes do motor na 11)

| Área | Arquivos |
|---|---|
| Orquestração | `gamekernel/core/scanner.py` (implementa `ScannerProtocol`), `core/enumerator.py`, `core/worker.py`, `core/detection_engine.py`, `core/risk_engine.py`, `core/tools.py` (localização de binários), `core/integrity.py` (verificação do manifesto de integridade) |
| Motores | `gamekernel/engines/clamav_engine.py`, `yara_engine.py`, `pe_analyzer.py`, `authenticode.py`, `strings_analyzer.py`, `static_heuristics.py`, `script_analyzer.py`, `archive_engine.py`, `pyinstaller.py`, `lnk_parser.py`, `reputation.py`, `game_context.py` (módulo especial de cracks) |
| Tempo real (backend) | `gamekernel/realtime/monitor.py` |
| CLI | `gamekernel/cli.py` (`python -m gamekernel.cli scan <pasta> --mode quick --json saida.json`) |
| Assinaturas base | `signatures/yara/**`, `signatures/ioc/**`, `signatures/clamav/**` (assinaturas locais, ex.: EICAR) |
| Ferramentas | `tools/build_known_good.py`, `tools/build_integrity_manifest.py` |
| Testes | `tests/foundation/**`, `tests/engines/**`, `tests/core/**`, `tests/realtime/**`, `tests/perf/**`, `tests/pe_builder.py` (gerador de PEs benignos para testes — pode ser usado pelo B) |
| Docs | `docs/THREAT_COVERAGE.md` (detecção e limitações por categoria), `docs/DETECTION_RULES.md` (regras YARA documentadas), `docs/PROGRESS_A.md`, `docs/TEST_REPORT_A.md` |

### Agente B — Aplicativo, proteção e distribuição (FASES 7, 8, 9, UI da 10, 12, seções 7, 14, 15, 16)

| Área | Arquivos |
|---|---|
| Entrada | `main.py` (raiz do repositório) |
| Interface (PySide6) | `gamekernel/ui/**` — tema escuro, ícones, menu lateral, Dashboard, Scanner, Resultados, Quarentena, Histórico, Tempo real, Sandbox, Atualizações, Privacidade/Rede, Configurações, notificações internas, bandeja do sistema, `ui/workers.py` (QThread em volta do `Scanner`) |
| Quarentena | `gamekernel/quarantine/vault.py` (AES-256-GCM, chave protegida por DPAPI, `.gkq`, restaurar/excluir com confirmação) |
| Atualização offline | `gamekernel/updates/**` (formato `.gkpkg`, verificação Ed25519, instalação atômica com rollback, importação de CVD oficiais do ClamAV) |
| Relatórios | `gamekernel/core/report_engine.py` (JSON, HTML autocontido, PDF via reportlab), `gamekernel/core/sysinfo.py` |
| Sandbox | `gamekernel/engines/sandbox_manager.py`, `gamekernel/engines/sandbox/monitor.ps1` (Windows Sandbox sem rede) |
| Ferramentas | `tools/gk_keygen.py`, `tools/make_update_package.py`, `tools/network_audit.ps1`, `tools/make_icon.py` |
| Distribuição | `installer/**` (spec do PyInstaller, script Inno Setup, `build_windows.ps1`), `.github/workflows/**`, `assets/**` (ícone/identidade visual) |
| Testes | `tests/ui/**`, `tests/quarantine/**`, `tests/updates/**`, `tests/reports/**`, `tests/sandbox/**` |
| Docs | `README.md`, `docs/INSTALL.md`, `docs/USAGE.md`, `docs/OFFLINE_UPDATES.md`, `docs/BUILD.md`, `docs/PRIVACY.md`, `docs/LIMITATIONS.md` (consolida e referencia `THREAT_COVERAGE.md`), `docs/PROGRESS_B.md`, `docs/TEST_REPORT_B.md` |

---

## 3. Contratos entre as partes

### 3.1 Scanner (A implementa, B consome)

```python
from gamekernel.core.scanner import Scanner                 # A
from gamekernel.core.scan_api import ScanOptions, ScanMode  # fundação

scanner = Scanner(settings, db, on_progress=cb_prog, on_result=cb_res, on_log=cb_log)
summary = scanner.run(ScanOptions(targets=[pasta], mode=ScanMode.DEEP, label="Jogo completo"))  # bloqueante
scanner.pause(); scanner.resume(); scanner.cancel()          # thread-safe
```

* `run()` é bloqueante → B o executa dentro de um `QThread` e reemite os callbacks como sinais Qt.
* Callbacks são chamados na thread de `run()`; `on_progress` ≈ 10/s no máximo.
* O scanner grava tudo no banco (`scans`, `scan_files`); a UI lê os resultados com
  `db.get_file_results(scan_id, ...)` e `db.count_file_results(...)` (paginação e filtros prontos).
* **Retomar varredura interrompida**: `main.py` (B) chama `db.mark_interrupted_scans()` na inicialização;
  o Histórico oferece "Retomar", que executa `ScanOptions(targets=scan["targets"], mode=..., origin="resume",
  resume_of=scan_id)`. Arquivos já analisados vêm do cache automaticamente.

### 3.2 Estado dos motores e assinaturas (A implementa, B exibe no Dashboard/Atualizações)

```python
from gamekernel.core.detection_engine import engine_statuses, signature_overview   # A
engine_statuses(settings) -> list[EngineStatus]
signature_overview(settings, db) -> SignatureOverview       # inclui stale / stale_reason
```

### 3.3 Layout das assinaturas instaladas (B escreve, A lê)

```
<data>/signatures/active/manifest.json
<data>/signatures/active/clamav/   *.cvd *.cld *.cud *.hdb *.hsb *.ndb *.ldb *.cdb *.ign2 *.fp *.sfp
<data>/signatures/active/yara/     *.yar *.yara
<data>/signatures/active/ioc/      *.json  (formato abaixo)
<data>/signatures/previous/        (conjunto anterior, para rollback)
<data>/signatures/staging/         (temporário durante a instalação)
```
Funções: `app_paths.active_signatures_dir()`, `previous_signatures_dir()`, `staging_signatures_dir()`.
Os motores carregam **as assinaturas base** (`<instalação>/signatures/`) **+ as ativas**; um arquivo ativo
com o mesmo nome substitui o base. Depois de instalar um pacote, B chama
`db.set_signature_state(componente, versão, origem, detalhes)` para `clamav`, `yara` e `ioc`.

Validação antes de ativar (A implementa, B chama no instalador de pacotes, sobre a pasta `staging`):

```python
from gamekernel.engines.yara_engine import validate_rules_dir        # -> (ok: bool, mensagens: list[str], n_regras: int)
from gamekernel.engines.clamav_engine import verify_database_dir     # -> (ok: bool, mensagens: list[str], info: list[dict])
from gamekernel.engines.reputation import validate_ioc_file          # -> (ok: bool, mensagens: list[str], n_entradas: int)
```

Formato IOC (`gamekernel-ioc`):
```json
{"format": "gamekernel-ioc", "version": "2026.11.12",
 "entries": [{"sha256": "<64 hex>", "verdict": "bad|good", "name": "…", "category": "<ThreatCategory>",
              "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "source": "…", "note": "…"}]}
```

### 3.4 Binários de terceiros (B empacota, A usa)

```
<recursos>/third_party/clamav/   clamscan.exe sigtool.exe libclamav.dll (+ DLLs do pacote oficial)
<recursos>/third_party/7zip/     7z.exe 7z.dll
```
A resolve os caminhos em `core/tools.py` (fallback para o PATH no Linux de desenvolvimento) e verifica
cada binário com `core/integrity.py` antes de usá-lo.

### 3.5 Manifesto de integridade (A implementa verificação e gerador, B chama no build)

* Build (B): `python tools/build_integrity_manifest.py <pasta_dist> --key <chave_privada>` gera
  `integrity_manifest.json` + `integrity_manifest.sig` (Ed25519, chave de release).
* Execução: `from gamekernel.core.integrity import check_installation` → `IntegrityReport(ok, verified, missing, modified, unsigned, detail)`; B exibe em Privacidade/Dashboard.

### 3.6 Sandbox (B implementa, A reavalia o risco)

* B: `sandbox_manager.check_availability() -> (disponível, motivo)`; `SandboxManager(settings).analyze(caminho, ...) -> SandboxReport` com `evidences: list[Evidence]` (`source=EvidenceSource.BEHAVIORAL`).
  Se o isolamento não estiver disponível, **não executa** e informa o motivo.
* A: `from gamekernel.core.risk_engine import reassess` → `reassess(file_result, extra_evidences) -> FileResult`.
  B persiste com `db.update_file_result(file_result.db_id, novo_resultado)`.

### 3.7 Tempo real (A implementa backend, B faz a página e as notificações)

```python
from gamekernel.realtime.monitor import RealtimeMonitor, RealtimeEvent   # A
mon = RealtimeMonitor(settings, db, on_event=callback)   # callback chamado em thread de fundo
mon.start(); mon.stop(); mon.is_running; mon.watched_folders
```
`RealtimeEvent(path, kind, result: FileResult | None, message)`. B decide notificações
(`settings realtime.notify_min_risk`) e mostra o histórico via `db.list_realtime_events()`.

### 3.8 Quarentena, auditoria e reputação (fundação; B usa)

* Tabelas e métodos prontos em `db.py`: `add_quarantine_item`, `list_quarantine`, `update_quarantine_status`,
  `add_quarantine_event`, `list_quarantine_events`, `append_audit`, `verify_audit_chain`,
  `set_reputation` (marcar "confiável" = possível falso positivo), `get_reputation`.
* Membros de arquivos compactados (`FileResult.container` preenchido): a quarentena isola o arquivo
  **contêiner** (`container`), explicando isso ao usuário.

---

## 4. Ordem de entrega e dependências

| Entrega do A | Libera para o B |
|---|---|
| A1 — motores estáticos + `Scanner` + `cli.py` | integrar Scanner/Resultados/Histórico com dados reais |
| A2 — `engine_statuses`, `signature_overview`, validadores de assinaturas | Dashboard e instalador de pacotes completos |
| A3 — `RealtimeMonitor`, `reassess`, `integrity` | página de tempo real, sandbox, integridade |

B pode começar imediatamente: tema/widgets/páginas, quarentena, atualizações, relatórios,
sandbox, empacotamento e CI só dependem da fundação. Até A1 chegar, B pode testar a UI com
um **duplo de teste** de `ScannerProtocol` restrito a `tests/ui/` (nunca no código do produto).

---

## 5. Fluxo Git

1. Base comum: branch `claude/magical-bell-fi6jw1` (commit da fundação).
2. O Agente B cria **sua própria branch** a partir desse commit e só altera arquivos que lhe pertencem.
3. Integração: o usuário mescla as duas branches em `main` (PRs). Como os arquivos são disjuntos,
   não há conflitos. Cada agente pode mesclar `main` na sua branch quando precisar testar a integração.
4. Commits pequenos e frequentes; `pytest -q` precisa passar antes de cada push.

---

## 6. Regras comuns (definição de pronto)

* Nada de funções vazias, `TODO`, botões sem função ou resultados simulados no código do produto.
* Python 3.13, `from __future__ import annotations`, type hints, `logging.getLogger(__name__)`.
* **Textos da interface e documentação em português (pt-BR)**; identificadores e comentários em inglês.
* Nenhum uso de rede (requests/urllib/QtNetwork proibidos). `main.py` chama `netguard.install()`
  **antes** de qualquer outro import e `multiprocessing.freeze_support()`.
* Subprocessos: caminho absoluto, `shell=False`, `CREATE_NO_WINDOW`, `cwd` = pasta da ferramenta.
* Nunca executar, abrir ou carregar arquivos analisados (exceto dentro da sandbox isolada).
* Amostras de teste perigosas (EICAR, scripts com comandos suspeitos) são **geradas em tempo de teste**
  em pastas temporárias — nunca commitadas — para não disparar o antivírus de quem clona o repositório.
* Mudanças em arquivos da fundação ou em contratos: combinar via usuário e registrar na seção 7.

---

## 7. Registro de mudanças de contrato

| Data | Agente | Mudança |
|---|---|---|
| 2026-11-12 | A | Versão inicial dos contratos. |
