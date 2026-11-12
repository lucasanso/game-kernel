# Game Kernel — Divisão do trabalho entre os dois agentes (revisão 3)

> Revisão 3 (2026-11-12): **reconciliação** depois que as duas branches foram integradas.
> O Agente B trabalhou a partir da revisão 1 e implementou partes que a revisão 2 atribuía ao A;
> esta revisão registra a divisão **real** e elimina duplicações. Revisões anteriores: histórico do Git.
>
> Branches: Agente A `claude/magical-bell-fi6jw1` · Agente B `claude/stoic-mayer-r46kuo`.
> A branch do A já contém um merge da branch do B (sem conflitos de código).

## 1. Papéis

* **Agente A — Agente 1 (Core e Segurança, C++)**: núcleo de análise, motores, quarentena, tempo real,
  Performance Monitor, System Optimizer, isolamento dos parsers, segurança de memória, conteúdo de detecção.
* **Agente B — Agente 2 (Python, integração e ferramentas)**: gk-ipc, processo auxiliar Python, atualizações
  offline (preparação em Python + verificação/instalação em C++), Threat Intelligence, relatórios, sandbox,
  motor de testes, CI do produto, empacotamento — e a **interface Qt 6 C++** (pendência P2, ver §5).

## 2. Árvore nativa única: `native/`

Toda a parte C++ fica em `native/` (proposta P4 do Agente B, adotada). Cada subprojeto compila sozinho e
entra no build raiz (`CMakeLists.txt` da raiz do repositório) por `add_subdirectory()`.

| Diretório | Dono | Conteúdo |
|---|---|---|
| `native/core/` | A | `gk_core` (sem Qt): hash, tipo real, PE, YARA, compactados, e os próximos motores |
| `native/bindings/` | A | `gk_native` (pybind11) — espelho da API do núcleo; muda junto com ela. **Substitui a etapa B6** |
| `native/worker/`, `native/cli/` | A | `gk-scanworker` (processo isolado), `gk-cli` |
| `native/quarantine/`, `native/realtime/`, `native/perf/`, `native/sysopt/` | A | Quarentena, tempo real, Performance Monitor, System Optimizer |
| `native/bridge/` | A | Serviços Qt (QObject/sinais) que a interface consome |
| `native/ipc/` | B | gk-ipc v1 (`HelperClient` C++/Qt) |
| `native/updates/` | B | Verificação Ed25519 e instalação atômica de `.gkpkg` |
| `native/app/` | B (P2) | Interface Qt 6 C++ |
| `CMakeLists.txt`, `CMakePresets.json`, `vcpkg.json`, `cmake/` (raiz) | A | Build raiz; B pede inclusões/dependências dos seus subprojetos |

## 3. Python, testes, documentos

| Caminho | Dono |
|---|---|
| `gamekernel/ipc/**`, `gamekernel/updates/**`, `gamekernel/ti/**`, `gamekernel/core/report_*.py`, `gamekernel/core/sysinfo.py`, `gamekernel/engines/sandbox*`, `gk_helper.py` | B |
| `gamekernel/engines/indicators.py` (tabela de indicadores), `gamekernel/core/filetypes.py` e `hashing.py` (oráculos de equivalência), `gamekernel/core/scan_api.py` (a substituir) | A |
| Fundação Python (`models.py`, `config.py`, `app_paths.py`, `netguard.py`, `crypto_utils.py`, `db.py`, `threat_catalog.py`) | A mantém; mudanças combinadas e registradas no §6 |
| `signatures/yara/**`, `signatures/internal/**`, `signatures/data/**`, `signatures/ioc/**` (conteúdo) | A |
| `signatures/keys/**` (chave pública de release — P6) | B |
| `tools/core_*` | A |
| `tools/**` (demais) | B |
| `tests/foundation/**`, `tests/native/test_{hash,filetype,pe,yara,archive,contracts}.py`, `tests/corpus_pe/**`, `tests/conftest.py` | A |
| `tests/native/native_build.py`, `tests/native/test_native_ipc.py`, `tests/{ipc,reports,sandbox,ti,updates,ui,integration,regression,perf,fp}/**` | B |
| `.github/workflows/core-ci.yml` | A |
| `.github/workflows/ci.yml`, `installer/**`, `assets/**` | B |
| `requirements.txt` (runtime do auxiliar Python) | B |
| `requirements-dev.txt`, `pyproject.toml` | A (B pede inclusões) |
| Docs: `ARCHITECTURE.md`, `MODULES.md`, `MIGRATION_PLAN.md`, `SECURITY.md`, `CORE_API.md`, `DETECTION_RULES.md`, `THREAT_COVERAGE.md`, `WORK_SPLIT.md`, `PROGRESS_A.md` | A |
| Docs: `INTEGRATION.md`, `BUILD.md`, `TESTING.md`, `OFFLINE_UPDATES.md`, `PROGRESS_B.md`, `README.md`, `INSTALL.md`, `USAGE.md`, `PRIVACY.md`, `LIMITATIONS.md` | B |
| `docs/CHANGELOG.md` | compartilhado: cada entrada marcada **(A)** ou **(B)** |

## 4. Duplicações eliminadas

| Tema | Decisão |
|---|---|
| Verificação/instalação de pacotes offline | Implementação única: `native/updates` (B). O passo "M10 — atualização" do A foi cancelado. |
| Cliente do processo auxiliar | Implementação única: `native/ipc` (B). |
| Protocolo entre processos | gk-ipc v1 (B) também para o `gk-scanworker` do A — não haverá segundo protocolo. |
| Bindings pybind11 do núcleo | Implementação única: `gk_native` (A). A etapa B6 passa a ser "usar `gk_native` no motor de testes". |
| Validação de bancos ClamAV em pacotes | Implementação única: `gk::updates::validateClamavDir` (B). O A não fará outra. |
| Validação de regras YARA em pacotes | **Ainda duplicada**: `gk::updates::validateYaraDir` (B, Qt) e `gk::yara::validate_rules_dir` (A, `gk_core`). Proposta: o validador do B delega ao `gk_core`, para que as regras sejam validadas exatamente como o motor as compila (mesmas externas, política de `include`, metadados obrigatórios). Execução: B, quando `native/updates` passar a ligar `gk_core`. |
| Documentos `INTEGRATION.md` e `TESTING.md` | Versões do B mantidas; conteúdo do núcleo foi para `docs/CORE_API.md`. |
| Changelog | Um só (`docs/CHANGELOG.md`), com marcação por agente. |

## 5. Decisões pendentes do usuário

* **P1 — Nome do produto**: "Game Kernel" (título da diretriz e repositório) ou "OFFLINE GAME GUARD" (texto da
  diretriz)? Os dois agentes mantêm *Game Kernel* até a confirmação; o nome exibido fica numa constante.
* **P2 — Dono da interface Qt 6 C++**: proposta dos dois agentes: **B** (preserva a divisão original), consumindo
  `native/bridge` do A.

## 6. Registro de mudanças de contrato

| Data | Agente | Mudança |
|---|---|---|
| 2026-11-12 | A | Revisão 3: reconciliação pós-merge (§2–§4); `cpp/` → `native/core` e `native/bindings`. |
| 2026-11-12 | A | `gamekernel/database/db.py`: correção de vazamento de handle na recuperação (Windows). Sem mudança de API. |
| 2026-11-12 | A | Revisão 2: arquitetura híbrida. |
| 2026-11-12 | A | Revisão 1: contratos Python iniciais. |
