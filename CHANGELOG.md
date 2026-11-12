# Changelog

## Agente A — Core e Segurança

### [não lançado]
- M1: núcleo C++20 `gk_core` — `ByteView` (leitura com limites e aritmética verificada), arquivos somente leitura e
  mapeados (compartilhamento total, só arquivos comuns), SHA-256 (libsodium) e MD5, identificação de tipo real.
- M1: módulo pybind11 `gk_native` (API v1) com tradução de exceções (`GkError`, `args=(código, mensagem)`).
- M1: testes de equivalência C++ × Python (hashlib, `filetypes.py`), execução sob ASan/UBSan, checagem de
  compilação Windows com mingw-w64; `contracts/schema.sql` extraído e verificado contra `db.py`.
- CI do núcleo (`.github/workflows/core-ci.yml`): Linux (release + ASan) e Windows (MSVC + vcpkg, triplet estático).
- Dependência adicionada: libsodium (ISC).
- Removido `gamekernel/core/tools.py` (WIP nunca integrado).
- Arquitetura híbrida C++20/Python adotada (docs/ARCHITECTURE.md rev. 2, MIGRATION_PLAN.md, INTEGRATION.md).
- Divisão de trabalho revisada (docs/WORK_SPLIT.md rev. 2): quarentena passa para o núcleo C++; UI Qt 6 C++ com o Agente B.
- Fundação Python (modelos, configurações, banco SQLite, netguard, Ed25519) — 23 testes.

## Agente B — Python, integração e ferramentas

### [não lançado]
- Processo auxiliar Python `gk-helper` (`gamekernel/helper/`): servidor do envelope IPC de `docs/INTEGRATION.md` §3
  com extensões opcionais (cancelamento, prazo, id em eventos, `error.data.reason`), isolamento de falhas
  (exceção → 1099 com o auxiliar ativo; proteção de stdout; `netguard`), cliente Python; métodos em
  `contracts/helper_methods.md`.
- Cliente C++/Qt de referência (`native/ipc/`): QProcess, sinais e slots, Job Object (Windows), RLIMIT_AS e
  PDEATHSIG (Linux), prazo → cancelamento → morte, reinício limitado. Oferecido ao Agente A para o `cpp/bridge` (M13).
- Relatórios forenses (`gamekernel/reports/`): JSON, HTML autocontido sem JavaScript (CSP `default-src 'none'`),
  PDF (reportlab, fonte Unicode); 15 seções e relatório individual de cracks; redação de usuário e de nome do
  computador; banco somente leitura. Serviço `reports.generate`.
- Sandbox (`gamekernel/sandbox/`): orquestração do Windows Sandbox sem rede, recusa sem isolamento, `monitor.ps1`
  (iscas de credenciais, documentos-isca, auditoria por GUID, árvore de processos), mapeamento para evidências
  comportamentais. Serviços `sandbox.*`.
- Atualização offline: formato `.gkpkg` v1 (`contracts/update_package.md`), construtor e verificador de referência
  em Python (`gamekernel/updates/`), verificador e instalador atômico C++ de referência (`native/updates/`,
  libsodium + libyara; oferecido ao Agente A para o M10), CLI `gk-update`.
- Inteligência de ameaças: `gamekernel/intel/ioc.py` (normalização, deduplicação, conflitos) e
  `gamekernel/rules/prepare.py` (compilação e *lint* de YARA); verificação antes de assinar com os validadores C++
  (`gamekernel/updates/prepare.py`); ferramentas `tools/gk_keygen.py`, `tools/make_update_package.py`,
  `tools/ti_build_ioc.py`.
- Testes: `tests/helper/`, `tests/integration/` (equivalência Python × C++ e mutações aleatórias),
  `tests/corpus/`; modo `GK_NATIVE_SANITIZE=1`. CI `.github/workflows/ci.yml` (Linux + Windows/MSVC).
- Dependências (nativo, B): Qt 6.4+ Core e Test, libsodium, libyara (opcional; sem ela, componentes YARA são recusados).
- Alinhamento à `docs/WORK_SPLIT.md` rev. 2: código movido de `gamekernel/ipc` → `gamekernel/helper`,
  `core/report_*` → `gamekernel/reports`, `engines/sandbox_manager` → `gamekernel/sandbox`, `ti/` →
  `gamekernel/intel` + `gamekernel/rules` + `gamekernel/updates/prepare.py`; testes de `tests/{ipc,reports,sandbox}`
  → `tests/helper`, de `tests/{updates,ti,native}` → `tests/integration`; o envelope IPC adotou o §3 do Agente A.
