# Game Kernel — Divisão do trabalho entre os dois agentes (revisão 2)

> Revisão 2 (2026-11-12), após a diretriz de arquitetura híbrida C++/Python.
> A revisão 1 continua no histórico do Git. Princípio mantido: **cada arquivo tem um único dono**,
> para que as branches dos dois agentes sejam mescladas sem conflitos.

## 1. Papéis

* **Agente A — "Agente 1: Core e Segurança"** (C++): núcleo, análise de arquivos, quarentena,
  integração com Windows, segurança de memória, desempenho, e a camada de serviços que a UI consome.
* **Agente B — "Agente 2: Python, integração e ferramentas"**: interface (mantida com B, como na revisão 1,
  agora em Qt 6 C++), helper Python, automação, atualizações offline (preparação), inteligência de
  ameaças, motor de testes, relatórios, empacotamento.

A UI permanece com B (divisão já estabelecida, preservada como pede a diretriz). B consome **somente** os
serviços de `cpp/bridge` (sinais/slots Qt); não acessa internals do núcleo.

## 2. Propriedade de arquivos

### Agente A

| Área | Caminhos |
|---|---|
| Núcleo C++ | `cpp/core/**` (análise, PE, hashing, tipo real, Authenticode, YARA, compactados, scripts/LNK, ClamAV, reputação, contexto de jogo/cracks, risco, orquestrador, banco SQLite C++, configurações, quarentena, verificação/instalação de pacotes, integridade, tempo real, Performance Monitor, System Optimizer, processos/IPC) |
| Processos C++ | `cpp/worker/**`, `cpp/cli/**` |
| Camada de serviços Qt | `cpp/bridge/**` |
| Bindings | `cpp/bindings/**` (módulo `gk_native`) |
| Build | `CMakeLists.txt`, `CMakePresets.json`, `vcpkg.json`, `cmake/**`, `.github/workflows/core-ci.yml` |
| Contratos | `contracts/**` |
| Conteúdo de detecção | `signatures/yara/**`, `signatures/ioc/**`, `signatures/clamav/**`, `signatures/internal/**`, `signatures/data/**` (famílias de cracks/mods), `gamekernel/engines/indicators.py` (tabela de indicadores) |
| Python legado do núcleo (a remover após equivalência) | `gamekernel/core/filetypes.py`, `gamekernel/core/hashing.py`, `gamekernel/core/scan_api.py` |
| Testes | `tests/foundation/**`, `tests/native/**` (unitários e de equivalência do núcleo via `gk_native`), `tests/corpus_pe/**` (fontes C para PEs reais via mingw-w64) |
| Docs | `docs/ARCHITECTURE.md`, `docs/MODULES.md`, `docs/INTEGRATION.md`, `docs/MIGRATION_PLAN.md`, `docs/SECURITY.md`, `docs/THREAT_COVERAGE.md`, `docs/DETECTION_RULES.md`, `docs/PROGRESS_A.md`; seção "Núcleo" de `docs/BUILD.md` e de `docs/TESTING.md`; seção "Agente A" de `CHANGELOG.md` |

### Agente B

| Área | Caminhos |
|---|---|
| Interface Qt 6 (C++) | `cpp/app/**` (janela, menu lateral, páginas, tema/QSS, ícones, bandeja, notificações) |
| Helper Python | `gamekernel/helper/**` (servidor JSON-RPC: relatórios, sandbox, inteligência de ameaças, preparação de pacotes) |
| Python de apoio | `gamekernel/` exceto os arquivos do Agente A listados acima (modelos, config, paths, netguard, db, crypto_utils, threat_catalog — mantidos para ferramentas, helper e testes) |
| Relatórios | `gamekernel/reports/**` |
| Sandbox | `gamekernel/sandbox/**` (inclui `monitor.ps1`) |
| Regras/IOC — ferramentas | `gamekernel/rules/**`, `gamekernel/intel/**`, `tools/**` (exceto geradores que o A criar em `tools/core_*`) |
| Testes (motor de testes) | `tests/integration/**`, `tests/regression/**`, `tests/perf/**`, `tests/fp/**`, `tests/helper/**`, `tests/ui/**`, `tests/corpus/**` |
| Empacotamento | `installer/**`, `.github/workflows/` (exceto `core-ci.yml`), `assets/**` |
| Docs | `README.md`, `docs/INSTALL.md`, `docs/USAGE.md`, `docs/OFFLINE_UPDATES.md`, `docs/PRIVACY.md`, `docs/LIMITATIONS.md`, `docs/PROGRESS_B.md`; seção "Empacotamento" de `docs/BUILD.md`; seção "Motor de testes" de `docs/TESTING.md`; seção "Agente B" de `CHANGELOG.md` |

## 3. Interfaces entre A e B

| A entrega | B usa em |
|---|---|
| `gk_native` (pybind11, `docs/INTEGRATION.md` §2) | motor de testes, ferramentas |
| `cpp/bridge`: `ScanService`, `ResultsModel`, `QuarantineService`, `UpdateService`, `RealtimeService`, `PerformanceService`, `OptimizerService`, `IntegrityService`, `HelperClient` | páginas da UI |
| `contracts/schema.sql`, `contracts/*.schema.json`, `contracts/threat_catalog.json` | helper, relatórios, testes |
| `gk-cli` (varreduras sem UI, saída JSON) | testes de integração, automação |
| Verificação/instalação de pacotes em C++ (`UpdateService`) | Offline Update Center; ferramentas de preparação geram o formato que o núcleo verifica |

| B entrega | A usa em |
|---|---|
| Helper Python (`gk-helper`) com métodos documentados em `contracts/ipc.md` | `HelperClient` no bridge (A implementa o cliente; B implementa o servidor) |
| Formato do pacote `.gkpkg` e ferramentas de geração | verificação/instalação no núcleo (o formato é fixado em `contracts/update_package.md`, escrito por B e revisado por A) |
| Corpus de testes e suíte de integração | validação contínua do núcleo |

## 4. Fluxo Git

Branch base: `claude/magical-bell-fi6jw1`. Cada agente trabalha na sua branch, altera só seus arquivos,
roda `pytest -q` (e o build CMake, quando houver C++) antes de cada push. O usuário mescla em `main`.

## 5. Regras comuns

* Nada de funções vazias, `TODO`, simulações ou botões sem função no produto.
* Textos para o usuário em pt-BR; identificadores e comentários em inglês.
* Nenhuma rede. Nenhum arquivo analisado é executado fora da sandbox isolada.
* Amostras perigosas (EICAR etc.) são geradas em tempo de teste, nunca commitadas.
* Mudanças de contrato: combinadas via usuário e registradas no §7.

## 7. Registro de mudanças de contrato

| Data | Agente | Mudança |
|---|---|---|
| 2026-11-12 | A | Revisão 1: contratos Python iniciais. |
| 2026-11-12 | A | `gamekernel/database/db.py`: correção de vazamento de handle na recuperação (bug do Windows encontrado pelo CI). Sem mudança de API. |
| 2026-11-12 | A | Revisão 2: arquitetura híbrida; quarentena passa para A (C++); UI permanece com B em Qt 6 C++ consumindo `cpp/bridge`; `scan_api.py` será substituído pela API C++/IPC. |
