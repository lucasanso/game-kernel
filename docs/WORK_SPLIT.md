# Game Kernel — Divisão do trabalho entre os dois agentes (revisão 4)

> Revisão 4 (2026-11-12): **convergência final** depois de dois merges cruzados. O Agente B alinhou seu
> código à revisão 2 (caminhos `gamekernel/helper`, `reports`, `sandbox`, `intel`, `rules`; testes em
> `tests/helper` e `tests/integration`; envelope IPC do §3 de `INTEGRATION.md`). Esta revisão confirma a
> revisão 2, com uma árvore C++ única em `cpp/` e com o A **adotando** `cpp/ipc` e `cpp/updates`, como o
> próprio B propôs (pendência 1 do `PROGRESS_B.md`). As revisões 1–3 estão no histórico do Git.
>
> Branches: Agente A `claude/magical-bell-fi6jw1` (contém tudo do B até `8e4fb65`) · Agente B
> `claude/stoic-mayer-r46kuo`. **O B deve mesclar a branch do A antes de continuar.**

## 1. Papéis

* **Agente A — Agente 1 (Core e Segurança, C++)**: núcleo de análise e motores, isolamento dos parsers,
  quarentena, tempo real, Performance Monitor, System Optimizer, verificação/instalação de pacotes, cliente
  gk-ipc, camada de serviços Qt (`cpp/bridge`), conteúdo de detecção, segurança de memória.
* **Agente B — Agente 2 (Python, integração e ferramentas)**: processo auxiliar Python e seus serviços
  (relatórios, sandbox), preparação de pacotes e Threat Intelligence, motor de testes de integração, CI do
  produto, empacotamento — e a **interface Qt 6 C++** (`cpp/app`), consumindo apenas `cpp/bridge`.

## 2. Propriedade de arquivos

| Caminho | Dono |
|---|---|
| `cpp/core/`, `cpp/bindings/`, `cpp/worker/`, `cpp/cli/`, `cpp/quarantine/`, `cpp/realtime/`, `cpp/perf/`, `cpp/sysopt/`, `cpp/bridge/` | A |
| `cpp/ipc/`, `cpp/updates/` | A (escritos pelo B; transferidos na rev. 4) |
| `cpp/app/` | B |
| `CMakeLists.txt`, `CMakePresets.json`, `vcpkg.json`, `cmake/`, `.github/workflows/core-ci.yml` | A |
| `contracts/schema.sql`, `contracts/ipc.md` (se criado) | A |
| `contracts/update_package.md`, `contracts/helper_methods.md` | B (A revisa mudanças que afetem o núcleo) |
| Fundação Python (`gamekernel/{app_paths,config,netguard,logging_setup,crypto_utils}.py`, `gamekernel/core/`, `gamekernel/database/`) e `gamekernel/engines/indicators.py` | A |
| `gamekernel/helper/`, `gamekernel/reports/`, `gamekernel/sandbox/`, `gamekernel/intel/`, `gamekernel/rules/`, `gamekernel/updates/`, `gk_helper.py` | B |
| `signatures/yara/`, `signatures/internal/`, `signatures/ioc/`, `signatures/clamav/`, `signatures/data/` | A |
| `signatures/keys/` | B |
| `tools/core_*` | A |
| `tools/` (demais) | B |
| `tests/conftest.py`, `tests/foundation/`, `tests/native/`, `tests/corpus_pe/` | A |
| `tests/helper/`, `tests/integration/`, `tests/corpus/`, `tests/ui/` | B |
| `.github/workflows/ci.yml`, `installer/`, `assets/` | B |
| `requirements.txt` (runtime do auxiliar) | B |
| `requirements-dev.txt`, `pyproject.toml` | A (B pede inclusões) |
| Docs do A: `ARCHITECTURE`, `MODULES`, `MIGRATION_PLAN`, `SECURITY`, `INTEGRATION`, `CORE_API`, `DETECTION_RULES`, `THREAT_COVERAGE`, `WORK_SPLIT`, `PROGRESS_A` | A |
| Docs do B: `README`, `INSTALL`, `USAGE`, `PRIVACY`, `LIMITATIONS`, `OFFLINE_UPDATES`, `PROGRESS_B` | B |
| `docs/BUILD.md`, `docs/TESTING.md`, `CHANGELOG.md` (raiz) | compartilhados por seção ("Núcleo/Agente A" × "Empacotamento, motor de testes/Agente B") |

Observação: os testes do B em `tests/integration/` que compilam `cpp/ipc` e `cpp/updates` continuam com o B
(eles exercitam o código; o dono do código C++ é o A).

## 3. Duplicações e decisões técnicas

| Tema | Decisão |
|---|---|
| Árvore C++ | Única, em `cpp/`. `native/` deixou de existir. |
| Cliente do auxiliar Python | `cpp/ipc` (adotado). O `cpp/bridge` (M13) o usará; não haverá outro. |
| Verificação/instalação de pacotes | `cpp/updates` (adotado). O antigo passo M10 do A passa a ser "integrar `cpp/updates` ao app". |
| Validação de regras YARA em pacotes | Hoje existe em `cpp/updates` (Qt) e em `gk::yara::validate_rules_dir` (`gk_core`). Agora que ambos são do A, o A fará `cpp/updates` delegar ao `gk_core` (mesmas externas, política de `include` e metadados que o motor usa). |
| Validação de bancos ClamAV | `gk::updates::validateClamavDir` (`cpp/updates`). |
| Bindings pybind11 | `gk_native` (A). O passo B6 do B é "usar `gk_native` nos testes". |
| Protocolo entre processos | gk-ipc v1 (`INTEGRATION.md` §3), também para o `gk-scanworker`. `-32602` (parâmetros inválidos) incluído, como o B propôs. Métodos do auxiliar: `contracts/helper_methods.md`. |
| Auditoria de imports "sem rede" | Proíbe **funções** de rede (`socket`, `connect`, `WSAStartup`, `getaddrinfo`, `send`, `recv`, WinHTTP/WinINet…), não a DLL `Ws2_32` inteira: a libyara do vcpkg a importa só por `htonl`/`ntohl` (achado do B). |
| Changelog | Único, na raiz, com seções por agente. |

## 4. Decisões pendentes do usuário

* **P1 — Nome do produto**: "Game Kernel" (título da diretriz e repositório) ou "OFFLINE GAME GUARD"? Mantido
  *Game Kernel* (constante única `gk::kProductName`).
* **P2 — Interface**: os dois agentes propõem **B** (preserva a divisão original). Sem objeção do usuário até agora.

## 5. Regras comuns

* Nada de funções vazias, `TODO`, simulações ou botões sem função no produto.
* Textos para o usuário em pt-BR; identificadores e comentários em inglês.
* Nenhuma rede; nenhum arquivo analisado executado fora da sandbox isolada.
* Amostras perigosas geradas em tempo de teste, nunca commitadas.
* `pytest -q` (e o build CMake) verde antes de cada push; nunca pular testes para ficar verde.
* Antes de trabalhar, mesclar a branch do outro agente; mudanças em arquivos do outro agente só por pedido
  registrado no §6 ou quando a mudança for mecânica e decorrente de uma decisão deste documento.

## 6. Registro de mudanças de contrato

| Data | Agente | Mudança |
|---|---|---|
| 2026-11-12 | A | Rev. 4: `native/` → `cpp/`; A adota `cpp/ipc` e `cpp/updates`; ajustes mecânicos de caminho em `tests/integration/conftest.py`, `tests/integration/test_cpp_helper_client.py`, `gamekernel/helper/client.py` e `gamekernel/updates/package.py` (só textos/caminhos). |
| 2026-11-12 | A | `INTEGRATION.md` §3: código `-32602`; métodos do auxiliar em `contracts/helper_methods.md`. |
| 2026-11-12 | A | `gamekernel/database/db.py`: correção de vazamento de handle na recuperação (Windows). Sem mudança de API. |
| 2026-11-12 | A | Rev. 3 (substituída pela rev. 4). |
| 2026-11-12 | A | Rev. 2: arquitetura híbrida. |
| 2026-11-12 | A | Rev. 1: contratos Python iniciais. |
