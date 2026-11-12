# Progresso — Agente B (Agente 2: Python, integração e ferramentas)

Branch: `claude/stoic-mayer-r46kuo`. Divisão vigente: **`docs/WORK_SPLIT.md` rev. 3** (reconciliação feita pelo
Agente A depois de integrar as duas branches). Esta branch já contém a branch do A até `2b36822`.

## Estado atual

* Árvore conciliada (núcleo do A com PE, YARA e compactados + componentes do B), `gk_native` compilado:
  `pytest -q` → **332 passed, 6 skipped**. Os pulados são 5 testes do corpus PE do A (sem mingw-w64 neste
  ambiente) e o teste do auxiliar congelado, que roda na CI.
* Suítes do B com ASan/UBSan (`GK_NATIVE_SANITIZE=1`): **189 passed**.
* CI do produto (`.github/workflows/ci.yml`), última execução antes desta conciliação (`a7e2a66`): **Linux verde**;
  **Windows com todos os testes do B verdes** (226 passed). A única falha era o teste da fundação
  `test_corrupt_database_is_recovered`, que o A já corrigiu (`db.py`). O `gk-helper.exe` congelado gerou JSON,
  HTML e PDF, e o artefato `gamekernel-windows-componentes` foi publicado.

| Etapa | Entrega | Estado |
|---|---|---|
| B1 | Auditoria, classificação e plano | ✅ |
| B2 | gk-ipc v1: auxiliar Python, cliente Python, cliente C++/Qt (`native/ipc`) | ✅ (protocolo único, também para o `gk-scanworker` do A) |
| B3 | Relatórios forenses (JSON, HTML, PDF) no auxiliar | ✅ |
| B4 | Atualização offline: `.gkpkg`, preparação Python, verificação e instalação C++ (`native/updates`) | ✅ (implementação única; o "M10" do A foi cancelado) |
| B5 | Threat Intelligence (IOC, YARA, relatório de atualização) | ✅ |
| B6 | Usar `gk_native` (A) no motor de testes | em andamento conforme o A amplia a API |
| B7 | Sandbox (Windows Sandbox sem rede) no auxiliar | ✅ (sem VM no Linux; `monitor.ps1` com sintaxe verificada na CI Windows) |
| B8 | CI Linux + Windows/MSVC, auxiliar congelado | ✅ |
| B9 | Interface Qt 6 C++ (`native/app`, pendência P2) | ⏳ próxima; consome `native/bridge` (A) |
| B10 | Instalador (Inno Setup), versão portátil, docs de usuário (INSTALL, USAGE) | ⏳ depende do executável da interface |

## Decisões de linguagem (B1)

| Componente | Linguagem | Justificativa |
|---|---|---|
| Relatórios | **Python** no processo auxiliar | reportlab é maduro para PDF; a lógica muda com frequência; fora do caminho crítico; isolado por processo |
| Sandbox | **Python** no auxiliar + PowerShell na VM | orquestração longa e bloqueante, leitura de dados escritos dentro da VM; isolada do app |
| Preparação de pacotes, IOC, YARA | **Python** | automação de publicador, fora do app (diretriz §3) |
| Verificação e instalação de pacotes | **C++** (`native/updates`) | diretriz: controles de segurança no núcleo C++ |
| Cliente do auxiliar / protocolo entre processos | **C++/Qt** (`native/ipc`) | o app é C++; o mesmo protocolo serve o `gk-scanworker` do A |
| Python embutido no processo do app | **rejeitado** | uma falha do Python derrubaria a interface |

## Entregas (resumo; detalhes em `docs/INTEGRATION.md`, `docs/OFFLINE_UPDATES.md`, `contracts/update_package.md`)

* **gk-ipc v1** (`gamekernel/ipc/`, `gk_helper.py`, `native/ipc/`): quadros uint32 + JSON (≤ 8 MiB), códigos de erro
  estáveis, cancelamento, prazos, proteção de stdio, ponte de logs, reinício limitado, Job Object no Windows
  (`KILL_ON_JOB_CLOSE`, limite de memória, restrições de UI; atribuído na criação) e `RLIMIT_AS`/`PDEATHSIG` no Linux.
* **Relatórios** (`gamekernel/core/report_*.py`, `sysinfo.py`): 15 seções, relatório por crack, redação de dados
  pessoais, HTML sem JavaScript (CSP `default-src 'none'`), banco somente leitura.
* **Atualização offline**: `.gkpkg` sem ZIP (verificação em passagem única, sem TOCTOU), Ed25519 (libsodium), YARA
  compilado antes de ativar, CVD conferido, instalador atômico com rollback e recuperação após queda de energia,
  CLI `gk-update`; equivalência Python × C++ inclusive com 60 mutações aleatórias.
* **TI** (`gamekernel/ti/`): IOC (normalização, deduplicação, conflitos), *lint* e compilação de YARA, bloqueio antes de
  assinar (inclusive com os validadores C++) e relatório de atualização; ferramentas em `tools/`.
* **Sandbox** (`gamekernel/engines/sandbox_manager.py`, `sandbox/monitor.ps1`).
* **CI** (`.github/workflows/ci.yml`) e PyInstaller do auxiliar (`installer/gk_helper.spec`).

## Conciliação com a rev. 3 (esta etapa)

* Mesclei a branch do A (`2b36822`, com o núcleo em `native/core`). A rev. 3 **mantém o meu layout original e o
  protocolo gk-ipc v1**. Por isso desfiz o realinhamento provisório que eu tinha feito para a rev. 2 (mudança de
  pastas e do envelope IPC) e reapliquei, nos caminhos da rev. 3, tudo que fiz depois do B7:
  correções do Windows (libyara do vcpkg com dependências, `windeployqt`, UTF-8, vcpkg em modo clássico, cache),
  teste C++ de limite de memória também no Windows, verificação da sintaxe do `monitor.ps1`, `README.md`,
  `docs/PRIVACY.md`, `docs/LIMITATIONS.md`, `contracts/update_package.md` e as seções do B em `BUILD.md`/`TESTING.md`.
* `docs/INTEGRATION.md` agora documenta os métodos `sandbox.*` e registra que o gk-ipc v1 é o único protocolo
  entre processos.

## Pendências

1. **P1 — Nome do produto** (usuário): "Game Kernel" ou "OFFLINE GAME GUARD". Mantido *Game Kernel*.
2. **P2 — Interface Qt 6 C++** (usuário): proposta dos dois agentes, com o B como dono, consumindo `native/bridge`.
3. **Validador YARA duplicado** (rev. 3 §4): `gk::updates::validateYaraDir` deve delegar ao `gk::yara::validate_rules_dir`
   do núcleo quando `native/updates` passar a ligar `gk_core`. Execução: B.
4. **Para o A — nome do pacote CMake da libyara no vcpkg**: o *port* `yara` exporta `unofficial-libyara` com o alvo
   `unofficial::libyara::libyara` (não `unofficial-yara`/`unofficial::yara::libyara`). Esse alvo já traz
   OpenSSL::Crypto, Crypt32 e **Ws2_32**. Hoje o `cmake/GkDependencies.cmake` cai no `find_library` e não liga o Ws2_32.
5. **Para o A — auditoria de imports de rede**: a libyara importa `Ws2_32` (funções de ordem de bytes, `htonl`/`ntohl`).
   Sugestão: a auditoria proíbe as funções de rede (`socket`, `connect`, `WSAStartup`, `getaddrinfo`, `send`/`recv`…),
   não a DLL inteira.
6. **`signatures/keys/`** (B pela rev. 3): a chave pública de *release* é copiada no *build*; a privada nunca é versionada.
