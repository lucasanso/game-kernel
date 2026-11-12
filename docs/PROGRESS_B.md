# Progresso — Agente B (Agente 2: Python, integração e ferramentas)

Branch: `claude/stoic-mayer-r46kuo`. Divisão vigente: **`docs/WORK_SPLIT.md` rev. 4** (convergência final: layout da
rev. 2 e árvore C++ única em `cpp/`). Esta branch contém a branch do A até `5c234c8` (M7).

## Estado atual (2026-11-12)

* `pytest -q` na árvore mesclada, com o `gk_native` do A compilado (`cmake --preset linux-debug`):
  **373 passed, 12 failed, 7 skipped**.
  * Os 12 que falham são `tests/native/test_risk.py` (Agente A, M7): o arquivo `signatures/data/game_components.json`
    nunca chegou ao repositório porque a regra `data/` do `.gitignore` também ignora `signatures/data/`. A CI do
    próprio A (`core-ci`, execução 43322196479) falha da mesma forma. Ver pendência 3.
  * Os pulados: 5 testes de corpus PE e 1 de análise (sem mingw-w64 neste ambiente), 1 que usa DLLs do Windows e o
    teste do auxiliar congelado, que roda na CI.
* Suítes do B: `tests/helper` + `tests/integration` + `tests/ui` → **207 passed, 1 skipped**; com ASan/UBSan
  (`GK_NATIVE_SANITIZE=1`) → **206 passed** + interface **1 passed** (com `detect_leaks=0`, por causa das alocações
  globais do Qt).
* CI do produto (`.github/workflows/ci.yml`) depois da mesclagem da rev. 4 (`9e42cd9`, execução 43325532416):
  **Linux verde e Windows verde**. No Windows: 235 passed, inclusive a interface `cpp/app` compilada com MSVC,
  `windeployqt` e plugin `offscreen`, e o ícone e o `VERSIONINFO` lidos do `GameKernel.exe`; o `gk-helper.exe`
  congelado (a partir de `gamekernel/helper/entry.py`) passou no teste de fumaça, e o artefato
  `gamekernel-windows-componentes` foi publicado. Os testes do A aparecem como pulados nessa CI porque ela não
  compila o `gk_native` (pendência 6).

| Etapa | Entrega | Estado |
|---|---|---|
| B1 | Auditoria, classificação e plano | ✅ |
| B2 | Processo auxiliar Python, cliente Python e cliente C++/Qt (`cpp/ipc`, hoje do A) | ✅ |
| B3 | Relatórios forenses (JSON, HTML, PDF) no auxiliar | ✅ |
| B4 | Atualização offline: `.gkpkg`, preparação Python, verificação e instalação C++ (`cpp/updates`, hoje do A) | ✅ |
| B5 | Threat Intelligence (IOC, YARA, relatório de atualização) | ✅ |
| B6 | Usar `gk_native` (A) nos testes de integração | em andamento conforme o A amplia a API |
| B7 | Sandbox (Windows Sandbox sem rede) no auxiliar | ✅ (sem VM no Linux; `monitor.ps1` com sintaxe verificada na CI Windows) |
| B8 | CI Linux + Windows/MSVC, auxiliar congelado | ✅ |
| B9 | Interface Qt 6 C++ (`cpp/app`) | 🔄 parte 1 ✅ (esqueleto + 3 páginas com serviços reais); páginas do núcleo aguardam `cpp/bridge` (A, M13) |
| B10 | Instalador (Inno Setup), versão portátil, docs de usuário (INSTALL, USAGE) | ⏳ depende do executável da interface e dos binários do núcleo |

## Mesclagem da rev. 4 (esta etapa)

Os dois agentes cruzaram merges: o A escreveu a rev. 4 a partir do meu alinhamento à rev. 2 (`8e4fb65`), enquanto eu
tinha voltado ao layout da rev. 3. Para convergir sem novo vaivém, **adotei a árvore do A inteira** e reapliquei
nela só o que o A ainda não tinha:

* `native/app` → **`cpp/app`** (interface, sem mudança de comportamento; comentários e CMake com os novos caminhos);
* `system.network_selftest` em `gamekernel/helper/server.py` e o teste em `tests/helper/test_helper_process.py`;
* `tests/ui/test_native_app.py` (agora usa `tests/integration/native_build.py` e `cpp/app`);
* `native_build.py`: plugin `offscreen` no Windows e **recriação automática de *builds* configurados a partir de
  outra origem** (sem isso, quem tinha `build/native-*` apontando para `native/` via um erro do CMake);
* `libqt6svg6-dev` na CI Linux;
* documentos do B (README, BUILD/TESTING, CHANGELOG da raiz, `contracts/*`).

Comparei arquivo por arquivo os módulos Python, ferramentas, testes, CI e spec do PyInstaller entre as duas árvores:
fora o B9, as diferenças eram só de caminho e de envelope. **Nenhuma funcionalidade se perdeu.**

Ajuste decorrente da rev. 4: o §3 do `INTEGRATION.md` passou a ter `-32602` (parâmetros inválidos), como eu tinha
proposto. O auxiliar Python agora responde `invalid_params` com `-32602`. No `cpp/ipc` (do A desde a rev. 4) fiz o
ajuste mecânico correspondente (`error_code::InvalidParams`, mapeamento e o teste em `tst_ipc.cpp`), permitido pelo
§5 da `WORK_SPLIT.md` por decorrer de uma decisão do documento. `contracts/helper_methods.md` foi atualizado.

## Decisões de linguagem (B1)

| Componente | Linguagem | Justificativa |
|---|---|---|
| Relatórios | **Python** no processo auxiliar | reportlab é maduro para PDF; a lógica muda com frequência; fora do caminho crítico; isolado por processo |
| Sandbox | **Python** no auxiliar + PowerShell na VM | orquestração longa e bloqueante, leitura de dados escritos dentro da VM; isolada do app |
| Preparação de pacotes, IOC, YARA | **Python** | automação de publicador, fora do app (diretriz §3) |
| Verificação e instalação de pacotes | **C++** (`cpp/updates`) | diretriz: controles de segurança no núcleo C++ |
| Cliente do auxiliar | **C++/Qt** (`cpp/ipc`) | o app é C++; o `cpp/bridge` do A vai usá-lo |
| Interface | **C++/Qt 6 Widgets** (`cpp/app`) | diretriz: aplicativo desktop nativo, sem interface web |
| Python embutido no processo do app | **rejeitado** | uma falha do Python derrubaria a interface |

## Entregas (detalhes em `docs/INTEGRATION.md`, `contracts/helper_methods.md`, `docs/OFFLINE_UPDATES.md`, `contracts/update_package.md`)

* **Processo auxiliar** (`gamekernel/helper/`): envelope do §3 com extensões opcionais (cancelamento, prazo, id em
  eventos, `error.data.reason`), *thread* de leitura e de trabalho, proteção de stdio, ponte de logs, `netguard`
  instalado antes de qualquer *import*; cliente Python. Exceção num serviço → `1099`, e o auxiliar continua.
* **Cliente C++/Qt** (`cpp/ipc`, escrito pelo B): QProcess, Job Object no Windows (`KILL_ON_JOB_CLOSE`, limite de
  memória, restrições de UI; atribuído na criação), `RLIMIT_AS`/`PDEATHSIG` no Linux, prazo → cancelamento → morte
  após carência, reinício limitado.
* **Relatórios** (`gamekernel/reports/`): 15 seções, relatório por crack, redação de dados pessoais, HTML sem
  JavaScript (CSP `default-src 'none'`), PDF com fonte Unicode, banco somente leitura.
* **Atualização offline**: `.gkpkg` sem ZIP (verificação em passagem única, sem TOCTOU), Ed25519, YARA compilado
  antes de ativar, CVD conferido, instalador atômico com reversão e recuperação após queda de energia, CLI
  `gk-update`; equivalência Python × C++, inclusive com 60 mutações aleatórias.
* **TI** (`gamekernel/intel/`, `gamekernel/rules/`, `gamekernel/updates/prepare.py`): IOC (normalização, deduplicação,
  conflitos), *lint* e compilação de YARA, bloqueio antes de assinar (também com os validadores C++) e relatório de
  atualização; ferramentas em `tools/`.
* **Sandbox** (`gamekernel/sandbox/`): `.wsb` sem rede e com entrada somente leitura, recusa sem isolamento real,
  `monitor.ps1` (iscas com SACL, auditoria por GUID, árvore de processos), evidências comportamentais.
* **CI** (`.github/workflows/ci.yml`) e PyInstaller do auxiliar (`installer/gk_helper.spec`).

## B9 — Interface Qt 6 C++, parte 1 (`cpp/app`)

Só entram páginas com serviço real por trás. As do núcleo (Painel, Scanner, Resultados, Quarentena, Histórico,
Tempo real, Desempenho e Otimizador) chegam quando o `cpp/bridge` do A existir, sem telas ou botões sem função.

* **Esqueleto**: janela com o ícone do produto (escudo + "chip", SVG próprio), menu lateral, cabeçalho por página,
  notificações internas (com histórico na sessão), indicador "100% offline" e instância única (trava em
  `<dados>/.app.lock`). Tema escuro: fundo grafite, destaques em azul e verde, risco em amarelo, laranja e vermelho.
* **Central de Atualização Offline** (`cpp/updates`): conjunto ativo e aviso de desatualização (data do pacote e
  `updates.stale_after_days`), importação em *thread* de trabalho (verificar → mostrar publicador, versão, chave e
  componentes → confirmar → instalar), *downgrade* só com confirmação explícita, reversão, histórico, chaves
  confiáveis (adicionar mostrando o identificador; as embutidas não podem ser removidas pela interface).
* **Análise comportamental** (`sandbox.*`): disponibilidade com o motivo, ativação gravada em `settings.json`,
  amostra, tempo de observação, confirmação com as limitações, progresso, cancelamento, evidências. Sem isolamento
  real, o botão fica desabilitado e explica por quê.
* **Privacidade e rede** (`system.info`, `system.network_selftest`): estado do auxiliar e do `netguard`, reinício
  do auxiliar, autoteste que tenta DNS e conexão de saída de verdade e comprova o bloqueio, tentativas bloqueadas.
* `AppContext`: mesmas regras de caminho do `app_paths.py` (portátil, `GAMEKERNEL_DATA_DIR`), escrita atômica do
  `settings.json` preservando as demais chaves, confirmações injetáveis para testes.
* **Ícone e versão do executável**: o logotipo tem fonte única (`assets/gamekernel.svg`, recurso Qt);
  `assets/gamekernel.ico` (9 tamanhos, entradas PNG) sai de `tools/make_app_icon.py`; no Windows, recurso com
  ícone e `VERSIONINFO`, com a versão do `project()` do CMake (a mesma exibida na interface).

Transitório, até o M13: a interface usa `cpp/ipc` e `cpp/updates` diretamente. A rev. 4 diz que a interface consome
só o `cpp/bridge`; quando ele existir, troco essas chamadas pelas do *bridge* sem mudar as páginas.

Testes: `tests/ui/test_native_app.py` → `cpp/app/tests/tst_app.cpp` (11 casos), com pacotes reais e o auxiliar
real, e capturas das três páginas em `build/native-app/screenshots/`; `tests/ui/test_app_resources.py`: `.ico`
válido e em dia com o SVG e, no Windows, ícone e `VERSIONINFO` lidos do `GameKernel.exe` com pefile.

## Pendências

1. **P1 — Nome do produto** (usuário): "Game Kernel" ou "OFFLINE GAME GUARD". Mantido *Game Kernel*.
2. **P2 — Interface com o B** (usuário): proposta dos dois agentes, sem objeção até agora.
3. **Para o A — `signatures/data/game_components.json` fora do repositório**: a linha `data/` do `.gitignore`
   (provavelmente para a pasta de dados do modo portátil) também casa com `signatures/data/`. Sugestão: trocar por
   `/data/` e commitar o arquivo. Até lá, `tests/native/test_risk.py` falha em qualquer clone novo.
4. **Para o A — `core-ci` Windows**: o pytest termina com `-1073741819` (`0xC0000005`, violação de acesso) depois dos
   resultados, possivelmente na finalização do `gk_native`.
5. **Para o A — `add_subdirectory(cpp/app)`** no `CMakeLists.txt` da raiz quando Qt 6 Widgets e Svg estiverem
   disponíveis. O app já compila sozinho (`cmake -S cpp/app`).
6. **Para o A — `gk_native` na CI do produto**: a `ci.yml` não compila o `gk_native`, então os testes do A aparecem
   como pulados nela (a `core-ci` os cobre). Se o A preferir uma CI única, incluo o *preset* do núcleo na `ci.yml`.
7. **`signatures/keys/`** (B): a chave pública de *release* é copiada no *build*; a privada nunca é versionada.
