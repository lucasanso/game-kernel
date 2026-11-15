# Progresso — Agente B (Agente 2: Python, integração e ferramentas)

Branch: `claude/stoic-mayer-r46kuo`. Divisão vigente: **`docs/WORK_SPLIT.md` rev. 4** (convergência final: layout da
rev. 2 e árvore C++ única em `cpp/`). Esta branch contém a branch do A até `398a4d1` (M8 varredura, M4 Authenticode,
M9 quarentena, M10 integridade da instalação, *hardening* do `gk-scanworker`, libyara sem OpenSSL e as anotações de
passagem para o B).

## Estado atual (2026-11-14)

* `pytest -q` na árvore mesclada, com o `gk_native`, o `gk-cli` e o `gk-scanworker` do A compilados
  (`cmake --preset linux-debug`): **525 passed, 39 skipped, nenhuma falha**. Os pulados dependem de plataforma ou de
  ferramenta ausente aqui: WinVerifyTrust e DLLs do Windows, mingw-w64 e osslsigncode (corpus PE e amostras
  assinadas), recursos PE do `GameKernel.exe` e o auxiliar congelado, que rodam na CI Windows.
* Suítes do B com ASan/UBSan (`GK_NATIVE_SANITIZE=1`): `tests/helper` + `tests/integration` → **211 passed**.
* O A resolveu as duas falhas que eu tinha apontado: `signatures/data/game_components.json` (regra `/data/` no
  `.gitignore`) e a violação de acesso do `gk_native` na saída do interpretador no Windows.
* Mesclagem desta etapa: o A alterou `gamekernel/reports/render_html.py` e `render_pdf.py` (do B) para o novo estado de
  assinatura "presente, não verificada" (assinatura em compactado ou cadeia impossível de montar *offline*); a
  mudança está correta e ganhou teste do B (`test_signature_status_wording`). O `signify` saiu do
  `requirements.txt` porque o Authenticode agora é verificado em C++.
* Novo teste do B: `tests/ui/test_app_offline_imports.py` estende a auditoria de rede do A ao `GameKernel(.exe)` e,
  no Windows, às DLLs que o `windeployqt` coloca ao lado dele (o que o instalador vai levar).
* CI do produto (`.github/workflows/ci.yml`) depois da mesclagem da rev. 4 (`9e42cd9`, execução 43325532416):
  **Linux verde e Windows verde**. No Windows: 235 passed, inclusive a interface `cpp/app` compilada com MSVC,
  `windeployqt` e plugin `offscreen`, e o ícone e o `VERSIONINFO` lidos do `GameKernel.exe`; o `gk-helper.exe`
  congelado (a partir de `gamekernel/helper/entry.py`) passou no teste de fumaça, e o artefato
  `gamekernel-windows-componentes` foi publicado. Os testes do A aparecem como pulados nessa CI porque ela não
  compila o `gk_native` (pendência 4).

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
| B9 | Interface Qt 6 C++ (`cpp/app`) | 🔄 10 páginas com serviços reais (Painel, Segurança do jogo, Análise forense, Histórico, Quarentena, Atualização offline, Análise comportamental, Relatórios, Privacidade e rede, Configurações); Tempo real, Desempenho e Otimizador entram com M11 e M12 |
| B10 | Instalador (Inno Setup), versão portátil, docs de usuário (INSTALL, USAGE) | ✅ validado na CI Windows (`c0af4d5`, execução 43656278389): produto compilado com MSVC, instalador gerado, instalação silenciosa, 17 testes do produto instalado e 17 do portátil sem pulos, desinstalação preservando os dados |

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

## B10 — Distribuição

* `tools/make_distribution.py`: pasta do produto (interface + `windeployqt`, `gk-cli`, `gk-scanworker`, `gk-update`,
  `gk-helper` congelado, assinaturas, `contracts/threat_catalog.json`, runtime MSVC local, guias), o **manifesto de
  integridade assinado do núcleo** (M10 do A, gerado com o código do A como último passo, chave pública em
  `signatures/keys/release.pub`) e o ZIP portátil com `portable.flag`. Recusa chave privada, DLL de rede, DLLs homônimas diferentes, `portable.flag`
  na pasta instalada e apagar uma pasta de saída que não seja uma distribuição anterior.
* `installer/gamekernel.iss`: Inno Setup em pt-BR, instalação por máquina ou por usuário, sem rede, ícone e versão
  únicos; a desinstalação **não apaga** `%LOCALAPPDATA%\GameKernel` (quarentena) e avisa onde os dados ficaram.
* CI `windows-package`: compila o produto inteiro (núcleo pelo *preset* do A, agora com Qt, e a interface com as
  mesmas dependências estáticas), monta, gera o instalador, instala em silêncio, testa o produto instalado, desinstala
  (conferindo que os dados ficam) e testa a versão portátil extraída.
* `tests/integration/test_distribution.py`: regras de montagem em qualquer plataforma; com `GK_INSTALLED_DIR`,
  testes de ponta a ponta do produto instalado (`gk-cli integrity` confirma a instalação e a assinatura, *imports*
  de rede de todos os binários, EICAR achado pelo `gk-cli` instalado sem aviso de integridade, relatório pelo
  `gk-helper` instalado a partir do mesmo banco). Ensaio local no Linux com os
  binários reais: pasta montada e ZIP portátil extraído passam nos testes de ponta a ponta.
* `docs/INSTALL.md` e `docs/USAGE.md` descrevem só o que existe (varredura e quarentena pela linha de comando até a
  interface ganhar essas páginas).

Achados da CI Windows no empacotamento, corrigidos: o `windeployqt` implantava o `Qt6Network.dll` por causa dos
plugins "generic" do Qt (toque TUIO por UDP), que o programa não usa — agora `--skip-plugin-types generic`, e a
montagem recusa qualquer DLL de rede; o `Qt6Core.dll` importa `WSAStartup`/`WSACleanup`/`WSAAsyncSelect` para o
laço de eventos (sem resolver nomes nem conectar): exceção estreita e testada na auditoria, documentada em
`docs/PRIVACY.md`.

Defeitos encontrados e corrigidos pelo caminho (todos do B): o `gk-helper.exe` congelado não tinha os métodos
`sandbox.*` nem o `monitor.ps1`, e o `system.info` não mostrava serviços que falharam ao carregar (agora mostra
`unavailable_services`); a distribuição não levava o `contracts/threat_catalog.json`.

## Tarefas do A assumidas pelo B (pedido do usuário, 2026-11-15)

Com o A indisponível, o usuário pediu ao B que assumisse as tarefas dele (registrado na `WORK_SPLIT.md` §6).

* **Motor de risco à prova de falha** (`cpp/scan/src/scanner.cpp`): se o motor de risco não carrega (ex.: catálogo
  ausente), todo arquivo com evidências vira `inconclusive`, com o maior risco das evidências e sem atenuação, situação
  `partial` com o motivo, e a limitação entra no resumo. Antes, um EICAR saía "desconhecido, sem risco".
  Teste: `tests/native/test_scan_cli.py::test_risk_engine_failure_never_hides_evidence`.
* **`gk-cli` portátil** (`cpp/cli/main.cpp`): respeita o `portable.flag`, com as mesmas regras do `app_paths.py` e
  da interface. Teste: `test_portable_copy_keeps_its_data_next_to_the_program`.
* **Interface na raiz do CMake**: `add_subdirectory(cpp/app)` quando há Qt Widgets/Svg; compilada pela raiz, a
  interface recebe o mesmo endurecimento e os mesmos avisos do núcleo (`gk_apply_options`). Corrigidos os avisos
  `-Wshadow` que isso revelou. A CI do instalador passa a tirar o `GameKernel.exe` desse mesmo build.

### M13 — `cpp/bridge` (serviços Qt para a interface)

* `gk::bridge::ScanService`: o `Scanner` do núcleo numa *thread* própria; `start`/`pause`/`resume`/`cancel`, sinais
  de progresso, resultado por arquivo e resumo (uma varredura por vez).
* `HistoryService`: varreduras e resultados lidos do SQLite em segundo plano, por uma conexão **somente leitura**
  nova no núcleo (`Database::open_readonly`, `list_scans`, `scan`, `file_results`); instalação nova sem banco dá
  listas vazias e não cria o banco.
* `QuarantineService`: cofre criptografado + banco + auditoria (`gk::quarantine::Manager`), uma operação por vez em
  segundo plano: colocar (com SHA-256 esperado), listar, restaurar, apagar, verificar. `gk::db::to_json` dos itens
  da quarentena passou para o núcleo (o `gk-cli` usa o mesmo).
* `IntegrityService`: `gk::integrity::Verifier` em segundo plano, mesmo relatório do `gk-cli integrity`.
* A interface passa a ser compilada só pela raiz do repositório (usa o *bridge*); os testes compilam a raiz em
  `build/native-root`. A CI instala as dependências do núcleo nos jobs de teste (Linux e Windows, vcpkg clássico com
  a libyara do *overlay*).
* Testes: `tests/integration/test_cpp_bridge.py` → `cpp/bridge/tests/tst_bridge.cpp` contra o núcleo real
  (varredura com *workers* isolados e EICAR gerado no teste, histórico, pausa/cancelamento, quarentena completa,
  instalação nova, integridade), também sob ASan/UBSan. Achado: sob ASan o `gk-scanworker` não iniciava por causa do
  limite `RLIMIT_AS` (o ASan reserva terabytes de endereços); nas builds com sanitizador o limite é desligado.

### Páginas do núcleo na interface (sobre o `cpp/bridge`)

* **Painel**, **Segurança do jogo**, **Análise forense**, **Histórico** e **Quarentena**, todas pelos serviços do
  `cpp/bridge` (a interface não chama o `gk_core` diretamente). Rótulos e explicações vêm do catálogo de ameaças da
  instalação (`gk::bridge::Catalog`), os mesmos textos do motor de risco e dos relatórios.
* Testes (`tst_app.cpp`, pelo pytest, também sob ASan/UBSan): varredura real com EICAR gerado no teste, histórico,
  painel (incluindo integridade "Sem manifesto" no desenvolvimento), análise com explicação e evidências, filtro,
  quarentena recusada e confirmada, restauração conferida byte a byte, verificação do cofre; janela com 10 páginas e
  capturas de todas em `build/screenshots/`.
* Corrigido pelo caminho: corrida em que o "carregar a última varredura" do início sobrescrevia uma varredura pedida
  explicitamente; no Windows, programas de uma árvore de build do Visual Studio (`cpp/<x>/Release/`) não achavam o
  `gk-scanworker`.

### M11 — proteção em tempo real (`cpp/realtime`)

* **Observador** (`gk::realtime::DirectoryWatcher`): Windows — `ReadDirectoryChangesW` com E/S sobreposta, subárvore
  inteira, uma *thread* para até 63 pastas, nomes curtos 8.3 convertidos, *buffer* estourado → pedido de nova
  verificação da pasta (`overflow`), pasta removida/inacessível → `failed` com o motivo do sistema. Linux (só
  desenvolvimento e CI) — inotify com uma *watch* por pasta, subpastas novas acompanhadas. Pastas inexistentes são
  recusadas com o motivo; pastas dentro de outra pedida não são observadas duas vezes.
* **Lotes** (`ChangeBatcher`, lógica pura com relógio e sonda injetados): só sai o arquivo que parou de mudar (sem
  evento por `stable_seconds`, duas sondagens iguais de tamanho e data, e abrível para leitura; o que nunca assenta
  sai após 2 min, marcado como "ainda em gravação"); alterações juntadas por `batch_seconds`; removidos e renomeados
  descartados (downloads `.part` → nome final); pasta só entra quando aparece (movida/copiada), nunca porque o conteúdo
  mudou; exclusões (pasta de dados do programa, `scan.excluded_paths`); muitas alterações → nova verificação das
  pastas observadas (o cache da varredura torna barato).
* **Monitor**: varredura no modo rápido com o `gk_scan` (origem `realtime`, sem ClamAV nos lotes), eventos em
  `realtime_events` (mesma tabela do `db.py`), aviso a partir de `notify_min_risk`, quarentena automática opcional só
  para ameaças confirmadas por assinatura — a regra foi extraída do motor de risco (`gk::risk::evidence_verdict`,
  `confirmed_by_signature`) para não haver duas — com o SHA-256 analisado conferido, e nunca para um arquivo que o
  usuário restaurou.
* **Interface**: `RealtimeService` (monitor numa *thread* própria), página **Tempo real** (pastas com estado real,
  nível de aviso, quarentena automática com confirmação, tempos, eventos com "Ver análise"), bloco no Painel, ícone na
  área de notificação com menu (fechar a janela mantém a proteção quando ela está ativa), avisos na janela e na área de
  notificação, Histórico sem os lotes automáticos por padrão (opção para incluir). As chaves são as `realtime.*` do
  `config.py`, aplicadas na hora.
* Testes: `tests/integration/test_cpp_realtime.py` → `tst_realtime.cpp` (12 casos: regras de lote, observador real,
  monitor de ponta a ponta com EICAR gerado no teste, quarentena automática e restauração, pasta de dados ignorada,
  pasta inexistente), `tst_bridge.cpp` (serviço) e `tst_app.cpp` (página e janela, captura `06-tempo-real.png`);
  limpos sob ASan/UBSan com detecção de vazamentos.
* Achado pelo caminho: o temporizador de progresso do `Scanner` era `static` (compartilhado entre a varredura manual
  e a do tempo real, em *threads* diferentes); passou a ser por instância.

### M12 — Performance Monitor e System Optimizer (`cpp/perf`, `cpp/sysopt`)

* **Monitor** (`gk::perf::Sampler`): Windows — CPU por `GetSystemTimes`; memória por `GlobalMemoryStatusEx`; disco
  e GPU por contadores PDH adicionados com `PdhAddEnglishCounterW` (`PhysicalDisk(_Total)`, `GPU Engine(*)\Utilization
  Percentage` somado por tipo de mecanismo — a GPU vale o tipo mais ocupado, como o Gerenciador de Tarefas —, `GPU
  Adapter Memory(*)\Dedicated/Shared Usage`); placas e memória de vídeo total pelo DXGI (adaptadores de software
  ignorados, casados com os contadores pelo LUID); processos por Toolhelp + `GetProcessTimes`/`GetProcessMemoryInfo`
  (os protegidos são contados como "não medidos"). Linux (desenvolvimento): `/proc` e `/sys/block`; GPU declarada
  indisponível. Taxas vêm da diferença entre duas amostras.
* **Otimizador** (`gk::sysopt`): diagnóstico só de leitura (registro, `PowerGetActiveScheme`, `GetSystemPowerStatus`,
  `QStorageInfo`), cada item com valor e, quando pede atenção, onde ajustar no Windows; nenhuma configuração do sistema
  é alterada. Limpeza de temporários em duas etapas: `analyzeTemp` (arquivos com mais de 24 h em `%TEMP%` e
  `<dados>/temp`, sem seguir links/junções, raízes inseguras recusadas) e `cleanTemp` (apaga só o listado e ainda
  igual em tamanho e data, e ainda dentro da pasta — uma pasta trocada por link entre as etapas é detectada; pastas
  antigas que ficam vazias são removidas). Fora do Windows, o `/tmp` compartilhado não é tocado.
* **Interface**: `PerformanceService` (amostras numa *thread* própria só enquanto a página Desempenho está na tela),
  `OptimizerService` (diagnóstico e limpeza em segundo plano; plano usado uma vez; auditoria
  `optimizer.temp_clean`); páginas **Desempenho** (blocos com o último minuto em gráfico, processos por processador,
  memória ou placa de vídeo, consumo do próprio programa) e **Otimizador** (diagnóstico, analisar → confirmar →
  limpar). Menu com 13 páginas.
* Testes: `tests/integration/test_cpp_perf.py` → `tst_perf.cpp` (uma *thread* ocupada tem de aparecer no consumo
  deste processo; GPU e disco medidos ou explicados) e `tst_sysopt.cpp` (diagnóstico; limpeza com arquivos antigos,
  recentes, alterados depois da análise, em uso no Windows, links e pasta trocada por link apontando para dados do
  usuário); casos no `tst_bridge.cpp` e no `tst_app.cpp` (capturas `07-desempenho.png` e `08-otimizador.png`); limpos
  sob ASan/UBSan.

## B9 — páginas que não dependem do A (2026-11-15)

* **Relatórios forenses**: lista as varreduras do banco pelo novo método `reports.scans` do auxiliar (somente
  leitura; o banco nunca é criado), gera HTML/JSON/PDF com as opções de privacidade e lista os relatórios gerados.
  Hoje as varreduras vêm do `gk-cli`; as da interface entram pelo mesmo banco quando houver `cpp/bridge`.
* **Configurações**: só chaves que algum componente lê hoje (o núcleo C++ ainda não lê o `settings.json`, então
  opções de varredura, motores, tempo real e quarentena ficam fora para não haver controle sem efeito). Validação
  com as faixas do `config.py`, escrita atômica preservando as demais chaves, propagação para as outras páginas
  (`AppContext::settingChanged`) e leitura confirmada pelo auxiliar Python.
* `scrollingPage`/`mutedLabel` foram para o `ui_kit` (estavam duplicados).

## Resposta às anotações de passagem do A (`WORK_SPLIT.md` §6, `398a4d1`)

| Anotação do A | O que o B fez |
|---|---|
| Relatórios: helper `_signature()` com "presente, não verificada" | Aceito; coberto por `test_signature_status_wording` |
| Dependências: sai `signify`, entra `asn1crypto` (oráculo) | Aceito |
| CI Windows: libyara do *overlay* `vcpkg/overlay-ports/yara` | `ci.yml` (job `windows`) instala a libyara com `--overlay-ports`; o job `windows-package` usa o *preset* do A, que já aponta o *overlay* |
| Empacotamento: rodar o manifesto de integridade e distribuir a chave pública | Feito na montagem com o código do A (`gamekernel.core.integrity`), como último passo. Meu `MANIFEST.sha256` (sem assinatura) foi **removido** para não duplicar o M10. A CI assina com uma chave efêmera (a de *release* nunca chega à CI) e exige `gk-cli integrity` verde com assinatura válida no produto instalado e no portátil |
| APIs para as telas (quarentena, integridade, assinaturas) | Anotado. Pela rev. 4 a interface consome o `cpp/bridge`; enquanto ele não existe, a interface usa `cpp/ipc` e `cpp/updates` diretamente. Se o A preferir, ligo o `cpp/app` ao `gk_core` já agora para as páginas de Quarentena e Integridade (pede o `add_subdirectory(cpp/app)` na raiz, pendência 3) |
| Acordo: `cpp/updates` delegar a validação YARA ao núcleo | **De acordo.** Lado do B pronto: o validador do publicador (`gamekernel/rules/prepare.py`) passou a exigir `category`/`severity` e a recusar `pe.signatures`/`pe.is_signed`/`pe.number_of_signatures` com a mesma checagem e mensagem do núcleo, e `test_publisher_gate_is_never_more_permissive_than_the_core` compara com `gk_native.yara_validate_dir`. Proposta ao A: o núcleo também recusar categoria desconhecida, severidade fora da escala e componente YARA sem regras (o publicador já recusa; hoje o núcleo aceita) |

## Pendências

1. **P1 — Nome do produto: decidido pelo usuário em 2026-11-15 — "Game Kernel".** (Para o A: atualizar o §4 da `WORK_SPLIT.md`; `gk::kProductName` e a interface já usam esse nome.)
2. **P2 — Interface com o B** (usuário): proposta dos dois agentes, sem objeção até agora.
3. **Para o A — `add_subdirectory(cpp/app)`** no `CMakeLists.txt` da raiz quando Qt 6 Widgets e Svg estiverem
   disponíveis. O app já compila sozinho (`cmake -S cpp/app`).
4. **Para o A — `gk_native` na CI do produto**: a `ci.yml` não compila o `gk_native`, então os testes do A aparecem
   como pulados nela (a `core-ci` os cobre). Se o A preferir uma CI única, incluo o *preset* do núcleo na `ci.yml`.
5. **`signatures/keys/`** (B): a chave pública de *release* é derivada da chave que assina o manifesto (`--key`) e
   gravada na montagem; a privada nunca é versionada nem chega à CI. Pacotes da CI usam uma chave efêmera e não são
   para distribuição.
6. **Para o A — falha do motor de risco não pode rebaixar o resultado**: sem `contracts/threat_catalog.json`, o
   `gk-cli` terminou a varredura como `completed` e classificou um EICAR com evidências YARA, de assinatura e de
   reputação como `unknown`/`NONE`, com apenas um *warning* ("Motor de risco: não foi possível abrir ..."). Uma
   falha interna da avaliação deveria dar `inconclusive` (ou falhar a varredura), nunca "desconhecido, sem risco".
   (Achado pelo teste de ponta a ponta da distribuição; o lado do B já leva o catálogo.)
7. **Para o A — `gk-cli` e a versão portátil**: o `default_data_dir()` do `gk-cli` ignora o `portable.flag`
   (o `app_paths.py` e a interface respeitam). Na versão portátil, a CLI sem `--data-dir` grava em
   `%LOCALAPPDATA%\GameKernel`, separada dos dados da interface.
8. **Para o A — primeira compilação MSVC de `cpp/scan` e `cpp/cli`**: a `core-ci` Windows não instala Qt, então
   essas partes (e `cpp/ipc`/`cpp/updates` com `/WX`) só passam a ser compiladas com MSVC no job `windows-package`.
