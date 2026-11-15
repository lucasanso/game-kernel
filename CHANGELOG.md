# Changelog

## Agente A — Core e Segurança

### [não lançado]
- Segurança: o `gk-scanworker` passa a se proteger antes de ler qualquer entrada — integridade baixa, sem privilégios, sem processos filhos, sem código dinâmico, sem DLLs de extensão (Linux: no_new_privs). O `SECURITY.md` já descrevia a integridade baixa e a ausência de processos filhos, que não estavam implementadas.
- M10: integridade da instalação em C++ (`gk/integrity.hpp`), ferramenta de release `tools/build_integrity_manifest.py` e verificação de `gk-scanworker`/`clamscan` antes de executá-los no orquestrador; `gk-cli integrity`. Correção: caminho do banco recuperado em mensagem usava `path::string()`.
- Segurança (achado da auditoria de importações): libyara do Windows compilada sem OpenSSL por um overlay do vcpkg — o port oficial trazia o código de socket/HTTP do OpenSSL estático para `gk_native` e `gk-scanworker`. Também sem leitor de memória de processos. Regras com campos de assinatura do módulo `pe` são recusadas com mensagem clara em todas as plataformas.
- Auditoria de importações: teste que verifica que nenhum binário C++ importa código de rede (controle já descrito em SECURITY.md/ARCHITECTURE.md, agora efetivamente verificado).
- M9: quarentena em C++. Cofre `.gkq` (XChaCha20-Poly1305 em fluxo, metadados cifrados, verificação antes de apagar o original, exclusão pelo mesmo handle no Windows, chave DPAPI, ACL restrita), restauração atômica conferida por SHA-256, `Manager` com banco/eventos/auditoria e recuperação de banco perdido, `gk-cli quarantine`.
- M4: assinaturas digitais (Authenticode). Núcleo portátil lê a tabela de certificados e o PKCS#7 (leitor DER limitado, assinaturas aninhadas), calcula o resumo da imagem e detecta adulteração e dados escondidos, inclusive em membros de compactados; no Windows, `WinVerifyTrust` sem rede + catálogos do sistema. Evidências `PE.Signature.*`, arquivo adulterado classificado como modificado, explicação com o assinante verificado, relatórios com "presente, não verificada". SHA-1 e SHA-384/512 no `gk/hash.hpp`. `signify` removido; `asn1crypto` (oráculo) e `osslsigncode` nos testes.
- Correção (Windows/MSVC): `localtime` → `localtime_s`; `path::string()` → `text::path_utf8` (nomes fora da página de código ANSI quebravam a recuperação do banco e a carga de IOCs).
- Correção: `signatures/data/game_components.json` não estava no repositório (o padrão `data/` do `.gitignore` também casava com `signatures/data/`; agora só `/data/` na raiz é ignorado).
- Correção: o `gk_native` derrubava o interpretador na saída no Windows (0xC0000005): objetos Python em `static` (exceção `GkError`, `json.loads`/`json.dumps`) eram destruídos depois da finalização do Python. Agora ficam em `gil_safe_call_once_and_store`, que nunca roda destrutor. Novo teste executa cada componente num interpretador próprio e exige saída limpa.
- M8: varredura ponta a ponta. `gk-scanworker` (processo isolado, servidor gk-ipc v1, cancelamento, membros de
  compactados como eventos); orquestrador Qt `gk::scan::Scanner` supervisionando N workers pelo cliente gk-ipc
  (Job Object, prazo, reinício), cache por caminho/mtime e por SHA-256 + impressão das regras, ClamAV em lotes com
  `--file-list` e vários bancos, reputação local (IOCs JSON + marcações do usuário), contexto e risco, gravação no
  SQLite pelo C++ com o mesmo esquema do Python (cadeia de auditoria compatível), resumo com limitações e avisos;
  `gk-cli` com códigos de saída. EICAR detectado por três mecanismos independentes (YARA, ClamAV, IOC).
  Testes ponta a ponta incluem worker que trava/cai e cancelamento por Ctrl+C.
- M7: motor de risco e módulo de cracks em C++ (`gk::risk`): reconhecimento de componentes por pasta a partir de
  `signatures/data/game_components.json` (21 famílias: emuladores Steam/Epic/EA/Ubisoft, desbloqueadores de DLC,
  Online-Fix, Steamless, ReShade, ENB, ASI Loader, Special K, DXVK, BepInEx, MelonLoader, Script Hook V, script
  extenders, repacks FitGirl), nomes e pastas de crack, DLL substituída com original `_o`, proxy não reconhecido;
  atenuação apenas de traços esperados (nunca de assinatura, YARA, reputação ou comportamento); classificação,
  estado de crack, categoria principal, falso positivo possível, explicação passo a passo e recomendações do
  `contracts/threat_catalog.json` (gerado de `threat_catalog.py`). Correção: iteração sobre JSON temporário
  (referência pendente em C++20) detectada pelo compilador.
- M6: camada de evidências em C++ (`gk::analysis`): regras estruturais de PE (empacotadores, protetores comerciais,
  entry point, importações mínimas, executáveis embutidos, overlay, TLS, PDB suspeito, drivers abusados, proxies
  de DLL), nomes enganosos (processos do sistema, typosquatting, extensão dupla, RLO), correlação de capacidades
  (stealers, keylogger, clipper, ransomware, minerador, persistência, desativação de proteções, downloader,
  injeção, backdoor, rede), scripts com número de linha e decodificação de `-EncodedCommand`/Base64, atalhos
  LNK/URL, literais IP:porta, análise individual de membros de compactados. Modelo C++ com JSON idêntico ao
  `gamekernel/core/models.py`. Corpus benigno não passa de LOW.
- WORK_SPLIT rev. 4: árvore C++ única em `cpp/`; o A adota `cpp/ipc` (cliente gk-ipc) e `cpp/updates` (verificação
  e instalação de pacotes), escritos pelo B, como propôs o B — sem módulos duplicados.
- M5: compactados em memória (libarchive) com formatos e filtros em lista branca (sem `mtree`, sem programas
  externos), limites anti-bomba com orçamento compartilhado entre níveis, SFX, nomes perigosos, links e criptografia.
- M3: motor YARA em C++ (libyara) equivalente ao yara-python; 10 regras de detecção documentadas
  (`docs/DETECTION_RULES.md`) e 95 indicadores gerados (`tools/core_gen_indicators.py`, literais em `\xNN`).
- M2: parser PE em C++ para entrada hostil, equivalente ao pefile em PEs reais (mingw-w64) e em DLLs do System32
  (CI Windows); fuzzing por mutação sob ASan/UBSan; ordinais de WS2_32/WSOCK32/OLEAUT32 nomeados como no pefile.
- Correções: vazamento de handle na recuperação do banco (Windows); alvo vcpkg `unofficial::libyara::libyara`;
  OpenSSL para a libyara estática; desempenho do parser PE em entradas hostis (cache e orçamento de recursos,
  busca de seção O(log n)).
- Dependências: nlohmann/json (MIT), libyara (BSD-3), libarchive (BSD-2).
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
- **Opções de varredura com efeito**: o núcleo lê o `settings.json` (`gk::scan::Config::load`: processos, tamanho
  máximo, limites de compactados, tipos de arquivo, exclusões, ClamAV) — na interface, na proteção em tempo real e no
  `gk-cli` (a linha de comando tem prioridade). A página Configurações ganhou o bloco **Varredura**. Corrigido: excluir
  a pasta `C:\Jogos\Foo` também excluía `C:\Jogos\FooBar`.
- **Pacotes de regras validados pelo núcleo**: no produto, a Central de Atualização e o `gk-update` aceitam um pacote
  YARA só se o motor que vai carregá-lo aceita (`gk::yara::validate_rules_dir`); o núcleo agora recusa também categoria
  desconhecida, severidade fora da escala, metadado vazio e componente sem regras, como o validador do publicador.
- **Monitor de desempenho e otimizador (M12, tarefa do A assumida pelo B)**: `cpp/perf` — processador
  (GetSystemTimes), memória, disco e GPU por mecanismo / memória de vídeo por contadores PDH adicionados pelo nome em
  inglês (independem do idioma do Windows), placas de vídeo pelo DXGI, processos que mais usam processador, memória
  e placa de vídeo (Toolhelp); `/proc` no Linux. `cpp/sysopt` — diagnóstico só de leitura (plano de energia e bateria,
  Modo de Jogo, gravação em segundo plano, agendamento de GPU, memória, espaço livre, programas de inicialização,
  reinicialização pendente), cada item com o que ajustar no Windows; limpeza de temporários em duas etapas (só o que
  a análise listou e não mudou; links nunca seguidos; arquivos em uso mantidos; auditoria). Serviços
  `PerformanceService` (amostragem só com a página aberta) e `OptimizerService`; páginas **Desempenho** e
  **Otimizador**.
- **Proteção em tempo real (M11, tarefa do A assumida pelo B)**: `cpp/realtime` — observador recursivo nativo
  (ReadDirectoryChangesW no Windows; inotify no Linux para desenvolvimento e CI), lotes só com arquivos que pararam de
  mudar (estabilidade, leitura possível, janela de agrupamento, remoções e renomeações descartadas, perda de eventos
  vira nova verificação da pasta), monitor que analisa no modo rápido com o `gk_scan` (origem `realtime`), registra
  em `realtime_events`, avisa a partir do nível escolhido e, só quando o usuário liga, coloca em quarentena ameaças
  confirmadas por assinatura (`gk::risk::confirmed_by_signature`, a mesma regra do motor de risco) — nunca um arquivo
  que o usuário restaurou. A pasta de dados do programa nunca é observada. `RealtimeService` no `cpp/bridge`; página
  **Tempo real**, bloco no Painel, ícone na área de notificação (fechar a janela mantém a proteção) e Histórico sem os
  lotes automáticos por padrão. Banco: `add_realtime_event`/`list_realtime_events` e filtro de origem em `list_scans`.
  Corrigido: o temporizador de progresso do `Scanner` era compartilhado entre instâncias (duas varreduras em *threads*
  diferentes).
- Interface: páginas do núcleo sobre o `cpp/bridge` — **Painel** (última varredura, assinaturas, quarentena,
  integridade da instalação, ações rápidas), **Segurança do jogo** (varredura com progresso, pausa, cancelamento e
  achados ao vivo), **Análise forense** (filtros, detalhes, explicação, recomendações, evidências com local exato,
  quarentena com SHA-256 conferido), **Histórico** e **Quarentena** (restaurar com confirmação e substituição
  explícita, apagar, verificar o cofre); rótulos do catálogo de ameaças da instalação; tabela de varreduras
  compartilhada com Relatórios.
- **Tarefas do A assumidas pelo B (pedido do usuário)**: M13 `cpp/bridge` (serviços Qt de varredura, histórico,
  quarentena e integridade, com leitura somente leitura do banco no núcleo); motor de risco à prova de falha;
  `gk-cli` respeitando o `portable.flag`; interface compilada pela raiz com o endurecimento do núcleo; limite de
  memória do *worker* desligado só em builds com AddressSanitizer.
- Interface Qt 6 C++ (`cpp/app`, etapa B9 parte 1): janela com menu lateral, cabeçalho por página, notificações
  internas, instância única, tema escuro grafite com destaques em azul e verde e cores de risco, ícones SVG e logotipo
  próprios. Páginas com serviço real: Central de Atualização Offline (`cpp/updates`: conjunto ativo e aviso de
  desatualização, importar → conferir publicador, versão, chave e componentes → confirmar → instalar, *downgrade* só
  com confirmação explícita, reversão, histórico, chaves confiáveis com as embutidas protegidas), Análise
  comportamental (`sandbox.*`: disponibilidade com o motivo, ativação gravada em `settings.json`, confirmação com as
  limitações, progresso, cancelamento, evidências) e Privacidade e rede (`system.info`, autoteste de rede, reinício
  do auxiliar). As páginas do núcleo entram com o `cpp/bridge` (A), sem telas provisórias.
- `docs/RELEASE.md`: como publicar uma versão (chave de *release*, assinatura de código, montagem, instalador,
  conferência em máquina limpa, pacotes de assinaturas, decisões sobre ClamAV e Sysmon); teste que exige a mesma
  versão no núcleo e na interface; a página Privacidade e rede mostra serviços do auxiliar que não carregaram.
- Interface: página **Configurações** só com opções que têm efeito hoje (padrões de privacidade dos relatórios, aviso
  de assinaturas desatualizadas, análise comportamental com Sysmon opcional, pasta de dados), validadas com as faixas
  do `config.py`, gravadas de forma atômica preservando as demais chaves e propagadas na hora para as outras páginas
  (`AppContext::settingChanged`); o auxiliar Python lê o que a interface grava (testado).
- Interface: página **Relatórios forenses** (varreduras do banco pelo novo método `reports.scans` do auxiliar, só
  leitura; geração em HTML, JSON e PDF com as opções de privacidade; progresso; relatórios gerados com abertura do
  arquivo ou da pasta). Utilitários de página (`scrollingPage`, `mutedLabel`) movidos para o `ui_kit`.
- Distribuição (B10): `tools/make_distribution.py` monta a pasta do produto (interface, `gk-cli`, `gk-scanworker`,
  `gk-update`, `gk-helper` congelado, assinaturas, catálogo de ameaças, runtime MSVC, guias) com o manifesto de
  integridade assinado do núcleo (M10 do A) e o ZIP portátil, recusando chave privada, DLL de rede e DLLs conflitantes; `installer/gamekernel.iss` (Inno
  Setup, pt-BR, por máquina ou por usuário, sem rede, desinstalação que preserva os dados e avisa onde estão);
  job `windows-package` na CI que instala em silêncio, testa o produto instalado de ponta a ponta, desinstala e
  testa a versão portátil; guias `docs/INSTALL.md` e `docs/USAGE.md`.
- Auxiliar congelado: os serviços `sandbox.*` e o `monitor.ps1` não entravam no `gk-helper.exe`; o spec agora deriva
  os *hidden imports* do `SERVICE_MODULES`, e o `system.info` lista `unavailable_services`.
- Ícone e versão do executável: logotipo com fonte única em `assets/gamekernel.svg` (recurso Qt), `assets/gamekernel.ico`
  gerado por `tools/make_app_icon.py`, recurso Windows com ícone e `VERSIONINFO`; a versão vem do `project()` do CMake
  e é a mesma exibida na interface.
- Novo método do auxiliar `system.network_selftest`: tenta DNS e conexão de saída e comprova o bloqueio.
- `invalid_params` passa a usar o código `-32602` do §3 (rev. 4), no auxiliar e, como ajuste mecânico, em `cpp/ipc`.
- Testes: `tests/ui/` (11 casos QtTest com pacotes reais e o auxiliar real, capturas de tela; limpos sob ASan/UBSan);
  no Windows, plugin de plataforma `offscreen` ao lado dos executáveis de teste; diretórios de *build* configurados a
  partir de outra origem são recriados.
- Mesclagem da `docs/WORK_SPLIT.md` rev. 4: o layout da rev. 2 fica valendo, e o C++ passa para `cpp/`. O
  realinhamento provisório à rev. 3 feito na branch do B foi descartado sem perda de conteúdo.
- Processo auxiliar Python `gk-helper` (`gamekernel/helper/`): servidor do envelope IPC de `docs/INTEGRATION.md` §3
  com extensões opcionais (cancelamento, prazo, id em eventos, `error.data.reason`), isolamento de falhas
  (exceção → 1099 com o auxiliar ativo; proteção de stdout; `netguard`), cliente Python; métodos em
  `contracts/helper_methods.md`.
- Cliente C++/Qt (`native/ipc/`, hoje `cpp/ipc/`, mantido pelo A): QProcess, sinais e slots, Job Object (Windows), RLIMIT_AS e
  PDEATHSIG (Linux), prazo → cancelamento → morte, reinício limitado. Oferecido ao Agente A para o `cpp/bridge` (M13).
- Relatórios forenses (`gamekernel/reports/`): JSON, HTML autocontido sem JavaScript (CSP `default-src 'none'`),
  PDF (reportlab, fonte Unicode); 15 seções e relatório individual de cracks; redação de usuário e de nome do
  computador; banco somente leitura. Serviço `reports.generate`.
- Sandbox (`gamekernel/sandbox/`): orquestração do Windows Sandbox sem rede, recusa sem isolamento, `monitor.ps1`
  (iscas de credenciais, documentos-isca, auditoria por GUID, árvore de processos), mapeamento para evidências
  comportamentais. Serviços `sandbox.*`.
- Atualização offline: formato `.gkpkg` v1 (`contracts/update_package.md`), construtor e verificador de referência
  em Python (`gamekernel/updates/`), verificador e instalador atômico C++ (`native/updates/`, hoje
  `cpp/updates/`, adotado pelo A na rev. 4; libsodium + libyara), CLI `gk-update`.
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
