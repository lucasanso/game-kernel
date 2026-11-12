# Changelog

## Agente A — Core e Segurança

### [não lançado]
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
- Interface Qt 6 C++ (`cpp/app`, etapa B9 parte 1): janela com menu lateral, cabeçalho por página, notificações
  internas, instância única, tema escuro grafite com destaques em azul e verde e cores de risco, ícones SVG e logotipo
  próprios. Páginas com serviço real: Central de Atualização Offline (`cpp/updates`: conjunto ativo e aviso de
  desatualização, importar → conferir publicador, versão, chave e componentes → confirmar → instalar, *downgrade* só
  com confirmação explícita, reversão, histórico, chaves confiáveis com as embutidas protegidas), Análise
  comportamental (`sandbox.*`: disponibilidade com o motivo, ativação gravada em `settings.json`, confirmação com as
  limitações, progresso, cancelamento, evidências) e Privacidade e rede (`system.info`, autoteste de rede, reinício
  do auxiliar). As páginas do núcleo entram com o `cpp/bridge` (A), sem telas provisórias.
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
