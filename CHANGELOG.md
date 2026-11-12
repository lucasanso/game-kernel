# Changelog

## Agente A — Core e Segurança

### [não lançado]
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
