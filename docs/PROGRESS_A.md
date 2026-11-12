# Progresso — Agente A (motor de detecção e dados)

## FASE 1 — Arquitetura e planejamento técnico ✅
* `docs/ARCHITECTURE.md` — arquitetura, pipeline, escolha de tecnologias.
* `docs/WORK_SPLIT.md` — divisão entre os agentes A e B e contratos.

## FASE 2 — Ambiente e dependências (fundação) ✅
* Dependências fixadas em `requirements.txt` / `requirements-dev.txt` (testadas em Python 3.13).
* Validado no ambiente de desenvolvimento: ClamAV 1.5.4, 7-Zip 23.01, unrar, Qt offscreen,
  YARA 4.5.4 com módulos `pe`, `dotnet`, `math`, `hash`.
* Fundação implementada: modelos, configurações, caminhos, netguard, banco SQLite, criptografia,
  contrato do scanner, identificação de tipos, hashing, catálogo de ameaças.
* Testes: `tests/foundation/` — 23 testes passando.

## Arquitetura híbrida — ETAPAS 1 a 4 ✅
* Auditoria e plano: `docs/MIGRATION_PLAN.md`; contratos: `docs/INTEGRATION.md`; módulos: `docs/MODULES.md`.

## M1 — base do núcleo C++ ✅
* `cpp/core`: `ByteView`, `ReadOnlyFile`/`MappedFile`, SHA-256/MD5, identificação de tipo; `cpp/bindings/gk_native`.
* Testes: 99 passando (Linux release com -Werror); 75 testes nativos sob ASan/UBSan sem erros;
  arquivos C++ compilam contra os cabeçalhos do Windows (mingw-w64).

## M2 — parser PE em C++ ✅
* `cpp/core/src/pe.cpp` (+ `text.cpp`, `serialize.cpp`); bindings `parse_pe`, `parse_pe_file`, `pe_rva_to_offset`,
  `pe_offset_to_rva`, `shannon_entropy`.
* Testes: equivalência com pefile no corpus real; mapeamento de endereços; fuzzing; estruturas malformadas
  (laço de recursos, contagens gigantes de exports, seção W+X, entry point fora das seções, truncamento).
* Fuzzing revelou dois problemas de desempenho (não de memória), corrigidos: análise repetida de recursos
  idênticos e busca linear de seção por RVA com até 2048 seções.
* CI: build Windows (MSVC + vcpkg) e testes nativos passaram no primeiro run; falha única corrigida no `db.py`.

## M3 — motor YARA em C++ ✅
* `cpp/core/src/yara_engine.cpp`; bindings `YaraRules`, `yara_validate_dir`, `yara_version`.
* Regras de detecção iniciais e gerador de indicadores; `docs/DETECTION_RULES.md`.
* Testes: 133 passando no total (Linux release); suíte nativa sob ASan/UBSan com 2000 iterações de fuzzing PE.

## M5 — compactados (libarchive) ✅
* Em memória, formatos e filtros em lista branca, limites anti-bomba com orçamento compartilhado entre níveis,
  nomes perigosos, links, criptografia; equivalência com zipfile/tarfile; fuzzing sob ASan.

## M6 — camada de evidências ✅
* Regras estruturais PE, nomes enganosos, correlação de capacidades (indicadores × imports), scripts
  (`-EncodedCommand`, Base64, ofuscação), LNK/URL, IP:porta, membros de compactados. Contrato JSON idêntico ao
  `models.py`.

## M7 — motor de risco e módulo de cracks/mods ✅
* `signatures/data/game_components.json` (21 componentes), contexto de pasta, mitigação só de traços esperados,
  classificação, estado de crack, falso positivo possível, explicação e recomendações do catálogo.

## M8 — varredura ponta a ponta ✅
* `gk-scanworker` (processo isolado, gk-ipc v1), `gk::scan::Scanner` (Qt Core), `gk::db` (SQLite, mesmo esquema
  e cadeia de auditoria do Python), reputação local, ClamAV em lote, `gk-cli`.

## M4 — assinaturas digitais (Authenticode) ✅
* Portátil: tabela de certificados, PKCS#7 com leitor DER limitado, assinaturas aninhadas, resumo da imagem
  (MD5/SHA-1/SHA-256/SHA-384/SHA-512), adulteração, dados escondidos (CVE-2013-3900); também em membros de
  compactados.
* Windows: `WinVerifyTrust` sem rede (cache-only, sem revogação online) + catálogos do sistema; estados
  confiável/sem assinatura/adulterado/raiz não confiável/expirado/revogado/bloqueado/cadeia incompleta/inválido.
* Evidências `PE.Signature.*`; adulteração marca o arquivo como modificado e é traço esperado em cracks
  reconhecidos; assinatura válida nunca reduz risco. Relatórios distinguem "presente, não verificada".
* `signify` removido das dependências (nada o usava; o oscrypto dele não funciona com OpenSSL 3).
* Testes: 48 em `test_authenticode.py` (oráculo asn1crypto + hashlib; 5 000 iterações de fuzzing sob ASan);
  CI Windows valida catálogo do sistema, assinatura real do `python.exe` e cópia adulterada.

## M9 — quarentena em C++ ✅
* `gk/quarantine.hpp`: cofre `.gkq` com libsodium secretstream (XChaCha20-Poly1305), metadados cifrados no bloco
  final (permitem reconstruir um banco perdido), uma única leitura do arquivo (hash enquanto cifra), cópia
  decifrada e conferida antes de apagar o original; no Windows o original fica travado contra escrita e é apagado
  pelo mesmo handle (`FileDispositionInfoEx`); chave DPAPI; ACL restrita; restauração atômica sem sobrescrever.
* `Manager`: banco (`quarantine`, `quarantine_events`) + auditoria encadeada; `verify` recupera itens órfãos e
  limpa cópias de itens já restaurados/apagados. `gk-cli quarantine add|list|restore|delete|verify`.
* Testes: 24 em `test_quarantine.py` (tamanhos de 0 a >3 MiB, adulteração em cada região, truncamento,
  reordenação, chave errada, ids inválidos, conflito de destino, ciclo completo lido pelo Python com cadeia de
  auditoria válida, banco perdido e recuperado) + 2 000 mutações de bytes sob ASan.

## Correções de CI (rodada atual)
* `signatures/data/game_components.json` não estava versionado (padrão `data/` do `.gitignore`).
* `gk_native` derrubava o Python na saída no Windows (objetos Python em `static`); teste de ciclo de vida.
* Build MSVC: `localtime` (C4996 com `/sdl`) e conversões `path::string()` (página de código ANSI) trocadas por
  `localtime_s`/`localtime_r` e `text::path_utf8`.

## Próximo
* M10 verificação de integridade em C++,
  M11 tempo real (`ReadDirectoryChangesW`), M12 Performance Monitor / System Optimizer, M13 serviços Qt para a UI.
* Token de integridade baixa para o `gk-scanworker`.
* Pendente de acordo com o Agente B: `cpp/updates` delegar a validação de YARA ao `gk::yara::validate_rules_dir`.
  Isso mudaria decisões de pacotes (o núcleo exige os metadados `category`/`severity` do contrato de regras) e
  precisa ser feito junto com o validador Python e os testes de equivalência de pacotes, que são do Agente B;
  além disso o `cpp/updates` precisa continuar compilável sozinho.

## Auditoria de importações (rede) ✅
* `tests/native/test_offline_imports.py` cumpre o que `SECURITY.md` promete: nenhum binário importa código de rede
  (Windows: parser PE do núcleo; Linux: `nm`/`objdump`). O próprio verificador é testado com um PE que importa
  `ws2_32!connect` e WinINet.
