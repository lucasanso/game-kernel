# Inventário de módulos

Legenda de estado: ✅ integrado e testado · 🔄 em migração · 🐍 mantido em Python · 🗑️ será removido após equivalência · ⏳ planejado

## Núcleo C++ (`cpp/core`, Agente A)

| Módulo | Arquivos | Estado | Substitui |
|---|---|---|---|
| Hashing (SHA-256/MD5 em streaming) | `hash.hpp/.cpp` | ✅ M1 (equivalência com hashlib, ASan) | `core/hashing.py` |
| Tipo real de arquivo | `filetype.hpp/.cpp` | ✅ M1 (equivalência em ~450 cabeçalhos gerados/mutados) | `core/filetypes.py` |
| Leitura limitada (`ByteView`) e arquivos somente leitura/mapeados | `byte_view.hpp`, `file_view.hpp/.cpp` | ✅ M1 | — |
| Parser PE (cabeçalhos, seções, entropia, imports/delay-imports, exports/forwarders, recursos, version info, manifest, TLS, debug/PDB, Rich, overlay, mapeamento RVA↔offset) | `pe.hpp/.cpp`, `text.hpp/.cpp`, `serialize.hpp/.cpp` | ✅ M2 (equivalência com pefile em PEs reais x86/x64; fuzzing sob ASan/UBSan) | `pefile` |
| Authenticode: tabela de certificados, PKCS#7 (DER limitado) e assinaturas aninhadas, resumo da imagem em MD5/SHA-1/SHA-256/SHA-384/SHA-512, adulteração, dados escondidos; confiança via `WinVerifyTrust` offline + catálogos (Windows); evidências `PE.Signature.*` | `authenticode.hpp/.cpp`, `authenticode_trust.cpp`, `signature_rules.cpp`, `src/der.hpp` | ✅ M4 (oráculo asn1crypto + hashlib em amostras assinadas com osslsigncode; assinatura real do python.exe e catálogo do Windows na CI; fuzzing sob ASan) | `signify` (removido das dependências) |
| YARA (compilação isolada por arquivo, `include` bloqueado, externals, limites, cancelamento, scanner por chamada — thread-safe) | `yara_engine.hpp/.cpp` | ✅ M3 (equivalência com yara-python: regras, namespaces, tags, metadados, offsets e trechos) | `engines/yara_engine.py` (oráculo) |
| Compactados (libarchive em memória; ZIP/7z/RAR/RAR5/ISO/CAB/TAR/CPIO/LHA + gz/bz2/xz/zstd/lz4; SFX; limites anti-bomba com orçamento compartilhado entre níveis; nomes perigosos, links, criptografia) | `archive.hpp/.cpp` | ✅ M5 (equivalência com zipfile/tarfile; fuzzing sob ASan) | py7zr, rarfile, pycdlib |
| Camada de evidências: regras estruturais PE, nomes enganosos, correlação de capacidades (indicadores × imports), scripts (linhas, `-EncodedCommand`, Base64, ofuscação), atalhos LNK/URL, IP:porta, membros de compactados | `analysis.hpp`, `model.hpp`, `pe_rules.cpp`, `capabilities.cpp`, `text_analysis.cpp`, `analysis.cpp` | ✅ M6 (contrato JSON idêntico ao `models.py`; corpus benigno ≤ LOW; ASan) | — |
| Contexto de pasta (cracks, desbloqueadores, mods, repacks — banco `signatures/data/game_components.json`) e motor de risco (mitigação só de traços esperados, classificação, estado de crack, explicação, recomendações do `contracts/threat_catalog.json`) | `risk.hpp`, `risk.cpp` | ✅ M7 | — |
| Orquestrador (`cpp/scan`), processo isolado `gk-scanworker` (servidor gk-ipc v1), banco SQLite C++ (`db.cpp`, esquema embutido de `contracts/schema.sql`), enumeração, reputação local (IOCs), ClamAV em lote, `gk-cli` | `cpp/scan`, `cpp/worker`, `cpp/cli`, `db.cpp`, `enumerate.cpp`, `reputation.cpp`, `clamav.cpp` | ✅ M8 (ponta a ponta, cache, falha/travamento do worker, cancelamento) | `core/scan_api.py` |
| Quarentena | `quarantine.cpp` | ⏳ M9 | — |
| Integridade da instalação | `integrity.cpp` | ⏳ M10 | `core/integrity.py` (verificação) |
| Tempo real | `win/realtime.cpp` | ⏳ M11 | — |
| Performance Monitor / System Optimizer | `win/perf.cpp`, `win/optimizer.cpp` | ⏳ M12 | — |
| Serviços Qt | `cpp/bridge/*` | ⏳ M13 | — |

## Python

| Módulo | Estado | Papel após a migração |
|---|---|---|
| `gamekernel/core/models.py` | ✅ 🐍 | Modelo de dados no lado Python (helper, relatórios, testes) |
| `gamekernel/core/threat_catalog.py` | ✅ 🐍 | Carrega `contracts/threat_catalog.json` |
| `gamekernel/config.py`, `app_paths.py` | ✅ 🐍 | Ferramentas e helper (mesmo formato do C++) |
| `gamekernel/netguard.py` | ✅ 🐍 | Bloqueio de rede em todo processo Python |
| `gamekernel/crypto_utils.py` | ✅ 🐍 | Assinatura de pacotes/manifestos (ferramentas) |
| `gamekernel/database/db.py` | ✅ 🐍 | Acesso de ferramentas/relatórios/testes; esquema em `contracts/schema.sql` |
| `gamekernel/engines/indicators.py` | 🐍 ✅ | Tabela de indicadores → `signatures/internal/indicators.yar` via `tools/core_gen_indicators.py` (teste de atualização) |
| `gamekernel/core/integrity.py` | 🐍 | Geração do manifesto (build); verificação migra para C++ |
| `gamekernel/core/filetypes.py`, `hashing.py` | 🗑️ | Oráculos dos testes de equivalência; removidos quando o orquestrador C++ (M8) os substituir no fluxo |
| `gamekernel/engines/yara_engine.py` | 🗑️ | Oráculo para o M3 (motor YARA C++) |
| `gamekernel/core/tools.py` | removido | Nunca integrado; substituído por `gk::process` (M8) |
| `gamekernel/core/scan_api.py` | 🗑️ | Substituído pela API C++/IPC (M8) |

## Componentes escritos pelo Agente B

| Componente | Local | Linguagem | Mantido por |
|---|---|---|---|
| Cliente gk-ipc v1 (QProcess, Job Object, prazos, reinício) | `cpp/ipc/` | C++/Qt | A (adotado na rev. 4) |
| Verificação Ed25519 e instalação atômica de pacotes `.gkpkg`, CLI `gk-update` | `cpp/updates/` | C++/Qt | A (adotado na rev. 4) |
| Processo auxiliar `gk-helper` (servidor gk-ipc, cliente Python) | `gamekernel/helper/` | Python | B |
| Relatórios forenses (JSON, HTML, PDF) | `gamekernel/reports/` | Python (auxiliar) | B |
| Sandbox (Windows Sandbox + `monitor.ps1`) | `gamekernel/sandbox/` | Python + PowerShell (na VM) | B |
| Threat Intelligence e preparação de regras/pacotes | `gamekernel/intel/`, `gamekernel/rules/`, `gamekernel/updates/` | Python | B |
| Estado detalhado: `docs/PROGRESS_B.md` | | | |
