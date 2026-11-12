# Inventário de módulos

Legenda de estado: ✅ integrado e testado · 🔄 em migração · 🐍 mantido em Python · 🗑️ será removido após equivalência · ⏳ planejado

## Núcleo C++ (`native/core`, Agente A)

| Módulo | Arquivos | Estado | Substitui |
|---|---|---|---|
| Hashing (SHA-256/MD5 em streaming) | `hash.hpp/.cpp` | ✅ M1 (equivalência com hashlib, ASan) | `core/hashing.py` |
| Tipo real de arquivo | `filetype.hpp/.cpp` | ✅ M1 (equivalência em ~450 cabeçalhos gerados/mutados) | `core/filetypes.py` |
| Leitura limitada (`ByteView`) e arquivos somente leitura/mapeados | `byte_view.hpp`, `file_view.hpp/.cpp` | ✅ M1 | — |
| Parser PE (cabeçalhos, seções, entropia, imports/delay-imports, exports/forwarders, recursos, version info, manifest, TLS, debug/PDB, Rich, overlay, mapeamento RVA↔offset) | `pe.hpp/.cpp`, `text.hpp/.cpp`, `serialize.hpp/.cpp` | ✅ M2 (equivalência com pefile em PEs reais x86/x64; fuzzing sob ASan/UBSan) | `pefile` |
| Authenticode | `win/authenticode.cpp` | ⏳ M4 | `signify` |
| YARA (compilação isolada por arquivo, `include` bloqueado, externals, limites, cancelamento, scanner por chamada — thread-safe) | `yara_engine.hpp/.cpp` | ✅ M3 (equivalência com yara-python: regras, namespaces, tags, metadados, offsets e trechos) | `engines/yara_engine.py` (oráculo) |
| Compactados (libarchive em memória; ZIP/7z/RAR/RAR5/ISO/CAB/TAR/CPIO/LHA + gz/bz2/xz/zstd/lz4; SFX; limites anti-bomba com orçamento compartilhado entre níveis; nomes perigosos, links, criptografia) | `archive.hpp/.cpp` | ✅ M5 (equivalência com zipfile/tarfile; fuzzing sob ASan) | py7zr, rarfile, pycdlib |
| Scripts / LNK / ClamAV / reputação | `scripts.cpp`, `lnk.cpp`, `clamav.cpp`, `reputation.cpp` | ⏳ M6 | — |
| Risco + contexto de jogo/cracks | `risk.cpp`, `game_context.cpp` | ⏳ M7 | — |
| Orquestrador, worker, IPC, banco, CLI | `scanner.cpp`, `ipc.cpp`, `db.cpp`, `native/worker`, `native/cli` | ⏳ M8 | `core/scan_api.py` |
| Quarentena | `quarantine.cpp` | ⏳ M9 | — |
| Integridade da instalação | `integrity.cpp` | ⏳ M10 | `core/integrity.py` (verificação) |
| Tempo real | `win/realtime.cpp` | ⏳ M11 | — |
| Performance Monitor / System Optimizer | `win/perf.cpp`, `win/optimizer.cpp` | ⏳ M12 | — |
| Serviços Qt | `native/bridge/*` | ⏳ M13 | — |

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

## Componentes do Agente B (integrados nesta branch por merge)

| Componente | Local | Linguagem |
|---|---|---|
| gk-ipc v1 (protocolo, auxiliar, clientes) | `gamekernel/ipc/`, `gk_helper.py`, `native/ipc/` | Python + C++/Qt |
| Atualizações offline (preparação; verificação e instalação atômica) | `gamekernel/updates/`, `native/updates/` | Python + C++/Qt |
| Relatórios forenses (JSON, HTML, PDF) | `gamekernel/core/report_*.py`, `sysinfo.py` | Python (auxiliar) |
| Sandbox (Windows Sandbox) | `gamekernel/engines/sandbox_manager.py`, `sandbox/monitor.ps1` | Python + PowerShell (na VM) |
| Threat Intelligence | `gamekernel/ti/` | Python |
| Detalhes e estado: `docs/PROGRESS_B.md` | | |
