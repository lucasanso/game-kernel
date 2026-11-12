# Inventário de módulos

Legenda de estado: ✅ integrado e testado · 🔄 em migração · 🐍 mantido em Python · 🗑️ será removido após equivalência · ⏳ planejado

## Núcleo C++ (`cpp/core`, Agente A)

| Módulo | Arquivos | Estado | Substitui |
|---|---|---|---|
| Hashing (SHA-256/MD5 em streaming) | `hash.hpp/.cpp` | ✅ M1 (equivalência com hashlib, ASan) | `core/hashing.py` |
| Tipo real de arquivo | `filetype.hpp/.cpp` | ✅ M1 (equivalência em ~450 cabeçalhos gerados/mutados) | `core/filetypes.py` |
| Leitura limitada (`ByteView`) e arquivos somente leitura/mapeados | `byte_view.hpp`, `file_view.hpp/.cpp` | ✅ M1 | — |
| Parser PE | `pe.hpp/.cpp` | ⏳ M2 | `pefile` |
| Authenticode | `win/authenticode.cpp` | ⏳ M4 | `signify` |
| YARA | `yara_engine.hpp/.cpp` | ⏳ M3 | `engines/yara_engine.py` |
| Compactados | `archive.hpp/.cpp` | ⏳ M5 | py7zr, rarfile, pycdlib |
| Scripts / LNK / ClamAV / reputação | `scripts.cpp`, `lnk.cpp`, `clamav.cpp`, `reputation.cpp` | ⏳ M6 | — |
| Risco + contexto de jogo/cracks | `risk.cpp`, `game_context.cpp` | ⏳ M7 | — |
| Orquestrador, worker, IPC, banco, CLI | `scanner.cpp`, `ipc.cpp`, `db.cpp`, `cpp/worker`, `cpp/cli` | ⏳ M8 | `core/scan_api.py` |
| Quarentena | `quarantine.cpp` | ⏳ M9 | — |
| Pacotes offline / integridade | `update.cpp`, `integrity.cpp` | ⏳ M10 | `core/integrity.py` (verificação) |
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
| `gamekernel/engines/indicators.py` | 🐍 | Gerador de `signatures/internal/indicators.yar` |
| `gamekernel/core/integrity.py` | 🐍 | Geração do manifesto (build); verificação migra para C++ |
| `gamekernel/core/filetypes.py`, `hashing.py` | 🗑️ | Oráculos dos testes de equivalência; removidos quando o orquestrador C++ (M8) os substituir no fluxo |
| `gamekernel/engines/yara_engine.py` | 🗑️ | Oráculo para o M3 (motor YARA C++) |
| `gamekernel/core/tools.py` | removido | Nunca integrado; substituído por `gk::process` (M8) |
| `gamekernel/core/scan_api.py` | 🗑️ | Substituído pela API C++/IPC (M8) |
