# Changelog

## Agente A — Core e Segurança

### [não lançado]
- M3: motor YARA em C++ sobre libyara (`gk::yara`): compilação com isolamento por arquivo, `include` bloqueado,
  variáveis externas, limites de correspondências, cancelamento, scanner por chamada (thread-safe), validação de
  diretórios de regras com metadados obrigatórios, salvar/carregar regras compiladas.
- M3: 10 regras de detecção iniciais documentadas (`signatures/yara/`, `docs/DETECTION_RULES.md`) e 95 regras de
  indicadores geradas (`signatures/internal/indicators.yar`, literais em escapes `\xNN`).
- M3: equivalência com yara-python (26 testes), execução sob ASan/UBSan; padrões sem átomo removidos da tabela.
- Dependência adicionada: libyara (BSD-3).
- M2: parser PE em C++ (`gk::pe::parse`) com limites explícitos em todas as tabelas, anomalias estruturais com
  códigos estáveis, cache de análise de recursos e orçamento de bytes, busca de seção por RVA em O(log n).
- M2: serialização JSON dos resultados (`gk/serialize.hpp`) — formato único usado por bindings e IPC.
- M2: corpus de PEs reais gerado com mingw-w64 (x86/x64: exe, DLL com forwarders e exports só por ordinal,
  recursos, VERSIONINFO, manifest, TLS, PDB, overlay); equivalência total com pefile, inclusive mapeamento
  RVA↔offset; fuzzing por mutação (400 iterações por padrão, 2000 no CI sob ASan/UBSan).
- Correção (fundação Python, encontrada pelo CI Windows): `Database._connect` vazava o handle quando o arquivo
  estava corrompido, impedindo a recuperação no Windows.
- Dependência adicionada: nlohmann/json (MIT, header-only).
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
