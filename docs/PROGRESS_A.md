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

## Próximas etapas do Agente A (histórico da revisão 1)
* FASE 3 — motor de detecção: ClamAV em lote, YARA, reputação local, orquestrador `Scanner`.
* FASE 4 — análise estática: PE, Authenticode, strings com offset/RVA, heurísticas de correlação, scripts, LNK.
* FASE 5 — compactados recursivos com proteção anti-bomba, PyInstaller embutido.
* FASE 6 — motor de risco, módulo de cracks (`game_context`).
* Backend de tempo real, integridade, CLI, testes de desempenho.
