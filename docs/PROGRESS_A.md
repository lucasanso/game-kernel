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

## Próximas etapas do Agente A
* FASE 3 — motor de detecção: ClamAV em lote, YARA, reputação local, orquestrador `Scanner`.
* FASE 4 — análise estática: PE, Authenticode, strings com offset/RVA, heurísticas de correlação, scripts, LNK.
* FASE 5 — compactados recursivos com proteção anti-bomba, PyInstaller embutido.
* FASE 6 — motor de risco, módulo de cracks (`game_context`).
* Backend de tempo real, integridade, CLI, testes de desempenho.
