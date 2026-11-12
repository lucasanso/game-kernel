# Game Kernel — Arquitetura híbrida C++20 / Python

> Revisão 2 (2026-11-12): adoção da arquitetura híbrida definida na diretriz de refatoração.
> A revisão 1 (100% Python) está no histórico do Git; o plano de transição está em `MIGRATION_PLAN.md`.

Game Kernel é um **aplicativo desktop nativo para Windows 10/11 x64**, 100% offline, especializado em
investigar jogos, cracks, repacks, mods e launchers. O usuário final instala um único programa; C++ e
Python ficam invisíveis.

## 1. Princípios

| Princípio | Aplicação |
|---|---|
| Offline por construção | Nenhum binário C++ vincula bibliotecas de rede (verificado por teste de imports). Processos Python rodam com `netguard` (audit hook). Atualizações apenas por pacote local assinado. Regras de firewall de saída opcionais no instalador. |
| Nunca executar o que é analisado | Análise estática apenas. Comportamental somente em VM descartável (Windows Sandbox) sem rede; sem isolamento disponível → não executa. |
| Isolamento de falhas | Parsers de formatos hostis (PE, compactados, YARA) rodam em **processos worker** limitados (Job Object, memória máxima, integridade baixa). Uma falha encerra só o worker; o arquivo é marcado como "não analisado: o analisador falhou" e o worker é reiniciado. |
| Evidência, não palpite | Cada achado é uma `Evidence` com fonte, regra, local exato (offset/RVA/seção/linha), confiança qualitativa e nota de falso positivo. Sem porcentagens inventadas. |
| Contexto de jogos | Cracks, emuladores, proxies de DLL e DRM são reconhecidos; só indicadores *esperados* são atenuados, nunca detecções por assinatura. |
| Preservação | Nada é apagado ou movido sem ação explícita do usuário. |

## 2. Processos

```
┌──────────────────────── GameKernel.exe (C++20 + Qt 6 Widgets) ────────────────────────┐
│  UI (Agente B): Dashboard · Game Security · Deep Forensic Analysis · Resultados ·      │
│  Quarentena · Histórico · Tempo real · System Optimizer · Performance Monitor ·        │
│  Offline Update Center · Privacidade/Rede · Configurações                              │
│        │ sinais/slots Qt                                                               │
│  gk_bridge (Agente A): serviços QObject (ScanService, QuarantineService, ...)           │
│        │ API C++ (sem Qt)                                                              │
│  gk_core (Agente A): orquestrador, fila de tarefas, cancelamento, banco SQLite,        │
│  risco, contexto de jogo, quarentena, atualização/integridade, tempo real,             │
│  performance, otimizador                                                               │
└─────────┬───────────────────────────────────┬─────────────────────────────┬───────────┘
          │ IPC (quadros JSON, pipes)          │ processo                    │ IPC JSON-RPC (stdio)
┌─────────▼──────────────┐        ┌───────────▼─────────┐        ┌──────────▼───────────────┐
│ gk-scanworker.exe ×N   │        │ clamscan.exe (lote) │        │ gk-helper.exe (Python    │
│ (C++, Job Object,      │        │ ClamAV oficial      │        │ congelado; Agente B):    │
│ integridade baixa):    │        └─────────────────────┘        │ relatórios, sandbox,     │
│ SHA-256, tipo real, PE,│                                       │ inteligência de ameaças, │
│ Authenticode, YARA,    │                                       │ preparação de pacotes    │
│ compactados, scripts   │                                       └──────────────────────────┘
└────────────────────────┘
```

## 3. Divisão por linguagem (decisão técnica)

| Componente | Linguagem | Motivo |
|---|---|---|
| Orquestração de análise, fila, cancelamento, memória | C++ | Controle de recursos, paralelismo real (sem GIL), integração com Job Objects |
| Leitura de arquivos, SHA-256, tipo real, PE, imports/exports, recursos, Authenticode | C++ | Caminho quente; dados hostis; WinVerifyTrust/CryptoAPI nativas |
| YARA, compactados | C++ (libyara, libarchive) | Bibliotecas nativas maduras; streaming com limites |
| Quarentena | C++ | Criptografia autenticada, DPAPI, controle de ACL e integridade |
| Verificação/instalação de pacotes, integridade da instalação | C++ | Exigência de segurança: validação no núcleo |
| Tempo real, System Optimizer, Performance Monitor | C++ | WinAPI (ReadDirectoryChangesW, PDH, DXGI, Toolhelp) |
| Interface | C++ / Qt 6 Widgets | Nativa, sem navegador; threads/sinais Qt |
| Relatórios (HTML/JSON/PDF) | Python (helper) | Produtividade; reportlab; não é caminho quente |
| Sandbox (Windows Sandbox) | Python (helper) | Orquestração e geração de configuração; sem processamento pesado |
| Preparação de pacotes, assinatura, IOC, regras YARA | Python (ferramentas) | Automação offline do mantenedor |
| Testes (integração, regressão, equivalência, desempenho, FP) | Python (pytest + `gk_native`) | Controle de testes em Python, conforme diretriz |

## 4. Dependências

| Dependência | Uso | Licença | Justificativa |
|---|---|---|---|
| libyara 4.5 | Motor YARA | BSD-3 | Requisito do produto |
| libarchive 3.7 | ZIP/7z/RAR/ISO/CAB/TAR/XZ em memória | BSD-2 | Substitui py7zr/rarfile/pycdlib/7z.exe com uma só biblioteca; streaming com limites |
| libsodium 1.0.18+ | SHA-256, Ed25519 (verificação), XChaCha20-Poly1305 (quarentena), zeragem segura | ISC | Criptografia auditada; nunca implementar primitivas próprias |
| SQLite 3 | Banco local | Domínio público | Requisito |
| nlohmann/json 3.11 | JSON (IPC, configurações, manifestos) | MIT | Header-only, amplamente usado |
| Qt 6 (Core, Gui, Widgets, Svg) | UI e camada de serviços | LGPL-3 | Requisito; **QtNetwork não é usado** |
| pybind11 2.13 | Módulo `gk_native` (testes/automação) | BSD-3 | Integração direta sem processo para testes |
| ClamAV 1.5 (binários oficiais) | Assinaturas | GPL-2 (processo separado) | Requisito; executado como processo independente |
| Windows SDK | wintrust, crypt32, pdh, dxgi, psapi, advapi32, shell32 | — | APIs oficiais |

Gerenciamento: **vcpkg (manifesto `vcpkg.json`) no Windows**, pacotes do sistema no Linux de desenvolvimento.

## 5. Layout do repositório

```
CMakeLists.txt, CMakePresets.json, vcpkg.json, cmake/   build raiz de toda a parte C++ (A)
cpp/core/       gk_core — núcleo sem Qt: hash, tipo real, PE, YARA, compactados e próximos motores (A)
cpp/bindings/   gk_native — módulo pybind11 do núcleo (A)
cpp/ipc/        gk_ipc — cliente gk-ipc v1 em C++/Qt (escrito pelo B, mantido pelo A)
cpp/updates/    gk_updates + gk-update — verificação Ed25519 e instalação atômica de pacotes (escrito pelo B, mantido pelo A)
cpp/worker, cpp/cli, cpp/quarantine, cpp/realtime, cpp/perf, cpp/sysopt, cpp/bridge   (A, próximos passos)
cpp/app/        interface Qt 6 C++ (B)
contracts/      schema.sql, update_package.md, helper_methods.md
gamekernel/     Python: fundação (A); helper, reports, sandbox, intel, rules, updates (B)
signatures/     regras YARA, indicadores gerados, IOCs, chaves públicas
tools/          automação (core_* do A; demais do B)
tests/          foundation, native, corpus_pe (A); helper, integration, corpus (B)
installer/      empacotamento Windows (B)
docs/           documentação
```

## 6. Dados e diretórios (inalterado)

| Caminho | Conteúdo |
|---|---|
| `<instalação>\` | executáveis, `third_party\clamav`, regras base, chaves públicas, `integrity_manifest.json(.sig)` |
| `%LOCALAPPDATA%\GameKernel\` | `gamekernel.db`, `settings.json`, `quarantine\`, `signatures\{active,previous,staging}`, `reports\`, `logs\`, `temp\` |
| Portátil | `.\data\` ao lado do executável (`portable.flag`) |

O formato do banco (`contracts/schema.sql`) e de `settings.json` é o mesmo para C++ e Python.
