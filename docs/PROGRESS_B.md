# Progresso — Agente B (Agente 2: Python, integração e ferramentas)

Branch: `claude/stoic-mayer-r46kuo` (criada a partir de `origin/claude/magical-bell-fi6jw1`, commit `fd1aa22`).

> **Mudança de diretriz (2026-11-12):** o projeto passa a usar uma arquitetura híbrida
> **C++20 + Qt 6 (núcleo e interface) / Python 3 (automação, integração, testes, relatórios)**.
> O Agente B passa a ser o **Agente 2 — Python, integração e ferramentas**.

---

## ETAPA 1 — Auditoria do estado real (2026-11-12)

| Item | Estado encontrado |
|---|---|
| Branches remotas | só `claude/magical-bell-fi6jw1` (fundação, `fd1aa22`). O Agente A ainda não publicou motor nenhum. |
| Código | **Só a fundação**, em Python (~3,1 mil linhas): caminhos, configurações, `netguard`, logs, Ed25519, modelos, contrato do scanner, catálogo de ameaças, tipos de arquivo, *hashing* e banco SQLite. |
| Não implementado | scanner e motores (A); interface, quarentena, atualizações, relatórios, sandbox, tempo real e empacotamento (B). Nenhuma linha da parte do B existia antes desta etapa. |
| Testes | `tests/foundation/`: 23 testes, todos passando. |
| Ambiente validado | Python 3.13, GCC 13, Clang 18, CMake 3.28, Ninja, Qt 6.4 (`qt6-base-dev`), pybind11 2.11, libsodium 1.0.18, ClamAV 1.5.4, 7-Zip. PowerShell **não** disponível (o *download* foi bloqueado pela política do ambiente). |

Conclusão: como quase nada além da fundação existe, a migração para a arquitetura híbrida custa pouco
**agora**. Nenhuma funcionalidade implementada é apagada.

## ETAPAS 2–3 — Mapeamento e classificação dos módulos

### Módulos existentes (fundação, Python)

| Módulo | Responsabilidade | Decisão | Justificativa técnica |
|---|---|---|---|
| `app_paths.py` | diretórios (instalado, portátil, dev) | **Mantido em Python** (auxiliar e ferramentas). O núcleo C++ precisa de um equivalente com a mesma regra (`portable.flag`, `GAMEKERNEL_DATA_DIR`). | O layout de dados é contrato; as duas linguagens o leem. |
| `config.py` | `settings.json` | **Mantido em Python** para ferramentas e auxiliar; o app C++ lê e grava o mesmo JSON. | O formato é contrato; a validação deve existir nos dois lados. |
| `netguard.py` | bloqueio de rede (*audit hook*) | **Mantido em Python**: protege todo processo Python do produto (auxiliar). No C++ a garantia é **por construção** (sem QtNetwork, WinHTTP, WinINet ou ws2_32), verificada por auditoria de *imports* dos binários no *build*. | *Audit hooks* só existem em Python. |
| `logging_setup.py` | log local rotativo | Mantido para ferramentas. No auxiliar, os logs viram frames `log` e quem grava é o host. | Dois processos rotacionando o mesmo arquivo falham no Windows. |
| `crypto_utils.py` | Ed25519 | **Mantido em Python** do lado do publicador (gerar chaves, assinar). A **verificação no app migra para C++** (libsodium), com teste de equivalência Python × C++. | Diretriz: validação criptográfica no núcleo C++. O CNG do Windows não oferece Ed25519. |
| `core/models.py`, `core/scan_api.py` | contratos de dados | **Mantidos como referência do contrato JSON**; o C++ espelha as estruturas e testes de ida e volta garantem a equivalência. | Evita dois contratos divergentes. |
| `core/threat_catalog.py` | textos de ameaças | Mantido em Python (relatórios). **Proposta:** exportar para um JSON de recursos lido pela UI C++, sem duplicar os textos. | "Não duplicar módulos". |
| `core/filetypes.py` | tipo real do arquivo | **Migrar para C++ (Agente A, File Analysis Engine).** A versão Python fica como **oráculo** dos testes de equivalência até a validação. | Hot path do núcleo. |
| `core/hashing.py` | SHA-256 em *streaming* | **C++ no núcleo (A).** Python continua nas ferramentas. | O `hashlib` já é C (OpenSSL): migrar as *ferramentas* não traria ganho real; o núcleo C++ precisa do próprio. |
| `database/db.py` | SQLite (WAL) | O **esquema é contrato**. Grava: núcleo C++ (A). Lê: serviços Python, **somente leitura**. | Um único escritor reduz o risco de corrupção. |

### Planejados e ainda sem código: novo destino

| Componente | Antes | Agora | Dono proposto |
|---|---|---|---|
| Scanner, motores, contexto de cracks | Python | **C++** (Core Engine + File Analysis Engine; YARA e ClamAV via libyara/libclamav ou `clamscan`) | A |
| Quarentena | Python (B) | **C++** Quarantine Engine | **A** (sai do escopo do B; nada havia sido escrito) |
| Tempo real | Python (A) | **C++** (`ReadDirectoryChangesW`) | A |
| System Optimizer, Performance Monitor | — | **C++** (WinAPI, PDH, DXGI) | A |
| Interface | PySide6 (B) | **Qt 6 C++** | **a confirmar** (pendência P2) |
| Atualizações offline | Python (B) | preparação em **Python** + verificação e instalação em **C++** (`native/updates`, libsodium) | B |
| Relatórios forenses | Python (B) | **Python**, executado no processo auxiliar via gk-ipc | B |
| Sandbox | Python (B) | **Python** no processo auxiliar (orquestração) + `monitor.ps1` dentro da VM | B |
| Threat Intelligence | — | **Python** (normalização, deduplicação, preparação de bases) | B |
| Ferramentas, testes, CI e empacotamento | Python/PyInstaller (B) | Python + CMake + `windeployqt` + PyInstaller (auxiliar) + Inno Setup | B |

## ETAPA 4 — Contratos C++/Python

Definidos em [`docs/INTEGRATION.md`](INTEGRATION.md):

* **C++ → Python**: processo auxiliar `gk-helper` + **gk-ipc v1** (pipes, JSON enquadrado, versão *major*,
  erros estáveis, prazos, cancelamento, reinício, Job Object). **Nunca** Python embutido no processo do app.
* **Python → C++**: **pybind11** (`gk_native`) para testes e ferramentas, quando as *headers* do núcleo existirem.
* **Dados**: o JSON de `models.py` é o contrato; o esquema SQLite é o contrato; os formatos `.gkpkg` e IOC vêm na etapa B4.

---

## Plano de refatoração do Agente B (etapas verificáveis)

| # | Etapa | Estado |
|---|---|---|
| B1 | Auditoria, classificação e contratos (este documento + `INTEGRATION.md`) | ✅ |
| B2 | gk-ipc v1: auxiliar Python, cliente Python, **cliente C++/Qt**, testes cruzados controlados pelo pytest | ✅ |
| B3 | Relatórios forenses (JSON, HTML autocontido, PDF) como serviço do auxiliar + `sysinfo` | ✅ |
| B4 | Atualização offline: formato `.gkpkg`, preparação e assinatura em Python, **verificação e instalação atômica em C++** (libsodium), testes de equivalência e adulteração | ⏳ |
| B5 | Threat Intelligence: normalização e deduplicação de IOC, conflitos, preparação e *lint* de regras YARA, relatório de atualização | ⏳ |
| B6 | Bindings pybind11 do núcleo C++ e testes de equivalência Python × C++ (depende das *headers* do A) | aguardando A |
| B7 | Sandbox (orquestração no auxiliar + `monitor.ps1`) | ⏳ |
| B8 | CI (Linux + Windows/MSVC), PyInstaller do auxiliar, CMake/`windeployqt`, Inno Setup, versão portátil | ⏳ |
| B9 | Interface Qt 6 C++, se confirmada como responsabilidade do B | pendência P2 |

## B2 — gk-ipc v1 ✅

**Implementado**
* `gamekernel/ipc/protocol.py`: enquadramento (`uint32 LE` + JSON UTF-8), limite de 8 MiB verificado antes
  de alocar, JSON estrito, validação de envelope, códigos de erro estáveis.
* `gamekernel/ipc/helper.py`: *runtime* do auxiliar, com *thread* de leitura (atende `cancel` na hora),
  *thread* de trabalho sequencial, prazos cooperativos, ponte `logging` → frames `log` e proteção de stdio
  (fds 0 e 1 duplicados, fd 1 redirecionado para stderr). Uma exceção num serviço vira `internal_error` e o auxiliar continua ativo.
* `gamekernel/ipc/client.py`: cliente Python (testes e ferramentas) com ambiente sanitizado, prazo, cancelamento,
  morte do auxiliar travado e reinício transparente.
* `gk_helper.py`: ponto de entrada (`netguard.install()` antes de qualquer outro *import*).
* `native/ipc/` (**C++20 + Qt 6 Core**): `FrameDecoder` incremental, `validateMessage`, `gk::ipc::HelperClient`
  (QProcess, sinais e slots, fila até o `hello`, prazo → `cancel` → morte após carência, reinício com limite
  de falhas seguidas, Job Object no Windows, `RLIMIT_AS` + `PDEATHSIG` no Linux).

**Testado**
* `tests/ipc/test_protocol.py`: 30 casos de enquadramento e envelope (truncado, gigante, UTF-8 inválido, `NaN`,
  versão errada, ids inválidos etc.).
* `tests/ipc/test_helper_process.py`: 16 testes com processo real: exceção, erro estruturado, escrita no stdout,
  eventos, resultado grande demais, resultado não serializável, prazo cooperativo, serviço travado (morto e
  reiniciado), *crash* duro (`os._exit`), rede bloqueada no auxiliar, EOF, `shutdown` e violação de protocolo.
* `native/ipc/tests/tst_ipc.cpp`: **34 testes C++ (QtTest)** contra os auxiliares Python reais, incluindo
  20 chamadas concorrentes, limite de memória, indisponibilidade após falhas repetidas e caminho relativo recusado.
  Controlados pelo pytest em `tests/native/test_native_ipc.py`.
* **AddressSanitizer + UBSan**: 34/34, sem erros nem vazamentos.

**Resultados**: `pytest -q` → **70 passed** (23 da fundação + 46 do IPC + 1 driver nativo com 34 testes C++).

**Problemas encontrados e corrigidos**
1. `system.shutdown` não encerrava o auxiliar: a leitura bloqueante impedia a saída. A leitura foi para uma
   *thread* própria e a principal agora espera o sinal de parada.
2. Um prazo vencido aparecia como `cancelled`, e não como `timeout`. O cliente agora sabe que foi ele quem cancelou por prazo.
3. **C++**: depois de matar um auxiliar travado, a chamada seguinte ia para o processo que ainda estava morrendo.
   Agora o processo é "aposentado" (`retire()`) na hora.
4. **C++**: uma falha emitida de forma síncrona dentro de `call()`, antes de o chamador receber o id, travava o
   `callBlocking`. Agora as falhas nunca são emitidas de forma síncrona (`failAllLater`).

## B3 — Relatórios forenses ✅

**Decisão de linguagem**: **Python**, executado no processo auxiliar. Motivos: o reportlab é maduro para PDF
(tabelas, quebra de página, fontes Unicode), a lógica de relatório muda com frequência e não está no caminho
crítico de desempenho, e o isolamento em processo separado impede que uma falha na geração derrube o app.

**Implementado**
* `gamekernel/core/sysinfo.py`: informações mínimas do computador (SO e build com aviso de fim de suporte do
  Windows 10, arquitetura, CPU, núcleos, memória, fuso). **Nunca** coleta usuário, MAC, IP ou número de série;
  o nome do computador só entra com opção explícita.
* `gamekernel/core/report_engine.py`: modelo `gamekernel-report` v1 com as 15 seções exigidas, mais o
  **relatório individual de cada crack** (tipo de modificação, assinatura, riscos potenciais, possibilidade de
  falso positivo, recomendação). Lê o banco com `PRAGMA query_only` (nunca cria nem altera), aplica `Redactor`
  (troca só segmentos de caminho inteiros) e grava de forma atômica, com SHA-256 de cada arquivo gerado.
  Distingue localização física (arquivo/contêiner) da localização da evidência (seção, offset, RVA, linha,
  trecho) e marca indicadores genéricos como "não é o código malicioso exato".
* `gamekernel/core/report_html.py`: HTML autocontido, **sem JavaScript**, CSP `default-src 'none'`, tudo
  escapado (testado com um arquivo chamado `<script>alert(1)</script>.dll`), tema claro/escuro e impressão.
* `gamekernel/core/report_pdf.py`: PDF com reportlab e fonte Unicode (Segoe UI/Arial no Windows, DejaVu no
  Linux); sem fonte Unicode, avisa que houve substituição de caracteres.
* `gamekernel/ipc/services/reports.py`: serviços `reports.generate` (validação estrita de parâmetros, eventos
  de progresso, cancelamento cooperativo) e `reports.formats`.

**Testado**
* `tests/reports/test_reports.py`: 26 testes (todas as seções, localização de evidência, membro de compactado →
  arquivo físico, relatórios de crack, redação e opção de incluir dados, escape/CSP, PDF com várias páginas,
  escrita atômica com hash, banco somente leitura, banco inexistente não é criado, parâmetros inválidos, serviço
  via processo auxiliar real com progresso).
* `native/ipc/tests/tst_ipc.cpp::reportServiceEndToEnd`: o **cliente C++** pede o relatório ao auxiliar Python
  real e confere tamanho e SHA-256 de cada arquivo gerado.
* Inspeção visual do HTML (Chromium) e do PDF (pdftoppm): layout correto, sem cortes.
* ASan/UBSan: 35/35.

**Resultado**: `pytest -q` → **96 passed**.

**Arquivos do B adicionados em `gamekernel/core/`** (registrar no `WORK_SPLIT.md`): `report_engine.py`,
`sysinfo.py` (já eram do B), `report_html.py` e `report_pdf.py` (novos).

---

## Pendências e decisões que dependem do usuário

* **P1 — Nome do produto.** A diretriz fala em "OFFLINE GAME GUARD", mas o título dela e o projeto usam
  **Game Kernel**. Mantive *Game Kernel* em todos os identificadores até haver confirmação.
* **P2 — Dono da interface Qt 6 C++.** Antes era do B (PySide6). A nova diretriz não a atribui a nenhum agente.
  Proposta: **B mantém a interface**, agora em C++ consumindo o núcleo do A, para preservar a divisão (regra 8).
* **P3 — Propriedade dos novos documentos.** Proposta para evitar conflitos: **A** — `ARCHITECTURE.md` (já é dono),
  `MODULES.md`, `MIGRATION_PLAN.md`, `SECURITY.md`; **B** — `INTEGRATION.md`, `BUILD.md`, `TESTING.md`, `CHANGELOG.md`.
* **P4 — Árvore `native/`.** Proposta: A é dono de `native/CMakeLists.txt` (raiz) e de `native/core/**`,
  `native/analysis/**`, `native/quarantine/**`, `native/sysopt/**`, `native/perf/**`; B é dono de `native/ipc/**`,
  `native/updates/**`, `native/bindings/**`. Cada subprojeto do B compila sozinho e entra na raiz por `add_subdirectory()`.
* **P5 — Arquivos da fundação.** `docs/WORK_SPLIT.md`, `docs/ARCHITECTURE.md`, `requirements*.txt` e `pyproject.toml`
  precisam refletir a arquitetura híbrida (dependências novas: pybind11 no desenvolvimento, libsodium e Qt 6
  no nativo). **Não os alterei**: são congelados e precisam de acordo entre os agentes.
* **P6 — `signatures/keys/`** (chave pública de *release*) não tem dono. A chave privada nunca é versionada;
  o *build* copia a chave pública do publicador.
