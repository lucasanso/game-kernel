# Progresso — Agente B (Agente 2: Python, integração e ferramentas)

Branch: `claude/stoic-mayer-r46kuo`. Base: `claude/magical-bell-fi6jw1` (fundação `fd1aa22` + arquitetura
híbrida do Agente A `3de964f`, mesclada nesta branch). Divisão vigente: **`docs/WORK_SPLIT.md` rev. 2**.

## Estado atual (2026-11-12)

`pytest -q` na árvore mesclada, com o `gk_native` do A compilado: **304 passed, 1 skipped** (auxiliar
congelado, executado na CI). Sem o `gk_native`: 229 passed, 76 skipped (testes do A).
Com `GK_NATIVE_SANITIZE=1` (ASan + UBSan nos binários C++ do B): `tests/helper` + `tests/integration` → 205 passed.

| Etapa | Entrega | Estado |
|---|---|---|
| B1 | Auditoria, classificação de módulos, plano | ✅ |
| B2 | Integração C++ ↔ Python por processo auxiliar (servidor Python, cliente Python, cliente C++/Qt de referência) | ✅ (envelope do A §3 adotado) |
| B3 | Relatórios forenses (JSON, HTML, PDF) como serviço do auxiliar | ✅ |
| B4 | Atualização offline: formato `.gkpkg`, preparação e assinatura (Python), verificador e instalador C++ de referência | ✅ |
| B5 | Inteligência de ameaças: IOC, regras YARA, relatório de atualização | ✅ |
| B6 | Testes de equivalência sobre o `gk_native` do A | depende das próximas APIs do A (M2+) |
| B7 | Sandbox (Windows Sandbox sem rede) como serviço do auxiliar | ✅ (sem VM no Linux; `monitor.ps1` verificado só estaticamente) |
| B8 | CI Linux + Windows/MSVC, auxiliar congelado | ✅ parte 1 (workflow publicado; resultado do Windows a confirmar) |
| B9 | Interface Qt 6 C++ (`cpp/app/**`) | ⏳ próxima; depende do `cpp/bridge` (A, M13) para os serviços do núcleo |
| B10 | Instalador Inno Setup, versão portátil, docs de usuário (README, INSTALL, USAGE, PRIVACY, LIMITATIONS) | ⏳ depende do executável da UI |

## Auditoria e decisões de linguagem (B1)

Ver também `docs/MIGRATION_PLAN.md` (Agente A), que cobre os módulos do núcleo. Do lado do B:

| Componente | Linguagem | Justificativa |
|---|---|---|
| Relatórios | **Python** (no processo auxiliar) | reportlab é maduro para PDF; a lógica muda com frequência; fora do caminho crítico; isolamento por processo |
| Sandbox | **Python** (no auxiliar) + PowerShell na VM | orquestração longa e bloqueante, *parsing* de dados escritos dentro da VM; isolado do app |
| Preparação de pacotes, IOC, YARA | **Python** | automação de publicador, fora do app (diretriz §3) |
| Verificação e instalação de pacotes | **C++** | diretriz: controles de segurança no núcleo C++. Implementação de referência do B em `native/updates`; o dono no núcleo é o A (M10) |
| Cliente do auxiliar | **C++/Qt** | o app é C++. Cliente de referência do B em `native/ipc`; o de produção é do A (`cpp/bridge`, M13) |
| Python embutido no processo do app | **rejeitado** | uma falha do Python derrubaria a interface |

## B2 — Processo auxiliar (`gamekernel/helper/`)

* `protocol.py`: quadros (uint32 LE + JSON UTF-8, ≤ 64 MiB, validado antes de alocar), **envelope do
  `INTEGRATION.md` §3** (`v`, códigos inteiros), extensões opcionais (`cancel`, `timeout_ms`, `event.id`,
  `error.data.reason/retryable/field`) documentadas em `contracts/helper_methods.md`.
* `server.py`: *thread* de leitura (cancelamento imediato) e de trabalho (sequencial), prazos cooperativos,
  logs como eventos `log`, proteção de stdio (fds duplicados, fd 1 → stderr). Exceção → `1099`, e o auxiliar continua.
* `client.py` (Python) e `native/ipc` (C++/Qt): ambiente sanitizado, prazo → cancelamento → morte após carência,
  reinício limitado (3 falhas seguidas), Job Object (`KILL_ON_JOB_CLOSE`, limite de memória, restrições de UI)
  atribuído na criação via `PROC_THREAD_ATTRIBUTE_JOB_LIST`; `RLIMIT_AS` e `PDEATHSIG` no Linux.
* `entry.py`: ponto de entrada (`gk-helper.exe`), `netguard.install()` antes de qualquer *import*.

Problemas encontrados e corrigidos: `system.shutdown` não destravava a leitura bloqueante; prazo vencido
aparecia como "cancelado"; no C++, chamada nova ia para o processo travado ainda morrendo (`retire()`) e uma
falha emitida de forma síncrona dentro de `call()` travava o `callBlocking` (`failAllLater`).

## B3 — Relatórios (`gamekernel/reports/`)

`engine.py` (modelo `gamekernel-report` v1, 15 seções + relatório individual de cracks, `Redactor`, banco com
`PRAGMA query_only`, gravação atômica com SHA-256), `render_html.py` (sem JavaScript, CSP `default-src 'none'`,
tudo escapado), `render_pdf.py` (reportlab, fonte Unicode), `sysinfo.py` (sem usuário, MAC, IP ou número de
série; nome do computador só com opção). Inspeção visual do HTML (Chromium) e do PDF (pdftoppm).

## B4/B5 — Atualização offline e inteligência de ameaças

* Contrato: `contracts/update_package.md` (formato, ordem de verificação, códigos de erro, semântica de
  instalação, `gamekernel-signatures`, `gamekernel-ioc`, chaves).
* Python: `gamekernel/updates/package.py` (construtor e verificador de referência), `gamekernel/updates/prepare.py`
  (bloqueio antes de assinar, inclusive com os validadores C++, e relatório de atualização),
  `gamekernel/intel/ioc.py`, `gamekernel/rules/prepare.py`; ferramentas `tools/gk_keygen.py`,
  `tools/make_update_package.py`, `tools/ti_build_ioc.py`.
* C++ de referência: `native/updates` (libsodium, libyara, Qt Core): verificação em passagem única sem TOCTOU,
  compilação real de YARA (`include` recusado), checagem do CVD (cabeçalho e MD5), IOC, instalador atômico
  (trava, *downgrade*, manutenção de componentes, troca `active`/`previous`, rollback, recuperação após queda).
* Correções encontradas pelos testes de equivalência: `$` em regex aceitava `\n` final (agora `fullmatch`/`\z`
  nos dois lados); regra de inteiro JSON alinhada ao Qt; nomes de dispositivo do Windows recusados;
  códigos de saída do ASan distintos da rejeição.

## B7 — Sandbox (`gamekernel/sandbox/`)

`manager.py`: recusa sem isolamento real; `.wsb` sem rede, GPU, áudio, vídeo, impressora ou área de
transferência, com entrada somente leitura; a amostra fica no host apenas como `sample.bin`; prazo e
cancelamento descartam a VM; o relatório da VM é lido de forma defensiva; o mapeamento gera evidências
comportamentais com notas de falso positivo e limitações honestas. `monitor.ps1`: só ASCII, auditoria por
GUID (independente do idioma), iscas de credenciais com SACL, documentos-isca, comparação antes/depois,
árvore de processos (4688), leituras de iscas (4663), DNS/WFP e Sysmon opcional. **Não executado aqui
(Linux, sem PowerShell)**: o CI Windows pode validar a sintaxe; a execução real exige o Windows Sandbox.

## Alinhamento à `WORK_SPLIT.md` rev. 2 (feito nesta etapa)

* Branch do A mesclada; conflitos `docs/INTEGRATION.md` e `docs/TESTING.md` resolvidos com a versão do A
  (dono). Meu `docs/CHANGELOG.md` foi incorporado à seção "Agente B" do `CHANGELOG.md` da raiz.
* Código movido para os caminhos do B: `gamekernel/helper`, `gamekernel/reports`, `gamekernel/sandbox`,
  `gamekernel/intel`, `gamekernel/rules`; testes para `tests/helper`, `tests/integration`, `tests/corpus`.
  Nada foi deixado em `tests/native/**` (do A).
* O envelope IPC passou a seguir o §3 do A (antes eu usava um envelope próprio).
* Seções do B preenchidas em `docs/TESTING.md`, `docs/BUILD.md` e `CHANGELOG.md`; novos `contracts/update_package.md`
  e `contracts/helper_methods.md`.

## Pendências que dependem do usuário ou do Agente A

1. **Sobreposição com o A**: `native/ipc` (cliente do auxiliar) e `native/updates` (verificação e instalação
   de pacotes) foram feitos e testados **antes** de eu ver a revisão 2, que atribui esses papéis ao A (M13 e M10).
   Não os apaguei (regra: não remover funcionalidade testada). Proposta: o A adota esse código em
   `cpp/bridge`/`cpp/core` e depois eu removo `native/`; ou o A escreve o seu e eles ficam só como
   referência de teste. **Decisão do usuário/A**, para evitar módulos duplicados.
2. **Nome do produto**: a diretriz fala em "OFFLINE GAME GUARD"; o projeto e a diretriz (no título) usam "Game
   Kernel". Mantive "Game Kernel".
3. **Contrato IPC**: proposta de incluir `-32602` (parâmetros inválidos) no §3; as extensões opcionais estão em
   `contracts/helper_methods.md` e precisam da revisão do A.
4. **`contracts/helper_methods.md`**: o §3 da rev. 2 cita `contracts/ipc.md` (A) para os métodos. Criei um
   arquivo separado para não editar o do A; o A pode incorporá-lo ou referenciá-lo.
5. **Dependências** a registrar pelo A em `vcpkg.json`/`requirements*.txt` (arquivos dele): libyara para a
   validação de pacotes (já usada pelo M3), pybind11 no `requirements-dev.txt` (o build do `gk_native` exige),
   aqtinstall (só na CI do B).
6. **`signatures/keys/`**: a chave pública de *release* é copiada no *build*; a privada nunca é versionada.
7. **Falha no Windows em arquivo da fundação (dono: A)**: `tests/foundation/test_db.py::test_corrupt_database_is_recovered`
   falha no Windows (já falhava na branch do A, no `core-ci`). Causa: em `gamekernel/database/db.py`, `_connect()` abre
   a conexão e executa `PRAGMA journal_mode=WAL`, que lança `DatabaseError` num arquivo corrompido **sem fechar a
   conexão**. O *handle* continua aberto, e `_recover()` não consegue renomear nem apagar o arquivo
   (`WinError 32`; no Linux, renomear um arquivo aberto é permitido). Correção sugerida: em `_connect`, fechar
   `conn` num `except BaseException` antes de relançar. Enquanto isso, o job Windows da minha CI também fica
   vermelho por causa desse teste. Não o pulei (regra: nunca desativar testes para ficar verde).
