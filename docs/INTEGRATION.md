# Game Kernel — Integração C++ ↔ Python

Responsável: **Agente B (Agente 2 — Python, integração e ferramentas)**.
Versão do contrato de integração: **gk-ipc v1** (`PROTOCOL_VERSION = 1`).

Este documento define **como** os componentes C++ (aplicativo Qt 6, núcleo, motores) e os
componentes Python (serviços auxiliares, automação, testes, ferramentas) conversam. Qualquer
mudança aqui exige acordo entre os dois agentes (via usuário) e entrada no `docs/CHANGELOG.md`.

---

## 1. Decisão: dois mecanismos, cada um com um papel

| Direção | Mecanismo | Onde é usado | Por quê |
|---|---|---|---|
| **C++ → Python** (o app usa código Python) | **Processo auxiliar** `gk-helper` + **gk-ipc v1** (JSON enquadrado sobre pipes anônimos) | Relatórios (PDF/HTML/JSON), orquestração da sandbox e futuros serviços Python | **Isolamento de falhas**: um erro, travamento, vazamento de memória ou *segfault* de uma extensão C do Python derruba só o processo auxiliar. O app continua, reporta `helper_crashed`/`timeout` e reinicia o auxiliar. Sem *sockets*, o que é compatível com o modo offline. |
| **Python → C++** (ferramentas e testes usam o núcleo) | **pybind11** (módulo de extensão `gk_native`, a partir das *headers* públicas do núcleo C++ do Agente A) | Test Engine (testes de equivalência Python × C++), ferramentas de automação (ex.: preparação de bases de reputação) | Chamada direta, sem serialização, e o processo hospedeiro é uma ferramenta ou um teste: se cair, não afeta o app. |

**Rejeitado: embutir o interpretador Python no processo do aplicativo** (Python C API ou
`pybind11::embed`). Uma falha do Python (ou de reportlab, yara-python e afins) derrubaria a
interface, o que contraria a regra "não permitir que uma falha de um módulo Python derrube todo o
aplicativo". Também mistura o GIL com as threads do Qt.

**Rejeitado: sockets locais, HTTP local, QtNetwork, QLocalSocket.** A política offline proíbe
módulos de rede; pipes anônimos herdados pelo processo filho bastam.

## 2. Transporte e enquadramento

* O app (host) cria o processo auxiliar com três pipes (stdin, stdout, stderr).
* **Frame** = `uint32` *little-endian* com o tamanho N, seguido de N bytes de JSON UTF-8 (um objeto).
  * `1 ≤ N ≤ max_frame` (padrão **8 MiB**). Um tamanho fora disso é rejeitado **antes** de alocar memória.
  * JSON estrito: sem `NaN`/`Infinity`, UTF-8 válido, raiz obrigatoriamente objeto.
  * Qualquer violação torna o fluxo irrecuperável: quem recebe registra `protocol_error` e fecha o canal.
* **stdout** é exclusivo do protocolo. O auxiliar duplica os fds 0 e 1 para uso privado e redireciona
  o fd 1 para stderr: `print()` ou escrita nativa no fd 1 não corrompem o protocolo (há teste para isso).
* **stderr** é diagnóstico: o host guarda as últimas 50 linhas e as encaminha ao log como `helper.stderr`.
* Inteiros devem ficar em `[-(2^53-1), 2^53-1]`, porque o Qt representa números JSON como `double`.

## 3. Mensagens

Todas têm `proto` (versão *major*) e `type`.

| `type` | Sentido | Campos obrigatórios |
|---|---|---|
| `hello` | auxiliar → host (primeiro frame) | `helper`, `version`, `methods` (lista), `pid`, `netguard` (bool) |
| `request` | host → auxiliar | `id` (inteiro 1…2^53-1), `method` (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`), `params` (objeto), opcional `timeout_ms` |
| `cancel` | host → auxiliar | `id` |
| `event` | auxiliar → host | `id`, `name`, `data` (objeto) — progresso ligado a uma requisição |
| `response` | auxiliar → host | `id`, `ok`; se `ok=true`, `result`; se `ok=false`, `error{code, message, retryable, details}` |
| `log` | auxiliar → host | `level` (`DEBUG|INFO|WARNING|ERROR|CRITICAL`), `logger`, `message` (≤ 4000 caracteres) |

Exemplo:

```json
{"proto":1,"type":"request","id":7,"method":"reports.generate","params":{"scan_id":12,"formats":["html","pdf"]},"timeout_ms":120000}
{"proto":1,"type":"event","id":7,"name":"progress","data":{"stage":"pdf"}}
{"proto":1,"type":"response","id":7,"ok":true,"result":{"files":[{"format":"pdf","path":"…","sha256":"…","size":48211}]}}
```

## 4. Versionamento

* `proto` é a versão *major*. Os dois lados recusam um *major* diferente (`unsupported_version`, canal fechado).
* **Campos desconhecidos são ignorados**, o que permite adições compatíveis sem trocar o *major*.
  **Tipos de mensagem desconhecidos** são erro de protocolo.
* Métodos são versionados pelo nome: uma mudança incompatível cria um método novo (`reports.generate_v2`)
  e o antigo é mantido por pelo menos uma versão do app.
* O `hello` lista os métodos disponíveis. O host verifica se o método existe antes de oferecer a função na interface.

## 5. Códigos de erro (estáveis)

| Código | Significado | `retryable` |
|---|---|---|
| `protocol_error` | frame ou mensagem malformada (canal fechado) | não |
| `unsupported_version` | versão de protocolo incompatível | não |
| `unknown_method` | método não registrado no auxiliar | não |
| `invalid_params` | parâmetros rejeitados pela validação do serviço | não |
| `cancelled` | cancelado pelo host | não |
| `timeout` | prazo excedido (cooperativo ou forçado) | sim |
| `resource_limit` | resultado ou requisição maior que o limite, memória insuficiente | não |
| `not_found` | recurso inexistente (ex.: varredura) | não |
| `io_error` | falha de leitura ou gravação | não |
| `busy` | fila do auxiliar cheia (32 requisições) | sim |
| `internal_error` | exceção inesperada num serviço (o auxiliar **continua ativo**) | não |
| `helper_crashed` | *(gerado pelo host)* o processo auxiliar terminou | sim |
| `helper_unavailable` | *(gerado pelo host)* não foi possível iniciar o auxiliar ou ele falhou demais | sim |

Implementações: `gamekernel/ipc/protocol.py` (`ErrorCode`) e `native/ipc/include/gk/ipc/protocol.hpp` (`error_code::`).

## 6. Ciclo de vida, prazos e recursos

* **Início sob demanda**: a primeira chamada inicia o auxiliar; as chamadas ficam em fila até o `hello` (prazo de 20 s).
* **Processamento sequencial** no auxiliar: uma requisição por vez numa *thread* de trabalho, enquanto a
  *thread* de leitura continua atendendo `cancel`. Para trabalho paralelo, o host inicia mais de um auxiliar.
* **Prazos**: o host envia `timeout_ms`. O serviço verifica `ctx.check()` em seus laços (cancelamento cooperativo).
  Vencido o prazo, o host envia `cancel` e espera `cancelGraceMs` (padrão 5 s). Sem resposta, **mata o
  processo**, responde `timeout` e o próximo pedido usa um auxiliar novo.
* **Reinício**: depois de uma falha, a próxima chamada inicia um auxiliar novo. Após `maxRestarts` (3) falhas
  seguidas, o estado vira `Unavailable` e as chamadas falham com `helper_unavailable` até `resetFailures()`
  (botão "Tentar novamente" na interface). Uma chamada bem-sucedida zera o contador.
* **Encerramento**: o host fecha o stdin; o auxiliar cancela o trabalho pendente e sai (código 0).
  `system.shutdown` faz o mesmo de forma explícita.
* **Limites do processo auxiliar**:
  * Windows: **Job Object** atribuído na criação (`PROC_THREAD_ATTRIBUTE_JOB_LIST`) com
    `KILL_ON_JOB_CLOSE` (o auxiliar morre junto com o app, inclusive numa falha do app),
    limite de memória (padrão 2 GiB), `DIE_ON_UNHANDLED_EXCEPTION` e restrições de UI
    (sem área de transferência, sem trocar *desktop*, sem alterar parâmetros do sistema). `CREATE_NO_WINDOW`.
  * Linux (desenvolvimento e CI): `RLIMIT_AS` e `PR_SET_PDEATHSIG(SIGKILL)`.
* **Ambiente sanitizado**: só variáveis essenciais do sistema mais `GAMEKERNEL_DATA_DIR`; nenhuma `PYTHON*`
  nem *proxy*. O auxiliar Python roda com `-I` (modo isolado) no desenvolvimento e instala o `netguard`
  antes de qualquer outro *import*.
* **Caminho absoluto obrigatório** para o executável do auxiliar; o diretório de trabalho é o do próprio auxiliar.

## 7. Logs

O auxiliar não grava o arquivo de log do app (dois processos rotacionando o mesmo arquivo falham no Windows).
Os registros do `logging` (nível INFO ou acima) viram frames `log`, e o host os grava no log local com o
prefixo do *logger*. O stderr do auxiliar também vai para o log (`helper.stderr`).

## 8. Métodos disponíveis (v1)

| Método | Descrição | Implementação |
|---|---|---|
| `system.ping` | teste de vida (`{"echo": …}`) | `gamekernel/ipc/helper.py` |
| `system.info` | versão, protocolo, Python, `netguard`, métodos | `gamekernel/ipc/helper.py` |
| `system.shutdown` | encerra após responder | `gamekernel/ipc/helper.py` |
| `reports.generate` | gera o relatório forense de uma varredura (ver abaixo) | `gamekernel/ipc/services/reports.py` |
| `reports.formats` | formatos disponíveis (`pdf` só se o reportlab estiver presente) e pasta padrão | `gamekernel/ipc/services/reports.py` |

### `reports.generate`

Parâmetros (qualquer parâmetro desconhecido é rejeitado com `invalid_params`; `details.field` indica o campo):

| Campo | Tipo | Padrão | Observação |
|---|---|---|---|
| `scan_id` | inteiro > 0 | — (obrigatório) | id da tabela `scans` |
| `formats` | lista de `json`, `html`, `pdf` | `["html","json"]` | |
| `output_dir` | caminho absoluto, pasta existente | `<dados>/reports` | os arquivos são gravados de forma atômica |
| `include_clean` | bool | `false` | lista também os arquivos sem indicadores (limite de 20 000) |
| `redact_username` | bool | `settings.reports.redact_username` (true) | troca o segmento do usuário nos caminhos por `<usuário>` |
| `include_hostname` | bool | `settings.reports.include_hostname` (false) | |
| `db_path` | caminho absoluto | `<dados>/gamekernel.db` | aberto **somente para leitura** (`PRAGMA query_only`); nunca é criado |

Eventos: `progress` com `data.stage` ∈ `load`, `json`, `html`, `pdf`.
Resultado: `{"scan_id", "files": [{"format","path","size","sha256"}], "counts": {…}, "max_risk": {…}, "warnings": […]}`.
Erros: `invalid_params`, `not_found` (banco ou varredura), `io_error`, `cancelled`, `timeout`.

## 9. Componentes

| Lado | Arquivo | Papel |
|---|---|---|
| Python | `gamekernel/ipc/protocol.py` | enquadramento, validação, construtores, códigos de erro |
| Python | `gamekernel/ipc/helper.py` | *runtime* do auxiliar: despacho, cancelamento, prazos, ponte de log, proteção de stdio |
| Python | `gamekernel/ipc/services/` | registro de serviços (falha de *import* aparece no log e em `system.info`) |
| Python | `gamekernel/ipc/client.py` | cliente Python (testes, ferramentas) |
| Python | `gk_helper.py` | ponto de entrada (`gk-helper.exe` quando congelado com PyInstaller) |
| C++ | `native/ipc/include/gk/ipc/protocol.hpp`, `src/protocol.cpp` | decodificador incremental, validação, construtores |
| C++ | `native/ipc/include/gk/ipc/helper_client.hpp`, `src/helper_client.cpp` | `gk::ipc::HelperClient` (QObject + QProcess, sinais/slots, Job Object) |
| Testes | `tests/ipc/` | protocolo e processo auxiliar real, com falhas provocadas (`fault_helper.py`) |
| Testes | `native/ipc/tests/tst_ipc.cpp` + `tests/native/test_native_ipc.py` | cliente C++ contra os auxiliares Python reais, controlado pelo pytest |

### Uso no aplicativo (C++)

```cpp
auto cfg = gk::ipc::HelperConfig::forInstallation(QCoreApplication::applicationDirPath(), dataDir);
auto* helper = new gk::ipc::HelperClient(cfg, this);
connect(helper, &gk::ipc::HelperClient::callSucceeded, this, &ReportsPage::onReportReady);
connect(helper, &gk::ipc::HelperClient::callFailed, this, &ReportsPage::onReportFailed);
connect(helper, &gk::ipc::HelperClient::eventReceived, this, &ReportsPage::onProgress);
connect(helper, &gk::ipc::HelperClient::logReceived, logger, &Logger::fromHelper);
const qint64 id = helper->call("reports.generate", {{"scan_id", scanId}, {"formats", QJsonArray{"html", "pdf"}}}, 120000);
```

## 10. Contratos de dados

* **Resultados de análise**: o formato JSON de `Evidence`, `Location`, `FileResult`, `FileFeatures` e
  `ScanSummary` é o de `to_dict()` em `gamekernel/core/models.py` e `scan_api.py` (fundação). As estruturas
  C++ do núcleo (Agente A) devem produzir **o mesmo JSON**. Os testes de equivalência (etapa B6) fazem a
  ida e volta `C++ → JSON → FileResult.from_dict → to_dict` e comparam campo a campo.
* **Banco SQLite**: o esquema de `gamekernel/database/db.py` é contrato. Quem grava é o núcleo
  (C++). Os serviços Python o abrem **somente para leitura** (`PRAGMA query_only=ON`).
* **Pacotes de atualização** (`.gkpkg`) e **IOC** (`gamekernel-ioc`): ver `docs/OFFLINE_UPDATES.md` (etapa B4).
