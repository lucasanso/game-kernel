# Contrato — métodos do processo auxiliar Python (`gk-helper`)

Escrito pelo Agente B (servidor: `gamekernel/helper/`). O envelope, os quadros e os códigos de erro são os
de `docs/INTEGRATION.md` §3 (Agente A). O cliente de produção é o `HelperClient` de `cpp/bridge` (Agente A).
O cliente C++ de referência em `native/ipc/` e o cliente Python em `gamekernel/helper/client.py` são usados
nos testes de integração (`tests/helper/`, `tests/integration/test_cpp_helper_client.py`).

## 1. Execução

* Produção: `<instalação>/helper/gk-helper.exe` (PyInstaller, *one-folder*, subsistema console iniciado com
  `CREATE_NO_WINDOW`). Desenvolvimento: `python -I gamekernel/helper/entry.py`.
* Ambiente: só variáveis essenciais do sistema mais `GAMEKERNEL_DATA_DIR` (nenhuma `PYTHON*` ou *proxy*).
  Diretório de trabalho: a pasta do auxiliar.
* `netguard` é instalado antes de qualquer outro *import*: o auxiliar não consegue abrir conexões.
* O stdout é exclusivo do protocolo: o auxiliar duplica os fds 0 e 1 e redireciona o fd 1 para stderr, então
  `print()` ou escrita nativa não corrompem o canal.
* Requisições são atendidas **uma por vez** (fila de até 32; cheia → `1002`/`busy`), enquanto a leitura
  continua aceitando cancelamentos.
* Fim do stdin → cancela o trabalho pendente e sai com código 0. Violação de protocolo → código 2.

## 2. Extensões opcionais ao envelope (compatíveis com §3: quem não as conhece as ignora)

| Extensão | Direção | Uso |
|---|---|---|
| `request.timeout_ms` | pai → filho | o serviço interrompe o trabalho de forma cooperativa e responde `1003` |
| `{"v":1,"type":"cancel","id":N}` | pai → filho | cancela a requisição N (`1004`) |
| `event.id` | filho → pai | id da requisição a que o evento pertence |
| `hello.methods`, `hello.pid`, `hello.netguard` | filho → pai | métodos disponíveis, PID e estado do bloqueio de rede |
| `error.data.reason`, `error.data.retryable` | filho → pai | motivo estável, mais fino que o código (tabela abaixo) |
| `error.data.field` | filho → pai | parâmetro rejeitado |

| `reason` | `code` | `retryable` |
|---|---|---|
| `protocol_error`, `invalid_params` | -32600 | não |
| `unknown_method` | -32601 | não |
| `not_found`, `io_error` | 1001 | não |
| `resource_limit` | 1002 | não |
| `busy` | 1002 | sim |
| `timeout` | 1003 | sim |
| `cancelled` | 1004 | não |
| `invalid_format` | 1005 | não |
| `internal_error` | 1099 | não (exceção num serviço; **o auxiliar continua ativo**) |

**Proposta ao Agente A**: incluir `-32602` (parâmetros inválidos, padrão JSON-RPC) na lista do §3. Hoje,
parâmetros inválidos usam `-32600` com `data.reason = "invalid_params"`.

## 3. Métodos (versão 1)

Parâmetros desconhecidos são rejeitados (`invalid_params` com `data.fields`).

### `system.ping` → `{"pong": true, "echo": <params.echo>}`
### `system.info` → `{"component", "version", "protocol", "python", "frozen", "pid", "netguard", "network_blocked_attempts", "methods": {nome: descrição}}`
### `system.shutdown` → `{"stopping": true}`; o auxiliar encerra depois de responder.

### `reports.generate`
| Parâmetro | Tipo | Padrão |
|---|---|---|
| `scan_id` | inteiro > 0 | obrigatório |
| `formats` | lista de `json`, `html`, `pdf` | `["html","json"]` |
| `output_dir` | caminho absoluto existente | `<dados>/reports` |
| `include_clean` | bool | `false` |
| `redact_username` | bool | `settings.reports.redact_username` (`true`) |
| `include_hostname` | bool | `settings.reports.include_hostname` (`false`) |
| `db_path` | caminho absoluto | `<dados>/gamekernel.db` (aberto com `PRAGMA query_only`; nunca é criado) |

Eventos: `progress` com `data.stage` ∈ `load`, `json`, `html`, `pdf`.
Resultado: `{"scan_id", "files": [{"format","path","size","sha256"}], "counts": {…}, "max_risk": {"level","label","meaning"}, "warnings": […]}`.
Erros: `invalid_params`, `not_found` (banco ou varredura), `io_error`, `cancelled`, `timeout`.
Conteúdo do relatório: `gamekernel-report` v1 (as 15 seções da especificação §16 + relatório individual de cracks).

### `reports.formats` → `{"formats": [...], "unavailable": {formato: motivo}, "default_output_dir": "…"}`

### `sandbox.availability` → `{"available", "reason", "enabled_in_settings", "supported_extensions", "limitations"}`
Nunca executa nada.

### `sandbox.analyze`
| Parâmetro | Tipo | Padrão |
|---|---|---|
| `path` | caminho absoluto de `.exe .dll .bat .cmd .ps1 .vbs .js .msi` (≤ 1 GiB) | obrigatório |
| `timeout_seconds` | 30 … 1800 | `settings.sandbox.timeout_seconds` |

Requer `settings.sandbox.enabled = true`. Sem isolamento real (Windows Sandbox ausente, outra instância
aberta, fora do Windows) → `1001` com `data.reason = "not_found"` e `data.executed = false`: **nada é executado**.
Use `timeout_ms` ≥ (`timeout_seconds` + 180 s de inicialização da VM) × 1000.
Eventos: `progress` com `stage` ∈ `boot`, `running` (`elapsed`), `collecting`, `done`.
Resultado (`SandboxReport`): `{"sample_path", "sha256", "available", "executed", "started_at", "finished_at", "timed_out",
"cancelled", "evidences": [Evidence (source = "behavioral")], "observations": {…}, "limitations": […], "error", "report_path"}`.
As evidências seguem `contracts/file_result.schema.json`/`core/models.py` e alimentam `reassess` do núcleo (Agente A).

### `sandbox.reports` (`limit` 1…1000, padrão 100) → `{"reports": [{"path","sample_path","sha256","started_at","executed","evidences","error"}]}`
