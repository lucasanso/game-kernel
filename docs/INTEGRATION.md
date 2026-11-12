# Integração C++ / Python — contratos

Três mecanismos, cada um com um propósito. Nenhuma comunicação fora deles.

| Mecanismo | Entre | Por quê |
|---|---|---|
| **pybind11** (`gk_native`) | testes/ferramentas Python → núcleo C++ (mesmo processo) | Testes de equivalência/regressão e automação chamando o código real do núcleo, sem serialização |
| **IPC worker** | `gk_core` → `gk-scanworker` | Isolamento de falhas e privilégios ao analisar arquivos hostis |
| **IPC helper (JSON-RPC sobre stdio)** | `GameKernel.exe` → `gk-helper` (Python congelado) | Funções Python no app final sem que uma falha do Python derrube o app |

## 1. Contratos de dados (fonte única: `contracts/`)

| Arquivo | Conteúdo | Produtor → consumidor |
|---|---|---|
| `contracts/schema.sql` | Esquema SQLite (versão em `meta.schema_version`) | C++ e Python carregam o mesmo arquivo |
| `contracts/file_result.schema.json` | `FileResult`, `Evidence`, `Location`, `FileFeatures` | C++ produz; Python (`core/models.py`) consome; testes validam os dois lados |
| `contracts/threat_catalog.json` | Textos de cada categoria de ameaça | UI C++ e relatórios Python |
| `contracts/helper_methods.md` | Métodos do auxiliar Python e extensões opcionais do envelope (Agente B) | C++ ↔ helper |

Regras de compatibilidade:
* Enums são serializados pelo **nome em texto** (`"HIGH"`, `"pe_exe"`, `"malware"`), nunca por número.
* Campos novos são opcionais; leitores ignoram campos desconhecidos.
* Mudança incompatível ⇒ incrementar a versão do contrato (`schema_version`, `protocol`), registrar em
  `CHANGELOG.md` e em `docs/WORK_SPLIT.md` §7.

## 2. Módulo pybind11 `gk_native`

* Construído por `cpp/bindings` (alvo CMake `gk_native`); versão exposta em `gk_native.API_VERSION`.
* Lista completa e atualizada das funções: `docs/CORE_API.md`.
* Espelho fino da API pública do núcleo; **não** contém lógica própria.
* Tipos complexos são retornados como `dict` no formato dos contratos JSON (o mesmo que o IPC usa),
  para que o lado Python use `FileResult.from_dict()` sem conversões ad hoc.
* Exceções C++ → exceções Python: `gk::Error` → `gk_native.GkError` (com `.code`), `std::bad_alloc` →
  `MemoryError`, `std::invalid_argument` → `ValueError`. Nenhuma exceção atravessa a fronteira sem tradução.
* O GIL é liberado em toda operação de E/S ou CPU longa (`py::gil_scoped_release`).

API v1 (M1):

```python
import gk_native
gk_native.API_VERSION                       # 1
gk_native.sha256_file(path) -> str          # hex minúsculo
gk_native.sha256_bytes(data) -> str
gk_native.hash_file(path) -> {"sha256", "md5", "size"}
gk_native.identify(header: bytes, extension: str, iso_probe: bytes = b"") -> {"kind","description","group","disguised"}
gk_native.identify_file(path) -> {...mesmo formato...}
```
(Ampliada a cada passo da migração; ver `MODULES.md`.)

## 3. IPC — quadros e envelope (worker e helper)

* **Quadro**: 4 bytes little-endian com o tamanho N, seguidos de N bytes UTF-8 de JSON. N ≤ 64 MiB;
  quadro maior ⇒ erro de protocolo e encerramento do canal.
* **Handshake**: primeira mensagem do processo filho:
  `{"v":1,"type":"hello","component":"gk-scanworker","version":"1.0.0","protocol":1}`.
  Versão de protocolo diferente ⇒ o pai encerra o filho e registra o erro.
* **Requisição**: `{"v":1,"id":<int>,"method":"<nome>","params":{...}}`
* **Resposta**: `{"v":1,"id":<int>,"result":{...}}` ou `{"v":1,"id":<int>,"error":{"code":<int>,"message":"...","data":{...}}}`
* **Evento** (sem id, filho → pai): `{"v":1,"type":"event","name":"progress","data":{...}}`
* **Logs** do filho: eventos `log` com `level` e `message`; o pai grava no log do app.

Códigos de erro: `-32600` requisição inválida · `-32601` método inexistente · `-32602` parâmetros inválidos · `1001` arquivo inacessível ·
`1002` limite de recurso excedido · `1003` tempo limite · `1004` cancelado · `1005` formato inválido ·
`1099` erro interno.

### Falhas
* Tempo limite por chamada (configurável; padrão 120 s por arquivo). Excedido ⇒ o pai mata o processo,
  marca o arquivo como `partial` com o motivo e inicia outro worker.
* Fim inesperado do processo (crash) ⇒ mesmo tratamento; após 3 falhas seguidas no mesmo arquivo,
  ele é registrado como "não analisado" e a varredura continua.
* O helper Python é iniciado sob demanda; falha ⇒ a funcionalidade correspondente mostra o erro,
  o restante do app continua funcionando.

## 4. Logs e recursos

* C++: JSON Lines em `<data>/logs/core.log` (rotação 5 × 5 MiB). Python: `<data>/logs/gamekernel.log`.
* Processos filhos: stdout/stderr nunca são misturados ao canal de dados (o canal usa pipes dedicados).
* Todo recurso do sistema (handles, mapeamentos, processos) é encapsulado em RAII no C++.
