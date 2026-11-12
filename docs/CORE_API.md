# API do núcleo C++ (`gk_core`) e módulo `gk_native` — Agente A

Complementa `docs/INTEGRATION.md` (Agente B), que define os mecanismos de integração entre linguagens
(gk-ipc v1 e pybind11). Este documento descreve **o que o núcleo expõe**.

## 1. Biblioteca `gk_core` (C++20, sem Qt)

| Cabeçalho | Função |
|---|---|
| `gk/byte_view.hpp` | `ByteView`: leitura com limites e aritmética verificada — única forma de ler dados de arquivos |
| `gk/file_view.hpp` | `ReadOnlyFile`, `MappedFile` (compartilhamento total, só arquivos comuns), `read_range` |
| `gk/hash.hpp` | SHA-256/SHA-512/SHA-384 (libsodium), MD5 e SHA-1 próprios (SHA-1 só para resumos de assinaturas antigas), `hash_file` em streaming com cancelamento |
| `gk/filetype.hpp` | Tipo real por conteúdo, PE disfarçado, filtros e prioridade |
| `gk/pe.hpp` | Parser PE para entrada hostil, anomalias com códigos estáveis, mapeamento RVA↔offset |
| `gk/yara_engine.hpp` | Regras YARA: compilação isolada por arquivo, `include` bloqueado, varredura thread-safe, validação de pacotes |
| `gk/archive.hpp` | Compactados em memória (libarchive) com limites anti-bomba e recursão |
| `gk/authenticode.hpp` | `inspect` (tabela de certificados, PKCS#7 e aninhadas, resumo da imagem, adulteração — portátil) e `verify_trust` (Windows, offline, com catálogos) |
| `gk/text.hpp` | UTF-16LE, `display_utf8` (texto hostil para exibição), `path_utf8` (nunca use `path::string()`) |
| `gk/serialize.hpp` | JSON dos resultados — mesmo formato no pybind11 e no IPC |
| `gk/error.hpp` | `gk::Error` com códigos (`FileAccess`, `ResourceLimit`, `Timeout`, `Cancelled`, `InvalidFormat`, `Internal`) |
| `gk/cancel.hpp` | `CancelToken` (cancelar/pausar) |

O núcleo não depende de Qt: é testável por pybind11, usado pelo `gk-scanworker` (processo isolado) e,
na aplicação, através da camada de serviços Qt.

## 2. Módulo `gk_native` (pybind11) — API v1

| Função | Retorno |
|---|---|
| `API_VERSION`, `CORE_VERSION` | versão da API Python e do núcleo |
| `sha256_bytes(b)`, `md5_bytes(b)`, `sha256_file(p)`, `hash_file(p, with_md5=True)` | hashes |
| `identify(header, ext, iso_probe=b"")`, `identify_file(p)`, `group_enabled(info, filtros)`, `priority(info, nome)`, `extension_of(p)` | tipo real |
| `parse_pe(b)`, `parse_pe_file(p)` | documento JSON do PE (`gk/serialize.hpp`) |
| `pe_rva_to_offset(b, rvas)`, `pe_offset_to_rva(b, offsets)`, `shannon_entropy(b)` | mapeamento e entropia |
| `YaraRules.compile_source(src)`, `YaraRules.compile_files(paths)` → `(regras, relatório)`; `.scan(data, filename=…, …)`, `.metadata()`, `.save(p)`, `YaraRules.load(p)`, `.rule_count` | YARA |
| `yara_validate_dir(p)`, `yara_version()` | validação de regras de pacotes |
| `archive_walk(b, limites)`, `archive_recognised(b)`, `libarchive_version()` | compactados |
| `authenticode_inspect(b)`, `authenticode_image_digest(b, alg)`, `authenticode_verify_trust(p)`, `authenticode_trust_supported()`, `sha1_bytes(b)`, `sha512_bytes(b, sha384=False)` | assinaturas digitais |

Exceções: `gk::Error` → `gk_native.GkError` com `args = (código, mensagem)`. O GIL é liberado em toda
operação longa. Localização do módulo nos testes: `GK_NATIVE_DIR` ou `build/<preset>/cpp/bindings`
(`tests/conftest.py`); `GK_REQUIRE_NATIVE=1` transforma ausência em falha (CI).

## 3. Contratos de dados

* `contracts/schema.sql` — esquema SQLite único (teste garante igualdade com `gamekernel/database/db.py`).
* Documentos JSON do núcleo: nomes de campos estáveis, enums como texto, campos novos sempre opcionais.

## 4. Processo de análise isolado (M8)

`gk-scanworker` executará os parsers (PE, YARA, compactados) fora do processo do aplicativo, sob Job Object
com limite de memória e integridade baixa, falando **gk-ipc v1** (`docs/INTEGRATION.md`) — o mesmo
enquadramento e envelope do processo auxiliar Python, sem um segundo protocolo.

## 5. Testes do núcleo

* `tests/native/test_hash.py`, `test_filetype.py` — equivalência com `hashlib` e `filetypes.py`.
* `tests/native/test_pe.py` — corpus de PEs reais gerado com mingw-w64 (`tests/corpus_pe/`), equivalência com
  pefile, mapeamento de endereços, estruturas malformadas, fuzzing por mutação.
* `tests/native/test_yara.py` — equivalência com yara-python, isolamento, `include`, concorrência.
* `tests/native/test_archive.py` — equivalência com zipfile/tarfile, bombas, limites, nomes perigosos, fuzzing.
* Sanitizers: preset `linux-asan`; `GK_SLOWDOWN_FACTOR` ajusta os limites de tempo; `GK_FUZZ_ITERATIONS`.

## 6. Regras de uso

* **Um único SQLite por processo.** `gk_native.CoreDatabase` (C++) e `gamekernel.database.Database` (Python) usam
  cópias diferentes da biblioteca SQLite; usá-las no mesmo processo quebra os locks POSIX entre elas (o fechamento de
  uma conexão de uma cópia libera os locks da outra e pode apagar o arquivo WAL). No produto isso não ocorre (o app
  usa só o C++; o Python roda no processo auxiliar). Nos testes, o lado C++ roda em outro processo
  (`tests/native/test_core_db.py`).
* `gk-scanworker` recebe caminhos absolutos de regras (`--rules`, `--indicators`) e informa no `hello` quantas regras
  carregou; o orquestrador registra aviso quando os indicadores não carregam.

## 7. Orquestrador e CLI

* `cpp/scan` (`gk::scan::Scanner`, Qt Core): enumeração → cache por caminho/tamanho/mtime e por SHA-256 + impressão
  dos motores → `gk-scanworker` × N supervisionados pelo cliente gk-ipc (`cpp/ipc`: Job Object, prazo, reinício) →
  ClamAV em lotes (`clamscan --file-list`, vários `--database`, cache por SHA-256 + identidade dos bancos) →
  reputação local (IOCs + marcações do usuário) → contexto de pasta e risco → SQLite.
* Falha ou travamento do worker: o arquivo recebe `status=error/partial` com o motivo e a varredura continua.
* `gk-cli scan <alvos> [--quick] [--json saída] [--data-dir dir] [--workers n] [--no-cache]` — códigos de saída:
  0 nada suspeito · 3 ameaças/suspeitos/PUA · 2 erro · 4 cancelada (Ctrl+C).
