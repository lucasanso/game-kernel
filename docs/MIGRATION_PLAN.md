# Plano de migração para a arquitetura híbrida C++20 / Python

Data: 2026-11-12 · Autor: Agente A (Core e Segurança)

## ETAPA 1 — Auditoria do estado real

Situação do repositório `lucasanso/game-kernel` no início da migração:

* Branch `claude/magical-bell-fi6jw1` (commit `fd1aa22`): fundação Python + 23 testes passando.
* Arquivos Python do Agente A ainda **não integrados** (trabalho em andamento, sem testes):
  `core/integrity.py`, `core/tools.py`, `engines/indicators.py`, `engines/yara_engine.py`.
* Nenhuma branch do Agente B publicada no remoto até esta data.
* Nenhum código C++, nenhuma interface gráfica implementada ainda.

Conclusão: a migração acontece **cedo**. Não há interface, scanner ou motor completo a portar;
o custo de adotar C++ agora é baixo e evita reescrever depois.

## ETAPA 2/3 — Mapa e classificação dos módulos existentes

| Módulo Python | Estado | Responsabilidade | Decisão | Justificativa |
|---|---|---|---|---|
| `core/models.py` | pronto + testes | Modelo de dados | **Mantido em Python** como representação do contrato no lado Python (helper, ferramentas, testes). Contrato canônico passa a ser `contracts/*.schema.json`; o C++ serializa exatamente o mesmo JSON. | Ferramentas e relatórios precisam do modelo; teste de equivalência garante compatibilidade. |
| `core/threat_catalog.py` | pronto | Textos de cada ameaça | **Conteúdo movido** para `contracts/threat_catalog.json` (fonte única); o módulo Python passa a carregá-lo. | A UI C++ e os relatórios Python precisam do mesmo texto. |
| `core/filetypes.py` | pronto + testes | Tipo real do arquivo (caminho quente) | **Migrar para C++** (`gk::filetype`). Python vira oráculo de teste e é removido após equivalência. | Executado para cada arquivo; leitura de bytes não confiáveis. |
| `core/hashing.py` | pronto | SHA-256 em streaming | **Migrar para C++** (libsodium). | Caminho quente; E/S grande. |
| `config.py` | pronto + testes | Configurações | **C++** (`gk::Settings`, mesmo JSON e mesmas chaves). Python mantém leitura para ferramentas. | O app é C++; arquivo único compartilhado. |
| `app_paths.py` | pronto | Diretórios | **C++** (`gk::paths`, `SHGetKnownFolderPath`); Python mantém o mesmo layout para ferramentas. | Contrato de diretórios idêntico. |
| `netguard.py` | pronto + testes | Bloqueio de rede no Python | **Mantido** e aplicado em todo processo Python (helper). No C++: nenhuma biblioteca de rede é vinculada, verificado por teste de imports dos binários. | Audit hooks só existem no Python. |
| `logging_setup.py` | pronto | Logs | **Mantido** no Python; C++ grava no mesmo diretório (JSON Lines). | — |
| `crypto_utils.py` | pronto + testes | Ed25519 | **Mantido em Python para ASSINAR** (ferramentas de pacote). **Verificação em tempo de execução → C++** (libsodium). Teste cruzado: Python assina, C++ verifica. | Requisito: validação criptográfica no núcleo C++. |
| `core/scan_api.py` | pronto | Contrato do scanner (Python) | **Substituído** pelo protocolo IPC/`contracts/scan_protocol.md` e pela API C++; removido quando o scanner C++ estiver integrado (M8). | Evitar duas APIs de scanner. |
| `database/db.py` | pronto + testes | SQLite | Dono em tempo de execução: **C++** (`gk::Database`). Esquema extraído para `contracts/schema.sql`, carregado pelos dois lados. Python mantém acesso para ferramentas/relatórios/testes. | Esquema único evita divergência; cadeia de auditoria com teste de equivalência. |
| `core/tools.py` (não integrado) | WIP | Execução de binários auxiliares | **Descartado**: substituído por `gk::process` (CreateProcess + Job Object). | Nunca foi integrado; o lançamento de processos é do núcleo C++. |
| `core/integrity.py` (não integrado) | WIP | Manifesto de integridade | **Geração permanece em Python** (ferramenta de build). **Verificação → C++**. | Build é automação; verificação é segurança em tempo de execução. |
| `engines/indicators.py` (não integrado) | WIP | Tabela de indicadores de capacidade | **Mantido em Python como gerador** de `signatures/internal/indicators.yar`, consumido pelo motor YARA C++. | Preparação de regras = Python; casamento de padrões = C++/libyara. |
| `engines/yara_engine.py` (não integrado) | WIP | Casamento YARA | **Casamento → C++ (libyara)**. Restante vira ferramenta Python de validação de regras (`gamekernel/rules/`), usada na preparação de pacotes. | Evita motor duplicado. |

## ETAPA 4 — Contratos C++/Python

Definidos em `docs/INTEGRATION.md` e `contracts/`:
1. **Dados**: JSON Schema de `FileResult`/`Evidence`/`Location`/`ScanSummary`; `schema.sql`.
2. **pybind11** (`gk_native`): espelho fino da API do núcleo, usado por testes e automação.
3. **IPC** entre processos (núcleo ↔ worker de análise; app ↔ helper Python): quadros com
   tamanho + JSON, envelope versionado estilo JSON-RPC, tempo limite e reinício após falha.

## ETAPA 5 — Migração dos componentes críticos (Agente A), em passos verificáveis

| Passo | Entrega | Critério de aceite |
|---|---|---|
| **M1** | CMake + `gk_core` (SHA-256, tipo de arquivo, leitura limitada) + `gk_native` (pybind11) | Equivalência com `hashlib` e `filetypes.py` em corpus gerado; build Linux OK |
| **M2** | Parser PE próprio com leitor limitado (seções, entropia, imports/exports/forwarders, recursos, overlay, TLS, debug/PDB, version info, manifest, CLR, diretório de segurança) | Equivalência com `pefile` em PEs reais gerados com mingw-w64; fuzzing por mutação sem falhas sob ASan/UBSan |
| **M3** | Motor YARA C++ (libyara): regras de detecção + indicadores gerados | Mesmos acertos/offsets que yara-python no corpus |
| **M4** | Authenticode (WinVerifyTrust, cache-only, sem CRL online) + dados do certificado | Testes Windows (CI) com binários assinados do sistema |
| **M5** | Compactados (libarchive) recursivos com limites anti-bomba | Testes de bomba de compressão, aninhamento, corrompidos, path traversal |
| **M6** | Scripts/LNK (YARA + decodificação de `-EncodedCommand`), ClamAV (processo isolado), reputação/IOC | EICAR detectado por 3 mecanismos independentes |
| **M7** | Motor de risco + contexto de jogo/cracks (regras orientadas a dados) | Testes de falsos positivos (ReShade, emuladores Steam) e de escalonamento |
| **M8** | Orquestrador + processo worker isolado + IPC + banco C++ + `gk-cli` | Integração completa; cancelamento, pausa, retomada, falha do worker não derruba o app |
| **M9** | Quarentena C++ (XChaCha20-Poly1305 + DPAPI, `.gkq`, verificação antes de restaurar) | Integridade, adulteração detectada, restauração autorizada |
| **M10** | Verificação/instalação de pacotes offline e integridade da instalação em C++ | Pacote adulterado rejeitado; rollback atômico |
| **M11** | Proteção em tempo real (ReadDirectoryChangesW) | Testes Windows |
| **M12** | Performance Monitor (PDH, DXGI VRAM, GPU engine) e System Optimizer (somente diagnóstico + limpeza segura de temporários com confirmação) | Testes Windows; nenhuma alteração agressiva do sistema |
| **M13** | Camada Qt de serviços (`gk_bridge`: QObject + sinais) para a UI | UI não trava; testes com QSignalSpy |
| **M14** | CI Windows (MSVC + vcpkg), build com sanitizers no Linux | Pipeline verde |

Regra: a implementação Python correspondente só é removida depois que o teste de equivalência passa
e o componente C++ estiver integrado.

## Riscos e mitigação

| Risco | Mitigação |
|---|---|
| Bugs de memória em parsers de formatos hostis | Leitor com limites verificados, aritmética checada, sanitizers, fuzzing, **parsers rodando em processo worker isolado** (Job Object, memória limitada, integridade baixa) |
| Divergência entre C++ e Python | Contratos JSON Schema + testes de equivalência em ambos os sentidos |
| Diferenças Linux (desenvolvimento) × Windows (produto) | Código Windows isolado em `platform/win`; CI Windows obrigatório; mingw-w64 para checagem de compilação local |
| Dependências | Apenas bibliotecas consolidadas e justificadas (ver ARCHITECTURE.md §4) |
