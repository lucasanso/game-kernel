# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). Cada entrada indica o agente responsável.

## [Não lançado]

### Adicionado
- **(A)** Núcleo C++20 `gk_core` (`native/core`): `ByteView` com limites verificados, arquivos somente leitura/mapeados,
  SHA-256 (libsodium) e MD5, identificação de tipo real; módulo pybind11 `gk_native` (API v1, `docs/CORE_API.md`).
- **(A)** Parser PE em C++ para entrada hostil (cabeçalhos, seções, entropia, imports/delay-imports, exports e
  forwarders, recursos, version info, manifest, TLS, PDB, Rich, overlay, mapeamento RVA↔offset em O(log n)),
  equivalente ao pefile em PEs reais gerados com mingw-w64; fuzzing por mutação sob ASan/UBSan.
- **(A)** Motor YARA em C++ (libyara) equivalente ao yara-python; 10 regras de detecção documentadas
  (`docs/DETECTION_RULES.md`) e 95 regras de indicadores geradas (`tools/core_gen_indicators.py`).
- **(A)** Compactados em memória (libarchive) com limites anti-bomba, recursão, SFX, nomes perigosos e criptografia.
- **(A)** `contracts/schema.sql` (esquema único, verificado contra `db.py`); CI do núcleo (`.github/workflows/core-ci.yml`).
- **(A)** Documentação: `ARCHITECTURE.md` rev. 2, `MIGRATION_PLAN.md`, `MODULES.md`, `SECURITY.md`, `BUILD.md`,
  `CORE_API.md`, `DETECTION_RULES.md`, `WORK_SPLIT.md` rev. 3.
- **(B)** gk-ipc v1: protocolo de integração C++ ↔ Python por processo auxiliar (`gamekernel/ipc/`, `gk_helper.py`),
  cliente C++/Qt `gk::ipc::HelperClient` (`native/ipc/`) e cliente Python; contrato em `docs/INTEGRATION.md`.
- **(B)** Testes cruzados: 46 testes Python (`tests/ipc/`) e 34 testes C++ (`native/ipc/tests/`) controlados pelo
  pytest (`tests/native/`); validação com AddressSanitizer e UBSan.
- **(B)** `docs/PROGRESS_B.md` (auditoria e plano de refatoração híbrida), `docs/TESTING.md`.

- **(B)** Relatórios forenses (JSON, HTML autocontido sem JavaScript, PDF) como serviço `reports.generate` do
  processo auxiliar: 15 seções, relatório individual de cracks, redação de dados pessoais, banco somente leitura
  (`gamekernel/core/report_engine.py`, `report_html.py`, `report_pdf.py`, `sysinfo.py`).
- **(B)** Teste ponta a ponta C++ → Python: o cliente Qt gera um relatório real pelo processo auxiliar.

- **(B)** Atualização offline: formato `.gkpkg` v1 assinado (Ed25519); construção e verificador de referência em
  Python (`gamekernel/updates/package.py`); **verificação e instalação atômica com rollback em C++**
  (`native/updates/`: libsodium, libyara, Qt Core) e CLI `gk-update`.
- **(B)** Threat Intelligence (`gamekernel/ti/`): IOC (normalização, deduplicação, conflitos), preparação e *lint* de YARA,
  verificação antes de assinar com os validadores C++, relatório de atualização; ferramentas `tools/gk_keygen.py`,
  `tools/make_update_package.py`, `tools/ti_build_ioc.py`.
- **(B)** Testes de equivalência Python × C++ (pacotes, IOC, YARA), mutações aleatórias e modo `GK_NATIVE_SANITIZE=1`.
- **(B)** `docs/OFFLINE_UPDATES.md`.

### Alterado
- **(B)** Escopo do Agente B ajustado à arquitetura híbrida: a quarentena passa ao núcleo C++ (Agente A); interface
  Qt 6 C++ com dono a confirmar.

### Corrigido
- **(A)** `Database._connect` vazava o handle de um banco corrompido e impedia a recuperação no Windows (achado pelo CI).
- **(A)** Fuzzing do parser PE: análise repetida de recursos idênticos e busca linear de seção (limites e cache).

### Dependências
- **(A)** Núcleo: libsodium, nlohmann/json, libyara 4.5, libarchive ≥ 3.6 (`vcpkg.json`, `cmake/GkDependencies.cmake`).
- **(B)** Nativo: Qt 6.4+ (Core, Test), CMake ≥ 3.21, **libsodium ≥ 1.0.18** (Ed25519, já que o CNG do Windows não
  oferece Ed25519), **libyara 4.5** (compilação de regras antes de ativar; opcional, e sem ela os componentes YARA
  são recusados). Ainda não adicionadas aos arquivos congelados da fundação (pendência P5).
