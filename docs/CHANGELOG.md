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
- **(B)** Sandbox (`gamekernel/engines/sandbox_manager.py`, `sandbox/monitor.ps1`): Windows Sandbox sem rede, recusa sem
  isolamento real, iscas de credenciais e documentos-isca, auditoria por GUID, mapeamento para evidências
  comportamentais; serviços `sandbox.availability`, `sandbox.analyze`, `sandbox.reports`.
- **(B)** CI do produto (`.github/workflows/ci.yml`): Linux (suíte completa + ASan/UBSan) e Windows (MSVC 2022, Qt 6.8,
  vcpkg, sintaxe do `monitor.ps1` no PowerShell 5.1 e 7, PyInstaller do auxiliar e teste do auxiliar congelado).
- **(B)** `contracts/update_package.md` (contrato normativo do `.gkpkg`), `README.md`, `docs/PRIVACY.md`, `docs/LIMITATIONS.md`.
- **(B)** Interface Qt 6 C++ (`native/app`, parte 1): janela, menu lateral, tema escuro, ícones SVG próprios,
  notificações internas, instância única; páginas Central de Atualização Offline, Análise comportamental e
  Privacidade e rede; 11 testes QtTest (`tests/ui/`) com pacotes reais e o auxiliar real, capturas de tela.
- **(B)** Método `system.network_selftest` no auxiliar: tenta DNS e conexão de saída e comprova o bloqueio.

### Alterado
- **(B)** Escopo do Agente B ajustado à arquitetura híbrida: a quarentena passa ao núcleo C++ (Agente A); interface
  Qt 6 C++ com o B (pendência P2 da rev. 3).
- **(B)** Conciliação com a `WORK_SPLIT` rev. 3: layout e protocolo gk-ipc v1 do B mantidos (um realinhamento
  provisório à rev. 2, feito na branch do B, foi desfeito); métodos `sandbox.*` documentados em `docs/INTEGRATION.md`.

### Corrigido
- **(B)** Windows: libyara estática do vcpkg ligada pelo alvo `unofficial::libyara::libyara` (traz OpenSSL, Crypt32
  e Ws2_32); DLLs do Qt implantadas ao lado dos executáveis de teste (`windeployqt`; evita `0xC0000139`); saída de
  subprocessos lida como UTF-8 e ferramentas com stdout UTF-8 (antes: texto corrompido e risco de `UnicodeEncodeError`);
  vcpkg executado em modo clássico fora da raiz (o `vcpkg.json` da raiz ativava o modo manifesto).
- **(B)** Teste C++ de limite de memória do auxiliar agora também roda no Windows (Job Object), em vez de ser pulado.
- **(A)** `Database._connect` vazava o handle de um banco corrompido e impedia a recuperação no Windows (achado pelo CI).
- **(A)** Fuzzing do parser PE: análise repetida de recursos idênticos e busca linear de seção (limites e cache).

### Dependências
- **(A)** Núcleo: libsodium, nlohmann/json, libyara 4.5, libarchive ≥ 3.6 (`vcpkg.json`, `cmake/GkDependencies.cmake`).
- **(B)** Nativo: Qt 6.4+ (Core, Test), CMake ≥ 3.21, **libsodium ≥ 1.0.18** (Ed25519, já que o CNG do Windows não
  oferece Ed25519), **libyara 4.5** (compilação de regras antes de ativar; opcional, e sem ela os componentes YARA
  são recusados). Incluídas no build raiz (`CMakeLists.txt`) quando o Qt 6 está disponível.
