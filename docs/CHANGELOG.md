# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). Cada entrada indica o agente responsável.

## [Não lançado]

### Adicionado
- **(B)** gk-ipc v1: protocolo de integração C++ ↔ Python por processo auxiliar (`gamekernel/ipc/`, `gk_helper.py`),
  cliente C++/Qt `gk::ipc::HelperClient` (`native/ipc/`) e cliente Python; contrato em `docs/INTEGRATION.md`.
- **(B)** Testes cruzados: 46 testes Python (`tests/ipc/`) e 34 testes C++ (`native/ipc/tests/`) controlados pelo
  pytest (`tests/native/`); validação com AddressSanitizer e UBSan.
- **(B)** `docs/PROGRESS_B.md` (auditoria e plano de refatoração híbrida), `docs/TESTING.md`.

### Alterado
- **(B)** Escopo do Agente B ajustado à arquitetura híbrida: a quarentena passa ao núcleo C++ (Agente A); interface
  Qt 6 C++ com dono a confirmar.

### Dependências
- **(B)** Nativo: Qt 6.4+ (Core, Test), CMake ≥ 3.21. Ainda não adicionadas aos arquivos congelados da fundação (pendência P5).
