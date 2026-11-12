# Game Kernel — Testes

Responsável: Agente B (Test Engine em Python). O **pytest controla todos os testes**, inclusive os C++:
os executáveis nativos são compilados com CMake e executados por *drivers* em `tests/native/`.

## Como executar

```bash
pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

Pré-requisitos dos testes nativos: CMake ≥ 3.21, compilador C++20 (MSVC 2022, GCC 13 ou Clang 17+),
Qt 6.4+ (Core e Test), Ninja (opcional). No Ubuntu:

```bash
sudo apt-get install -y cmake ninja-build g++ qt6-base-dev libgl-dev libsodium-dev libyara-dev pkg-config
```

Sem o toolchain, os testes nativos são **pulados com o motivo**. Na CI, `GK_NATIVE_REQUIRED=1` transforma o
pulo em **falha**, para que um problema de integração nunca fique escondido.

Variáveis úteis:

| Variável | Efeito |
|---|---|
| `GK_NATIVE_REQUIRED=1` | toolchain nativo ausente = falha (CI) |
| `GK_NATIVE_CONFIG=Debug` | tipo de *build* dos testes nativos (padrão `Release`) |
| `GK_NATIVE_SANITIZE=1` | compila variantes **ASan + UBSan** (`build/*-asan`) e roda a suíte inteira contra elas; códigos de saída 99/98 distinguem um erro de memória de uma rejeição legítima |

Sanitizadores (Linux):

```bash
cmake -S native/ipc -B build/native-ipc-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
cmake --build build/native-ipc-asan
```

```bash
GK_PYTHON=$(which python3) GK_REPO=$PWD ./build/native-ipc-asan/gk_ipc_tests
```

## Organização

| Pasta | Conteúdo | Dono |
|---|---|---|
| `tests/foundation/` | fundação (modelos, banco, configurações, Ed25519, netguard) | A |
| `tests/ipc/` | protocolo gk-ipc e processo auxiliar real com falhas provocadas (`fault_helper.py`) | B |
| `tests/reports/` | relatórios: conteúdo, cracks, privacidade, escape, PDF, serviço no auxiliar (`sample_scan.py` grava uma varredura realista) | B |
| `tests/updates/` | pacotes `.gkpkg`: construtor, **equivalência Python × C++**, adulterações, mutações aleatórias, instalador C++ | B |
| `tests/ti/` | IOC, YARA (yara-python × libyara), ferramentas do publicador ponta a ponta | B |
| `tests/native/` | *drivers* pytest que compilam e executam os testes C++ do B | B |
| `native/ipc/tests/` | testes QtTest do cliente C++ (executados contra os auxiliares Python reais) | B |

## Regras

* Amostras perigosas (EICAR, scripts suspeitos) são **geradas em tempo de teste** em pastas temporárias e nunca versionadas.
* Nenhum teste usa a rede. O auxiliar roda com `netguard`, e há teste que confirma o bloqueio.
* Cada teste usa um diretório de dados isolado (`isolated_data_dir`).
* Testes que dependem de tempo usam prazos curtos com margem (sem `sleep` fixo para "esperar dar certo").

## Resultados

Ver `docs/TEST_REPORT_B.md` (gerado a cada etapa) e `docs/PROGRESS_B.md`.
