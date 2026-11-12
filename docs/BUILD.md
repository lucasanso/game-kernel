# Compilação

## Núcleo C++ (Agente A)

### Linux (desenvolvimento e testes)
```bash
sudo apt-get install -y cmake ninja-build g++ qt6-base-dev libqt6svg6-dev libyara-dev libarchive-dev \
  libsodium-dev libsqlite3-dev nlohmann-json3-dev
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cmake --preset linux-debug -DPython_EXECUTABLE=$PWD/.venv/bin/python
cmake --build --preset linux-debug
```
O módulo `gk_native` é gerado em `build/linux-debug/cpp/bindings/` e os testes o encontram via
`GK_NATIVE_DIR` (definido automaticamente pelo `tests/conftest.py` quando o build padrão existe).

Build com sanitizers (ASan + UBSan) para testes de segurança de memória:
```bash
cmake --preset linux-asan -DPython_EXECUTABLE=$PWD/.venv/bin/python
cmake --build --preset linux-asan
```

### Windows (produto)
Requisitos: Visual Studio 2022 (MSVC v143), CMake ≥ 3.25, vcpkg (`VCPKG_ROOT`), Qt 6.8 LTS (MSVC 2022 64-bit).
```bash
cmake --preset windows-release
cmake --build --preset windows-release
```
As dependências C/C++ vêm de `vcpkg.json` (modo manifesto).

## Empacotamento (Agente B)
Seção mantida pelo Agente B.
