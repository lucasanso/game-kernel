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
Para rodar os testes contra esse build, os runtimes dos sanitizers e a libstdc++ precisam ser pré-carregados
(o interpretador Python não é compilado com ASan e não carrega a libstdc++ por conta própria):
```bash
LD_PRELOAD="$(gcc -print-file-name=libasan.so):$(gcc -print-file-name=libubsan.so):$(gcc -print-file-name=libstdc++.so)" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 GK_NATIVE_DIR=build/linux-asan/cpp/bindings python -m pytest -q tests/native
```

### Windows (produto)
Requisitos: Visual Studio 2022 (MSVC v143), CMake ≥ 3.25, vcpkg (`VCPKG_ROOT`), Qt 6.8 LTS (MSVC 2022 64-bit).
```bash
cmake --preset windows-release
cmake --build --preset windows-release
```
As dependências C/C++ vêm de `vcpkg.json` (modo manifesto).

## Empacotamento (Agente B)

### Processo auxiliar Python (`gk-helper`)
```bash
pip install -r requirements-dev.txt
pyinstaller installer/gk_helper.spec --noconfirm --distpath dist --workpath build/pyinstaller
```
Saída: `dist/gk-helper/` (*one-folder*), copiada para `<instalação>/helper/`. Teste de fumaça:
`GK_FROZEN_HELPER=dist/gk-helper/gk-helper(.exe) pytest -q tests/helper/test_frozen_helper.py`.

### Componentes C++ do Agente B (independentes do preset do núcleo)
```bash
cmake -S cpp/updates -B build/native-updates -G Ninja && cmake --build build/native-updates   # gk-update
cmake -S cpp/ipc -B build/native-ipc -G Ninja && cmake --build build/native-ipc               # cliente de referência + testes
```
No Windows: `-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64`
(libsodium e yara pelo vcpkg).

### CI
`.github/workflows/ci.yml` (Agente B): Linux, com a suíte completa e a variante ASan/UBSan; Windows, com MSVC, Qt 6.8
(aqtinstall), libsodium e yara (vcpkg), a suíte completa, o PyInstaller do auxiliar e o teste do auxiliar congelado.
Nenhum segredo é usado; a chave privada de *release* nunca chega à CI.

O instalador Windows (Inno Setup) e a versão portátil serão definidos quando o executável Qt da interface
(`cpp/app`) e os binários do núcleo existirem.
