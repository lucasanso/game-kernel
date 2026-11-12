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
O módulo `gk_native` é gerado em `build/linux-debug/native/bindings/` e os testes o encontram via
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

## Empacotamento e componentes do Agente B

O build raiz (acima) já inclui `native/ipc` e `native/updates` quando o Qt 6 está disponível. Os dois também
compilam sozinhos, que é como o motor de testes os usa:
```bash
cmake -S native/updates -B build/native-updates -G Ninja && cmake --build build/native-updates   # gk-update
cmake -S native/ipc -B build/native-ipc -G Ninja && cmake --build build/native-ipc               # cliente gk-ipc + testes
```
No Windows: `-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64`.
A libyara do vcpkg é estática e é ligada pelo alvo `unofficial::libyara::libyara` (pacote `unofficial-libyara`),
que traz OpenSSL::Crypto, Crypt32 e Ws2_32.

### Interface (`native/app`)
```bash
sudo apt-get install -y qt6-base-dev libqt6svg6-dev   # Linux; no Windows o Qt 6.8 do aqtinstall já inclui Svg
cmake -S native/app -B build/native-app -G Ninja && cmake --build build/native-app --target GameKernel
```
Executável: `GameKernel(.exe)`. Em desenvolvimento, o processo auxiliar vem de `GK_DEV_REPO` (raiz do repositório) e
`GK_DEV_PYTHON` (ou `python3` no PATH); instalado, de `<app>/helper/gk-helper(.exe)`. Sem nenhum dos dois, as páginas
que dependem do auxiliar mostram "indisponível" com o motivo.

### Processo auxiliar Python (`gk-helper`)
```bash
pip install -r requirements-dev.txt
pyinstaller installer/gk_helper.spec --noconfirm --distpath dist --workpath build/pyinstaller
```
Saída: `dist/gk-helper/` (*one-folder*), copiada para `<instalação>/helper/`. Teste de fumaça:
`GK_FROZEN_HELPER=dist/gk-helper/gk-helper(.exe) pytest -q tests/ipc/test_frozen_helper.py`.

### CI do produto
`.github/workflows/ci.yml` (Agente B): Linux, com a suíte completa e a variante ASan/UBSan; Windows, com MSVC 2022,
Qt 6.8 (aqtinstall), libsodium e yara (vcpkg em modo clássico, fora da raiz do repositório, com cache binário),
a suíte completa, a sintaxe do `monitor.ps1` (PowerShell 5.1 e 7), o PyInstaller do auxiliar e o teste de fumaça
do auxiliar congelado (que rodam mesmo se o passo de testes falhar). Nenhum segredo é usado; a chave privada de
*release* nunca chega à CI.

O instalador Windows (Inno Setup) e a versão portátil serão definidos quando o executável da interface
(`native/app`) existir.
