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

### Interface (`cpp/app`)
```bash
sudo apt-get install -y qt6-base-dev libqt6svg6-dev   # Linux; no Windows o Qt 6.8 do aqtinstall já inclui Svg
cmake -S cpp/app -B build/native-app -G Ninja && cmake --build build/native-app --target GameKernel
```
Também compila `cpp/ipc` e `cpp/updates` quando construída sozinha. Executável: `GameKernel(.exe)`. Em
desenvolvimento, o processo auxiliar vem de `GK_DEV_REPO` (raiz do repositório) e `GK_DEV_PYTHON` (ou `python3` no
PATH); instalado, de `<app>/helper/gk-helper(.exe)`. Sem nenhum dos dois, as páginas que dependem do auxiliar
mostram "indisponível" com o motivo.

Ícone e versão: o logotipo tem uma fonte única, `assets/gamekernel.svg`, embutida no executável como recurso Qt (ícone
da janela). `assets/gamekernel.ico` (16 a 256 px, entradas PNG) é gerado a partir dele com
`python tools/make_app_icon.py`; rode de novo sempre que o logotipo mudar (um teste acusa o `.ico` desatualizado).
No Windows, `cpp/app/resources/gamekernel.rc.in` vira o recurso com o ícone e o `VERSIONINFO`; a versão vem do
`project()` de `cpp/app/CMakeLists.txt`, a mesma mostrada na interface.

### CI
`.github/workflows/ci.yml` (Agente B): Linux, com a suíte completa e a variante ASan/UBSan; Windows, com MSVC, Qt 6.8
(aqtinstall), libsodium e yara (vcpkg), a suíte completa, o PyInstaller do auxiliar e o teste do auxiliar congelado.
Nenhum segredo é usado; a chave privada de *release* nunca chega à CI.

### Distribuição: instalador e versão portátil (Windows)

1. Núcleo: `cmake --preset windows-release -DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64 -DGK_BUILD_BINDINGS=OFF` e
   `cmake --build --preset windows-release --target gk-cli gk-scanworker gk-update` (com Qt, a raiz também compila
   a varredura, a CLI e o `gk-update`).
2. Interface com as mesmas dependências estáticas: `cmake -S cpp/app -B build/pkg-app` com o *toolchain* do vcpkg,
   `-DVCPKG_TARGET_TRIPLET=x64-windows-static-md -DVCPKG_INSTALLED_DIR=<build/windows-release/vcpkg_installed>
   -DVCPKG_MANIFEST_MODE=OFF -DGK_APP_BUILD_TESTS=OFF`, depois `--target GameKernel`.
3. Auxiliar: `pyinstaller installer/gk_helper.spec --distpath dist --workpath build/pyinstaller`.
4. Pasta do produto, manifesto e ZIP portátil: `python tools/make_distribution.py --app … --bin gk-cli.exe
   --bin gk-scanworker.exe --bin gk-update.exe --helper dist/gk-helper --crt-dir <Microsoft.VC143.CRT>
   [--release-key release.pub] --out dist/GameKernel --portable-zip dist/GameKernel-<versão>-portable.zip`.
   A ferramenta roda o `windeployqt`, copia assinaturas, `contracts/threat_catalog.json` e os guias, grava
   `MANIFEST.sha256` e **recusa** chave privada, DLL de rede, DLLs homônimas diferentes e `portable.flag` na pasta
   instalada.
5. Instalador: `iscc /DAppVersion=<versão> /DSourceDir=<dist\GameKernel> /DOutputDir=dist installer\gamekernel.iss`.

Builds sem `--release-key` (como os da CI) não trazem chave embutida: o usuário adiciona a chave do publicador na
Central de Atualização Offline. O job `windows-package` da CI faz todos os passos, instala em silêncio, testa o
produto instalado e a versão portátil (`tests/integration/test_distribution.py` com `GK_INSTALLED_DIR`) e
desinstala, conferindo que os dados do usuário ficam.
