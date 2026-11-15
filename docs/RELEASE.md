# Publicar uma versão do Game Kernel

Este guia é para quem **publica** o Game Kernel (não para o usuário final). A CI gera e testa instaladores, mas com
uma chave descartável: eles servem para teste, não para distribuir. Uma versão de verdade exige os passos abaixo,
feitos por você, com a chave de *release* fora do repositório e fora da CI.

## 1. Chave de release (uma vez)

Em um computador confiável, de preferência desconectado da internet:

```bash
python tools/gk_keygen.py --out-dir E:\chaves-game-kernel --name release
```

* `release.key` é a chave **privada** (protegida por senha). Guarde-a e faça cópia de segurança em mídia separada.
  Nunca a coloque no repositório, na CI, em nuvem ou em e-mail. Quem tem esse arquivo e a senha pode publicar
  atualizações e instaladores aceitos pelo Game Kernel.
* `release.pub` é a chave **pública**. Ela vai dentro do produto (a montagem a grava em `signatures/keys/`) e pode ser
  publicada junto com o identificador que a ferramenta mostra, para quem quiser conferir.

A mesma chave assina os pacotes de assinaturas (`.gkpkg`) e o manifesto de integridade da instalação.

## 2. Versão

A versão do produto está em dois lugares, que precisam coincidir (um teste da CI garante isso):

* `cpp/app/CMakeLists.txt` → `project(gk_app VERSION x.y.z)`: interface, `VERSIONINFO` e instalador;
* `CMakeLists.txt` da raiz → `project(GameKernel VERSION x.y.z)`: núcleo (`gk-cli --version`).

## 3. Compilar o produto (Windows, MSVC)

Siga `docs/BUILD.md`, seção *Distribuição*: núcleo pelo *preset* `windows-release` com Qt, interface com as mesmas
dependências estáticas e auxiliar com o PyInstaller.

**Assinatura de código (opcional, recomendada).** Sem um certificado de assinatura de código, o Windows mostra o aviso
do SmartScreen ao abrir o instalador. Se você tiver um certificado, assine os executáveis (`GameKernel.exe`,
`gk-cli.exe`, `gk-scanworker.exe`, `gk-update.exe`, `helper\gk-helper.exe`) **antes** do passo 4, porque o manifesto
de integridade registra os arquivos exatamente como serão distribuídos. Assine o instalador depois do passo 5.

## 4. Montar e assinar a pasta do produto

```bash
python tools/make_distribution.py --app build\windows-release\cpp\app\Release\GameKernel.exe ^
  --bin build\windows-release\cpp\cli\Release\gk-cli.exe ^
  --bin build\windows-release\cpp\worker\Release\gk-scanworker.exe ^
  --bin build\windows-release\cpp\updates\Release\gk-update.exe ^
  --helper dist\gk-helper --crt-dir "<VC>\Redist\MSVC\<versão>\x64\Microsoft.VC143.CRT" ^
  --key E:\chaves-game-kernel\release.key ^
  --out dist\GameKernel --portable-zip dist\GameKernel-<versão>-portable.zip
```

A senha da chave é pedida no terminal. A ferramenta para com erro se faltar algum componente, se aparecer uma DLL de
rede ou uma chave privada, e confere o manifesto antes de gerar o ZIP portátil.

## 5. Instalador

```bash
iscc /DAppVersion=<versão> /DSourceDir=<repo>\dist\GameKernel /DOutputDir=<repo>\dist installer\gamekernel.iss
```

## 6. Conferir antes de publicar

Em uma máquina virtual limpa, sem rede:

1. Instale com o instalador gerado e abra o Game Kernel.
2. `"C:\Program Files\Game Kernel\gk-cli.exe" integrity --install-dir "C:\Program Files\Game Kernel"`: deve terminar
   com código `0` e mostrar o identificador da **sua** chave.
3. Na Central de Atualização Offline, importe um pacote `.gkpkg` assinado com a mesma chave.
4. Faça uma varredura com o `gk-cli` em uma pasta com o arquivo de teste EICAR e gere o relatório na página
   Relatórios.
5. Desinstale e confira que `%LOCALAPPDATA%\GameKernel` continua lá.

Os mesmos passos rodam automaticamente na CI (job `windows-package`) com a chave descartável; esta conferência manual
confirma a versão assinada com a chave real.

## 7. Pacotes de assinaturas (a cada atualização de regras)

```bash
python tools/make_update_package.py build --key E:\chaves-game-kernel\release.key --version AAAA.MM.DD.N ^
  --publisher "Equipe Game Kernel" --yara <pasta> --ioc <pasta> --clamav <pasta> ^
  --out GameKernel-assinaturas-AAAA.MM.DD.N.gkpkg --report relatorio-atualizacao.json
```

O pacote só é gerado se o aplicativo for aceitá-lo (regras compiladas, metadados obrigatórios, indicadores
validados). Distribua o `.gkpkg` por qualquer meio (pendrive, site); o usuário importa na Central de Atualização
Offline. Formato e regras: `docs/OFFLINE_UPDATES.md` e `contracts/update_package.md`.

## Decisões que ficam com quem publica

* **ClamAV**: o núcleo usa o `clamscan` de `third_party\clamav\` dentro da instalação ou, na falta dele, o que estiver
  instalado no sistema (PATH). Ele não vai no pacote por padrão (é GPL: distribuir exige oferecer o código-fonte
  correspondente). Sem ele, a varredura usa YARA,
  reputação local e as heurísticas do núcleo, e o relatório registra que o ClamAV não estava disponível.
* **Sysmon**: não pode ser redistribuído; o usuário pode apontar o próprio `Sysmon64.exe` em Configurações.
