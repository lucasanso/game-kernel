# Publicar uma versão do Game Kernel

Este guia é para quem **publica** o Game Kernel (não para o usuário final). A CI gera e testa instaladores, mas com
uma chave descartável: eles servem para teste, não para distribuir. Uma versão de verdade exige os passos abaixo,
feitos por você, com a chave de *release* fora do repositório e fora da CI.

## Visão geral

A chave privada de *release* nunca sai do seu computador e você não precisa compilar nada: a CI compila e monta o
produto com a sua chave **pública**, você assina o manifesto em casa e devolve só a assinatura (que não é segredo); a
CI anexa a assinatura **à mesma pasta que compilou** (sem recompilar, para os hashes baterem), gera o instalador e a
versão portátil e testa o produto instalado com a sua chave. Por fim, você confere o instalador num Windows limpo.

O que você precisa no seu computador: Python 3.11 ou mais novo com o pacote `cryptography`
(`python -m pip install cryptography`) e o código do repositório (GitHub → branch → *Code* → *Download ZIP*, ou
`git clone`). Os comandos abaixo rodam na pasta do repositório.

## 1. Gerar a chave de release (uma vez)

Em um computador confiável, de preferência desconectado da internet, gravando a chave num pendrive:

```bash
python tools/gk_keygen.py --out-dir E:\chaves-game-kernel --name release
```

* Pede uma senha (12 caracteres ou mais) e mostra o **identificador** da chave (16 caracteres hexadecimais). Anote.
* `release.key` é a chave **privada**, cifrada com a senha. Faça cópia de segurança em outra mídia. Nunca a coloque
  no repositório, na CI, em nuvem ou em e-mail: quem tem esse arquivo e a senha publica instaladores e pacotes de
  assinaturas aceitos pelo Game Kernel. (O `.gitignore` recusa `*.key`.)
* `release.pub` é a chave **pública**: copie-a para `installer/release/release.pub` no repositório e faça *commit*
  (ou envie o conteúdo para quem mantém o repositório). Ela pode ser publicada.

A mesma chave assina os pacotes de assinaturas (`.gkpkg`, seção 7) e o manifesto de integridade da instalação.

## 2. Versão

A versão do produto está em dois lugares, que precisam coincidir (um teste da CI garante isso):

* `cpp/app/CMakeLists.txt` → `project(gk_app VERSION x.y.z)`: interface, `VERSIONINFO` e instalador;
* `CMakeLists.txt` da raiz → `project(GameKernel VERSION x.y.z)`: núcleo (`gk-cli --version`).

## 3. A CI prepara a versão

Com `installer/release/release.pub` no repositório, cada execução da CI (job `windows-package`) monta, além da
versão de teste, a **versão de release** com os mesmos binários e a sua chave pública, e publica dois artefatos
(guardados por 90 dias):

* `gamekernel-release-preparada`: a pasta completa do produto, com o manifesto ainda sem assinatura;
* `gamekernel-release-manifesto`: só o `integrity_manifest.json` e o `preparo.json` (versão, número da execução,
  *commit*, identificador da chave) — é o que você baixa para assinar.

## 4. Assinar no seu computador

Baixe o artefato `gamekernel-release-manifesto` da execução que quer publicar (página da execução no GitHub → seção
*Artifacts*), extraia e rode:

```bash
python tools/release_sign.py sign <pasta extraída>\integrity_manifest.json --key E:\chaves-game-kernel\release.key
```

A ferramenta mostra a versão, a quantidade de arquivos, o identificador da chave e a execução da CI, pede a senha e
a confirmação, e recusa assinar se a versão não levar a chave pública desta chave privada. Ela grava
`assinatura.json` (versão, execução, chave e a assinatura em base64 — nada disso é segredo). Coloque esse arquivo em
`installer/release/assinatura.json` e faça *commit*.

## 5. A CI finaliza

Com `installer/release/assinatura.json` no repositório, o job `release-final` baixa a pasta preparada pela execução
indicada, anexa a assinatura e confere tudo (`tools/release_sign.py attach`: assinatura válida, pasta igual ao
manifesto, chave igual a `installer/release/release.pub`), gera o instalador e o ZIP portátil, instala em silêncio e
testa o produto instalado e o portátil exigindo a **sua** chave, roda o kit de teste em máquina limpa e publica o
artefato `gamekernel-<versão>-release` (instalador, ZIP portátil e `SHA256SUMS.txt`).

**Assinatura de código (opcional, recomendada).** Sem um certificado de assinatura de código, o Windows mostra o aviso
do SmartScreen ao abrir o instalador. Com um certificado, assine o instalador final com o `signtool` antes de
distribuir. Assinar também os executáveis internos exige assiná-los antes de montar o manifesto (passo 3), o que hoje
significa compilar no seu computador (`docs/BUILD.md`, seção *Distribuição*, e `tools/make_distribution.py --key`).

## 6. Conferir num Windows limpo

Use o kit em `installer/teste-maquina-limpa/` (veja o `LEIA-ME.txt` de lá). Com a Área Restrita do Windows
(Windows 10/11 Pro, Enterprise ou Education), coloque o `GameKernel-<versão>-setup.exe` na pasta do kit e rode:

```bash
powershell -ExecutionPolicy Bypass -File installer\teste-maquina-limpa\iniciar.ps1 -ChaveEsperada <identificador da sua chave>
```

A Área Restrita abre um Windows novo, **sem rede**, e o teste roda sozinho: instalação, o programa abre sem nada além
do que veio no instalador (runtime do Visual C++ incluído), integridade com a sua chave, varredura (com o arquivo de
teste EICAR, se o antivírus do Windows não o apagar antes), a interface abre e fecha, desinstalação preservando os
dados. O resultado aparece no Bloco de Notas e fica em `resultado-teste-<data>.txt`. No Windows Home, rode
`teste.ps1` dentro de uma máquina virtual nova.

Depois, à mão: importe um pacote `.gkpkg` assinado com a mesma chave na Central de Atualização Offline e gere um
relatório na página Relatórios.

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
