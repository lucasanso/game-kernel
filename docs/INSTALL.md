# Instalação do Game Kernel

O Game Kernel funciona **sem internet**: nada é baixado na instalação nem depois dela, e o usuário não precisa de
Python, C++ ou qualquer outro programa.

## Requisitos

* Windows 10 (versão 1809 ou mais nova) ou Windows 11, 64 bits.
* Cerca de 400 MB livres para o programa, mais espaço para os seus dados (histórico, relatórios e quarentena).
* Opcional, para a **análise comportamental**: Windows 10/11 Pro, Enterprise ou Education com o recurso
  "Área Restrita do Windows" (Windows Sandbox) ativado e virtualização ligada no firmware. Sem ele, o resto do
  programa funciona normalmente e a análise comportamental fica desativada, explicando o motivo.

## Instalador

1. Execute `GameKernel-<versão>-setup.exe`.
2. Escolha instalar para todos os usuários (pasta *Arquivos de Programas*, pede permissão de administrador) ou só
   para você (sem administrador).
3. Ao final, abra o Game Kernel pelo menu Iniciar.

Instalação silenciosa (administradores): `GameKernel-<versão>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`
(acrescente `/CURRENTUSER` para instalar só para o usuário atual e `/DIR="pasta"` para escolher a pasta).

## Versão portátil

1. Extraia `GameKernel-<versão>-portable.zip` numa pasta em que você tenha permissão de escrita (por exemplo, um
   pendrive ou `D:\Ferramentas`). Não use *Arquivos de Programas*.
2. Execute `GameKernel.exe` dentro da pasta `GameKernel`.

O arquivo `portable.flag` faz o programa guardar os dados em `GameKernel\data`, ao lado do executável, em vez de
`%LOCALAPPDATA%\GameKernel`. Apague a pasta para remover tudo.

## Onde ficam os dados

| Instalação | Pasta de dados |
|---|---|
| Instalador | `%LOCALAPPDATA%\GameKernel` |
| Portátil | `GameKernel\data` |
| Personalizada | variável de ambiente `GAMEKERNEL_DATA_DIR` |

A pasta guarda o banco de varreduras, os relatórios, as configurações (`settings.json`), as atualizações de
assinaturas instaladas e a **quarentena** (arquivos seus, criptografados).

## Conferir a integridade

A pasta do programa traz `MANIFEST.sha256` com o SHA-256 de cada arquivo. Para conferir uma instalação:

```bash
python tools/make_distribution.py --verify "C:\Program Files\Game Kernel" --ignore unins000.exe --ignore unins000.dat
```

## Atualizar e desinstalar

* **Programa**: execute o instalador de uma versão nova; ele substitui a anterior e mantém os seus dados.
* **Assinaturas**: são atualizadas por pacotes offline assinados (`.gkpkg`), pela Central de Atualização Offline
  dentro do programa. Veja `docs/OFFLINE_UPDATES.md`.
* **Desinstalar**: *Configurações → Aplicativos → Game Kernel → Desinstalar*. O programa é removido, mas a pasta de
  dados é **mantida** de propósito: ela contém a quarentena. Restaure o que precisar e então apague a pasta
  `%LOCALAPPDATA%\GameKernel` manualmente.
