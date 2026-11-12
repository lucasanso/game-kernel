# Game Kernel

Antivírus **offline** especializado em jogos para Windows 10/11 (64 bits): investiga pastas de jogos, cracks,
repacks, mods e launchers, explica **o que** foi encontrado, **onde** (arquivo e posição dentro dele), **por que**
é suspeito e **o que fazer**, sem nunca enviar nada para a internet.

> **Estado: em desenvolvimento.** Ainda não há instalador. A interface (Qt 6 C++) já tem as páginas de atualização
> offline, análise comportamental e privacidade; as páginas de varredura chegam com os serviços do núcleo. Abaixo está o que existe
> e foi testado. O progresso detalhado está em `docs/PROGRESS_A.md` (núcleo) e `docs/PROGRESS_B.md`
> (integração, ferramentas, interface e distribuição).

## Arquitetura (híbrida C++20 / Python)

| Camada | Tecnologia | Dono |
|---|---|---|
| Interface desktop (`native/app`) | Qt 6, C++ | Agente B (em construção) |
| Serviços para a interface (`native/bridge`) | Qt 6, C++ | Agente A |
| Núcleo de análise, quarentena, tempo real, monitor de desempenho (`native/core`) | C++20, libyara, libarchive, libsodium, WinAPI | Agente A |
| Cliente do processo auxiliar e atualização offline (`native/ipc`, `native/updates`) | Qt 6 Core, C++, libsodium | Agente B |
| Processo auxiliar `gk-helper` (relatórios, sandbox) | Python 3, isolado em processo próprio | Agente B |
| Preparação de atualizações, inteligência de ameaças, testes | Python 3 | Agente B |

Detalhes: `docs/ARCHITECTURE.md`, `docs/INTEGRATION.md`, `docs/CORE_API.md`, `docs/MODULES.md`,
`docs/MIGRATION_PLAN.md`, `docs/WORK_SPLIT.md`, `contracts/`. O usuário final não precisa de Python nem de C++: tudo é distribuído junto.

## O que já funciona (testado)

* **Núcleo (A)**: SHA-256/MD5, tipo real de arquivo, parser PE para entrada hostil, motor YARA (libyara) e
  compactados em memória com limites anti-bomba (libarchive), em C++, com equivalência testada contra
  referências Python (hashlib, pefile, yara-python) e *fuzzing* sob ASan/UBSan. Detalhes em `docs/PROGRESS_A.md`.
* **Integração (B)**: processo auxiliar Python supervisionado. Uma falha, travamento ou estouro de memória do Python
  não derruba o aplicativo (prazo, cancelamento, reinício, Job Object). O cliente C++/Qt (`native/ipc`) é testado
  contra o auxiliar real no Linux e no Windows (MSVC).
* **Relatórios forenses (B)**: JSON, HTML autocontido (sem JavaScript) e PDF, com as 15 seções exigidas e um relatório
  individual por crack; nome de usuário e nome do computador omitidos por padrão.
* **Atualização offline (B)**: pacotes `.gkpkg` assinados com Ed25519, verificação em C++ (libsodium) e instalação
  atômica com reversão. As regras YARA são compiladas antes da ativação, e pacotes adulterados ou de *downgrade*
  são recusados. Ferramentas do publicador em `tools/`.
* **Inteligência de ameaças (B)**: normalização, deduplicação e detecção de conflitos de indicadores;
  *lint* e compilação de regras YARA.
* **Análise comportamental (B)**: orquestração do Windows Sandbox **sem rede**. Sem isolamento real, nada é executado.

## Princípios

* 100% offline: nenhuma telemetria, conta ou consulta externa. Os processos Python bloqueiam a rede (`netguard`),
  e o C++ não vincula bibliotecas de rede.
* Nada analisado é executado fora de uma máquina virtual descartável e sem rede.
* Evidência, não palpite: cada achado tem fonte, regra, localização e possibilidade de falso positivo; não há
  "porcentagens de infecção".
* Nada é apagado ou movido sem ação do usuário.

## Desenvolvimento

```bash
pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen python -m pytest -q
```
Os testes C++ são compilados e executados pelo pytest. Dependências de sistema e opções (sanitizadores, Windows):
`docs/BUILD.md` e `docs/TESTING.md`. Atualizações offline: `docs/OFFLINE_UPDATES.md`.
Privacidade: `docs/PRIVACY.md`. Limitações conhecidas: `docs/LIMITATIONS.md`.
