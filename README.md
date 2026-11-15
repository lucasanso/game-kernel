# Game Kernel

Antivírus **offline** especializado em jogos para Windows 10/11 (64 bits): investiga pastas de jogos, cracks,
repacks, mods e launchers, explica **o que** foi encontrado, **onde** (arquivo e posição dentro dele), **por que**
é suspeito e **o que fazer**, sem nunca enviar nada para a internet.

> **Estado: em desenvolvimento.** Já há instalador e versão portátil para Windows, gerados e testados de ponta a
> ponta na CI (instalação silenciosa, integridade assinada, varredura real, relatório e desinstalação; ver
> `docs/INSTALL.md`). A interface (Qt 6 C++) faz varredura, análise forense, quarentena, proteção em tempo real,
> monitor de desempenho, otimizador, atualização offline, análise comportamental, relatórios e privacidade.
> Uso: `docs/USAGE.md`. Abaixo está o que existe e foi testado. O progresso detalhado está em `docs/PROGRESS_A.md` (núcleo) e `docs/PROGRESS_B.md`
> (integração, ferramentas, interface e distribuição).

## Arquitetura (híbrida C++20 / Python)

| Camada | Tecnologia | Dono |
|---|---|---|
| Interface desktop (`cpp/app`) | Qt 6, C++ | Agente B (em construção) |
| Serviços para a interface (`cpp/bridge`) | Qt 6, C++ | Agente A (escrito pelo B a pedido do usuário) |
| Proteção em tempo real (`cpp/realtime`) | Qt 6 Core, C++, ReadDirectoryChangesW | Agente A (escrito pelo B a pedido do usuário) |
| Monitor de desempenho e otimizador (`cpp/perf`, `cpp/sysopt`) | Qt 6 Core, C++, PDH, DXGI | Agente A (escrito pelo B a pedido do usuário) |
| Núcleo de análise, quarentena, tempo real, monitor de desempenho (`cpp/core`) | C++20, libyara, libarchive, libsodium, WinAPI | Agente A |
| Cliente do processo auxiliar e atualização offline (`cpp/ipc`, `cpp/updates`) | Qt 6 Core, C++, libsodium | Agente A (escritos pelo B) |
| Processo auxiliar `gk-helper` (relatórios, sandbox) | Python 3, isolado em processo próprio | Agente B |
| Preparação de atualizações, inteligência de ameaças, testes | Python 3 | Agente B |

Detalhes: `docs/ARCHITECTURE.md`, `docs/INTEGRATION.md`, `docs/CORE_API.md`, `docs/MODULES.md`,
`docs/MIGRATION_PLAN.md`, `docs/WORK_SPLIT.md`, `contracts/`. O usuário final não precisa de Python nem de C++: tudo é distribuído junto.

## O que já funciona (testado)

* **Núcleo (A)**: SHA-256/MD5, tipo real de arquivo, parser PE para entrada hostil, motor YARA (libyara),
  compactados em memória com limites anti-bomba (libarchive), camada de evidências (estrutura, nomes enganosos,
  capacidades, scripts, atalhos) e motor de risco com contexto de cracks e mods, em C++, com equivalência testada
  contra referências Python e *fuzzing* sob ASan/UBSan. Detalhes em `docs/PROGRESS_A.md`.
* **Integração (B)**: processo auxiliar Python supervisionado. Uma falha, travamento ou estouro de memória do Python
  não derruba o aplicativo (prazo, cancelamento, reinício, Job Object). O cliente C++/Qt (`cpp/ipc`) é testado
  contra o auxiliar real no Linux e no Windows (MSVC).
* **Interface (B)**: aplicativo Qt 6 C++ (`cpp/app`) com tema escuro, menu lateral e notificações internas, ligado ao
  núcleo pela camada de serviços `cpp/bridge`. Tem Painel, Segurança do jogo (varredura em processos isolados, com
  pausa e cancelamento), Análise forense (o quê, onde, por quê e o que fazer, com evidências e locais exatos),
  Histórico, Quarentena (cofre criptografado: colocar, restaurar conferindo o conteúdo, apagar, verificar),
  **Proteção em tempo real** (pastas escolhidas observadas pelo sistema; cada arquivo novo é analisado quando termina
  de ser gravado, com aviso na janela e na área de notificação e quarentena automática opcional só para ameaças
  confirmadas por assinatura; não bloqueia a execução antes da análise, o que exigiria um *driver*), **Desempenho**
  (processador, memória, placa de vídeo e memória de vídeo, disco e os programas que mais consomem, medidos pelo
  Windows), **Otimizador** (diagnóstico só de leitura com o que ajustar no próprio Windows e limpeza de temporários
  antigos com confirmação), a
  Central de Atualização Offline (importar, conferir publicador e chave, instalar, reverter, chaves confiáveis), a
  análise comportamental (disponibilidade real da sandbox, confirmação, progresso, evidências), os Relatórios
  forenses (varreduras do banco, HTML/JSON/PDF com opções de privacidade), Privacidade e rede (autoteste que tenta
  DNS e conexão de saída e comprova o bloqueio) e Configurações. Sem telas ou botões sem função.
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
