# Guia de uso do Game Kernel

O Game Kernel analisa pastas de jogos, cracks, repacks, mods e launchers **sem internet** e explica o que
encontrou, onde (arquivo e posição), por que é suspeito e o que fazer. Nada que ele analisa é executado no seu
computador; a única execução possível é a análise comportamental, dentro de uma máquina virtual descartável sem
rede, e só quando você confirma.

> **Estado desta versão.** A interface tem Painel, Segurança do jogo (varredura), Análise forense, Histórico,
> Quarentena, Central de Atualização Offline, análise comportamental, Relatórios forenses, Privacidade e rede e
> Configurações. Proteção em tempo real, monitor de desempenho e otimizador ainda não existem. Limitações conhecidas:
> `docs/LIMITATIONS.md`.

## Interface (`GameKernel.exe`)

### Painel
A situação de tudo num relance: a última varredura (ameaças e suspeitos), as assinaturas (pacote instalado e se está
desatualizado), a quarentena e a **integridade da instalação** (os arquivos do programa conferidos com o manifesto
assinado). **Analisar uma pasta de jogo…** começa uma varredura direto daqui.

### Segurança do jogo (varredura)
1. **Adicionar pasta…** ou **Adicionar arquivo…**: a pasta do jogo, do crack, do repack ou do mod.
2. Escolha **Completa** (todos os tipos, inclusive dentro de compactados) ou **Rápida** (executáveis e scripts).
3. **Iniciar varredura**. A análise roda em processos isolados e só lê os arquivos: nada é executado, movido ou
   apagado. Você pode **Pausar**, **Retomar** ou **Cancelar** (o que já foi analisado fica gravado).
4. Os achados aparecem enquanto a varredura anda; no fim, **Abrir a análise completa**.

### Análise forense
Os resultados de uma varredura: para cada arquivo, risco, classificação, categoria, se é crack ou mod reconhecido e
onde está (inclusive dentro de compactados). Ao escolher um arquivo, você vê caminho, SHA-256, assinatura digital,
**por que** foi classificado assim, **o que fazer** e as **evidências** (fonte, regra, local exato como posição ou
linha, e quando pode ser falso positivo).

**Colocar em quarentena** pede confirmação e move o arquivo para um cofre criptografado (se o arquivo mudou desde a
análise, a operação é recusada). Para um arquivo dentro de um compactado, o compactado inteiro vai para a
quarentena. **Gerar relatório** abre a página de Relatórios já na varredura certa.

### Histórico
Todas as varreduras deste computador. **Abrir a análise** (ou clique duplo) e **Gerar relatório**.

### Quarentena
Os arquivos isolados, com quando, de onde, risco, detecção e motivo. **Restaurar no local original** ou
**Restaurar em…** pedem confirmação e conferem o conteúdo com o registrado na entrada; se já houver um arquivo no
destino, o programa pergunta antes de substituir. **Apagar definitivamente** pede confirmação e não pode ser
desfeito. **Verificar cofre** autentica todos os itens.

### Central de Atualização Offline
Mantém as assinaturas (regras YARA, indicadores e bancos ClamAV) em dia **sem internet**, com pacotes `.gkpkg`
recebidos de quem publica as atualizações.

1. **Importar pacote…**: escolha o arquivo. O programa confere a assinatura digital e mostra publicador, versão,
   chave e componentes **antes** de pedir confirmação.
2. **Confirmar**: a instalação é atômica. Se algo falhar, nada muda.
3. **Reverter para a versão anterior**: volta ao conjunto anterior.

Pacotes adulterados, de publicador não confiável ou com regras inválidas são recusados, com o motivo. Instalar uma
versão **mais antiga** só acontece com confirmação explícita. Em *Chaves confiáveis*, você adiciona a chave pública
de um publicador (o programa mostra o identificador para você conferir); as chaves que vêm com o programa não
podem ser removidas pela interface. O aviso de "assinaturas desatualizadas" usa a data do pacote e a configuração
`updates.stale_after_days`.

### Análise comportamental
Observa o que um programa faz quando executado **dentro do Windows Sandbox**, sem rede e com a amostra somente
leitura.

1. Marque *Ativar a análise comportamental* (fica desligada por padrão). Se o Windows Sandbox não estiver disponível, o motivo aparece e o
   botão fica desabilitado.
2. **Escolher arquivo…**, defina o tempo de observação e clique em **Analisar na máquina virtual**; leia as
   limitações antes de confirmar.
3. Acompanhe o progresso. **Cancelar** descarta a máquina virtual.
4. As evidências mostram o que foi observado (processos, persistência, acesso a credenciais-isca, tentativas de
   rede bloqueadas, alterações em massa de arquivos), com severidade e possibilidade de falso positivo.

Um programa malicioso pode detectar a máquina virtual e não fazer nada; ausência de comportamento suspeito **não**
prova que o arquivo é seguro.

### Relatórios forenses
Gera o relatório de uma varredura registrada neste computador (hoje, as feitas com o `gk-cli`).

1. Escolha a varredura na lista (número, data, modo, alvos, ameaças, risco máximo). O banco é só lido.
2. Marque os formatos: **HTML** (para ler; sem scripts e sem acesso à internet), **JSON** (para ferramentas) e
   **PDF** (para arquivar).
3. Opções de privacidade: por padrão o nome de usuário é ocultado nos caminhos e o nome do computador não entra.
   Marque as opções só se for compartilhar o relatório com quem precisa desses dados.
4. **Gerar relatório da varredura escolhida**. Ao terminar, **Abrir relatório** abre o HTML, e a lista
   *Relatórios gerados* mostra tudo o que está na pasta de relatórios (clique duas vezes para abrir).

O relatório traz as 15 seções da análise (resumo, ameaças, cracks, locais exatos, evidências, recomendações,
limitações...) e um relatório individual para cada crack encontrado.

### Privacidade e rede
* Mostra se o processo auxiliar está ativo e com o bloqueio de rede ligado.
* **Executar autoteste** (Autoteste de rede): tenta de verdade resolver um nome (DNS) e abrir uma conexão de saída e mostra que as
  duas tentativas foram bloqueadas. Nenhum dado sai do computador.
* Lista as tentativas de rede bloqueadas nesta sessão e permite reiniciar o processo auxiliar.

### Configurações
* **Relatórios forenses**: padrões de privacidade (ocultar o nome de usuário, incluir o nome do computador).
* **Atualização offline**: depois de quantos dias (1 a 365) o programa avisa que as assinaturas estão
  desatualizadas.
* **Análise comportamental**: ativar, tempo de observação padrão (30 a 1800 s) e, opcionalmente, o `Sysmon64.exe`
  da Microsoft Sysinternals, que você precisa ter (ele não pode ser redistribuído).
* **Dados neste computador**: onde ficam o banco, os relatórios, as configurações e a quarentena.

Só aparecem opções que já têm efeito. As mudanças valem na hora para as outras páginas; **Restaurar padrões desta
página** pede confirmação e nunca apaga arquivos.

## Linha de comando (`gk-cli`)

Abra um terminal na pasta do programa (ou use o caminho completo).

```bat
gk-cli scan "D:\Jogos\MeuJogo" --json resultado.json
```

* `--quick` faz a análise rápida (arquivos de dados só pelo cabeçalho, compactados não expandidos); sem ela, a
  análise é completa, inclusive dentro de compactados.
* Código de saída: `0` sem ameaças, `3` ameaça, suspeito ou PUA encontrado, `4` cancelado, `2` erro.
* O JSON traz, para cada arquivo, risco, classificação, evidências (fonte, regra, local, possibilidade de falso
  positivo), contexto de crack/mod e recomendação.

Quarentena (os arquivos são criptografados e só voltam com sua ação):

```bat
gk-cli quarantine add "D:\Jogos\MeuJogo\arquivo.dll" --reason "detectado na varredura"
gk-cli quarantine list
gk-cli quarantine restore <id> --to "D:\Restaurados\arquivo.dll"
gk-cli quarantine delete <id>
gk-cli quarantine verify
```

Nada é apagado ou movido sem um comando seu.

## Como ler um resultado

* **Risco** (Nenhum, Informativo, Baixo, Médio, Alto, Crítico) vem das evidências, não de porcentagens inventadas.
* **Classificação**: malware, suspeito, PUA (potencialmente indesejado), modificado (crack ou mod reconhecido, sem
  ameaça), legítimo conhecido, desconhecido ou inconclusivo (a análise não pôde ser concluída, por exemplo por
  limite de tempo ou arquivo ilegível; não é um atestado de segurança).
* **Crack ou mod reconhecido** (emuladores de loja, desbloqueadores de DLC, ReShade, ENB, carregadores de mods...)
  tem os traços *esperados* atenuados, mas nunca uma detecção por assinatura, regra YARA ou comportamento.
* **Falso positivo possível** aparece quando a evidência também ocorre em programas legítimos; a explicação diz por
  quê.

## Privacidade

Nada é enviado para a internet: não há telemetria, conta, nuvem ou consulta externa. Detalhes em
`docs/PRIVACY.md`.
