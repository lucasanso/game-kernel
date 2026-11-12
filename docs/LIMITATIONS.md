# Game Kernel — Limitações conhecidas

Consolidadas a partir dos componentes implementados. As limitações por categoria de ameaça (detecção
estática) ficam em `docs/THREAT_COVERAGE.md` (Agente A) quando o motor estiver integrado.

## Gerais

* **Funcionar offline não significa proteger contra tudo.** Sem atualização automática, ameaças surgidas depois
  do último pacote importado podem não ser reconhecidas por assinatura. O aplicativo avisa quando as assinaturas
  passam do prazo configurado (padrão: 7 dias).
* A ausência de detecções **não** garante que um arquivo seja seguro.
* Os níveis de risco são qualitativos e baseados em evidências; **não** são probabilidades de infecção.
* Cracks, emuladores e ferramentas de DRM se parecem com malware em vários indicadores. Por isso a heurística aponta
  capacidades, não intenção, e cada evidência indica a possibilidade de falso positivo.
* O Windows 10 não recebe mais atualizações de segurança gratuitas desde 14/10/2025. Os relatórios mostram esse aviso.

## Análise comportamental (sandbox)

* Exige o **Windows Sandbox** (Windows 10/11 Pro, Enterprise ou Education, virtualização ativa). Sem ele, a análise
  é recusada e **nada é executado**.
* Só o comportamento ocorrido durante o tempo de observação (padrão: 120 s) é visto. Malwares podem detectar a
  máquina virtual e ficar inativos.
* Com a rede desativada, as tentativas de conexão são registradas, mas o que aconteceria depois da comunicação
  com o servidor do atacante não acontece.
* A amostra roda como administrador **dentro** da VM e poderia adulterar o relatório do monitor. Os resultados
  são evidências, nunca garantia.
* Detecção de injeção em processos: limitada sem o Sysmon (Sysinternals), que o usuário pode fornecer
  (`sandbox.sysmon_path`). O Game Kernel não o redistribui.
* O monitor (`gamekernel/engines/sandbox/monitor.ps1`) é testado estaticamente e tem a sintaxe verificada na CI Windows;
  a execução real exige o Windows Sandbox.

## Atualização offline

* A importação **direta** de bases oficiais do ClamAV (CVD avulso, sem `.gkpkg`) ainda não está disponível:
  depende da verificação RSA da Cisco Talos via `sigtool` (Agente A). Dentro de um `.gkpkg`, a autenticidade
  vem da assinatura do publicador, e o MD5 de cada CVD é conferido.
* Sem a libyara no build, pacotes com regras YARA são **recusados** (falha fechada), em vez de ativados sem validação.

## Relatórios

* O PDF usa uma fonte Unicode do sistema (Segoe UI, Arial ou DejaVu). Sem nenhuma delas, caracteres fora do
  Windows-1252 são substituídos e o aplicativo avisa; o HTML e o JSON mantêm os nomes exatos.
* Em varreduras muito grandes, o relatório lista as 20 000 ocorrências de maior risco e informa o total.

## Processo auxiliar

* Atende uma requisição por vez (fila de 32). Trabalhos longos (sandbox) ocupam o auxiliar até terminar ou ser cancelado.
* Inteiros trocados com o aplicativo devem ficar em ±2^53 (o Qt representa números JSON como `double`).
