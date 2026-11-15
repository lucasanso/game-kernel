# Game Kernel — Privacidade

Esta página descreve o comportamento dos componentes já implementados e é atualizada a cada entrega.

## Nada sai do computador

* Não há telemetria, anúncios, rastreamento, conta, cadastro nem consulta online de hashes ou arquivos.
* **Processos Python** (auxiliar `gk-helper`, ferramentas): `gamekernel/netguard.py` instala um *audit hook* antes
  de qualquer outro *import* e bloqueia conexões, DNS, `urllib`/`http`/`ftp`/`smtp` e `webbrowser`, além de
  limpar variáveis de *proxy*. Os testes confirmam o bloqueio dentro do auxiliar (`tests/helper`).
* **Processos C++**: não vinculam bibliotecas de rede. A verificação de *imports* cobre os binários do núcleo
  (Agente A), a interface e tudo o que o instalador entrega (Agente B): nenhum deles importa funções de conexão,
  resolução de nomes ou envio/recebimento (`connect`, `getaddrinfo`, `send`, `recv`, WinHTTP, WinINet...), e o
  módulo de rede do Qt (`Qt6Network.dll`) não é distribuído. Única exceção, documentada e testada: o `Qt6Core.dll`
  inicializa o Winsock (`WSAStartup`/`WSACleanup`/`WSAAsyncSelect`) para o laço de eventos do Qt, sem capacidade de
  abrir conexões. O canal entre o aplicativo e o auxiliar usa **pipes anônimos**, não *sockets*.
* **Atualizações**: só por arquivo local `.gkpkg` assinado; nada é baixado.
* **Sandbox**: a máquina virtual roda com a rede desativada; tentativas de conexão da amostra são apenas registradas.

## O que é armazenado (somente no computador)

| Dado | Onde | Observação |
|---|---|---|
| Resultados de análises, histórico, quarentena, registro administrativo | `%LOCALAPPDATA%\GameKernel\gamekernel.db` (ou `data\` na versão portátil) | Caminhos e hashes dos arquivos analisados |
| Relatórios exportados | `…\GameKernel\reports\` | Só quando o usuário gera |
| Assinaturas instaladas | `…\GameKernel\signatures\` | Com histórico de instalação |
| Relatórios da sandbox | `…\GameKernel\sandbox\reports\` | Observações da máquina virtual |
| Logs | `…\GameKernel\logs\` | Locais e rotativos |
| Eventos da proteção em tempo real | `gamekernel.db` (`realtime_events`) | Caminho, SHA-256, risco e ação de cada achado nas pastas observadas |

O monitor de desempenho e o otimizador só **leem** dados locais (contadores do Windows, lista de processos, valores
do registro sobre energia e jogos, espaço livre) para mostrar na tela; nada disso é gravado, exceto o registro de
auditoria de cada limpeza de temporários (quantos arquivos e bytes).

## Relatórios

* O **nome de usuário** é trocado por `<usuário>` nos caminhos (`C:\Users\<usuário>\…`), e o **nome do
  computador** é omitido. As duas coisas podem ser incluídas por opção explícita (`reports.redact_username`,
  `reports.include_hostname`).
* Informações do computador: apenas sistema operacional e build, arquitetura, modelo e núcleos da CPU, memória
  total e fuso horário. **Nunca**: usuário, endereços MAC/IP, números de série, identificadores de hardware ou
  lista de programas instalados.
* O HTML não contém JavaScript nem recursos externos (CSP `default-src 'none'`): abrir o relatório no navegador
  não gera nenhum acesso à rede.
* O banco de dados é aberto **somente para leitura** durante a geração.

## Ambiente do processo auxiliar

O auxiliar recebe só as variáveis de ambiente essenciais do sistema e a pasta de dados. Nenhuma variável `PYTHON*`,
*proxy* ou segredo é herdada.
