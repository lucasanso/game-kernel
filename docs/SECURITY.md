# Segurança do Game Kernel

## Modelo de ameaça
Os arquivos analisados são **hostis**: podem ter estruturas malformadas para explorar parsers, bombas de
compressão, caminhos maliciosos em compactados e nomes enganosos. O próprio aplicativo não pode virar
vetor de ataque nem enfraquecer as defesas do Windows.

## Controles

| Área | Controle |
|---|---|
| Segurança de memória (C++) | Leitor `ByteView` com limites verificados em toda leitura; aritmética de offsets com verificação de overflow; nenhum `memcpy`/ponteiro cru sobre dados do arquivo fora do leitor; RAII para handles e mapeamentos; build de testes com ASan/UBSan; fuzzing por mutação dos parsers |
| Assinaturas digitais | Verificação de confiança só com dados locais (`WinVerifyTrust` com recuperação de URL restrita ao cache e sem consulta de revogação); PKCS#7 hostil lido por leitor DER limitado (sem comprimento indefinido, tags estendidas ou elementos além do pai), dentro do processo isolado; nomes de certificados com caracteres de controle/direção neutralizados; uma assinatura válida nunca reduz o risco de outras evidências |
| Isolamento | Parsers em `gk-scanworker` com Job Object (limite de memória, sem processos filhos, encerrado com o pai) e integridade baixa (não consegue gravar em arquivos do usuário) |
| Compactados | Limites de profundidade, número de membros, tamanho total, tamanho por membro e razão de compressão; nomes de membros nunca viram caminhos de disco; extração apenas em memória |
| Execução | Nenhum arquivo analisado é executado, carregado (`LoadLibrary`) ou aberto por associação do shell. Subprocessos: caminho absoluto, sem shell, `cwd` = pasta da ferramenta, binário verificado no manifesto de integridade |
| Rede | Nenhuma biblioteca de rede vinculada nos binários C++ (teste de imports); `netguard` nos processos Python; regras de firewall opcionais |
| Quarentena | XChaCha20-Poly1305 com chave protegida por DPAPI; extensão `.gkq`; SHA-256 verificado antes de restaurar; operações registradas no log de auditoria encadeado |
| Atualizações | Pacote assinado com Ed25519; verificação no núcleo C++ antes de qualquer extração; hash de cada arquivo; rejeição de caminhos fora do pacote; instalação atômica com rollback; anti-downgrade |
| Integridade | Manifesto assinado dos componentes instalados, verificado na inicialização e antes de executar binários auxiliares |
| Auditoria | Log administrativo encadeado por SHA-256 (adulteração detectável) |
| Privacidade | Sem telemetria; relatórios com nome de usuário ocultado por padrão |
| Coexistência | Não desativa nem altera o Microsoft Defender; sem drivers de kernel; sem hooks |
