# Regras de detecção YARA

Dois conjuntos de regras, com papéis diferentes:

| Conjunto | Local | Papel | Atualizável |
|---|---|---|---|
| **Regras de detecção** | `signatures/yara/*.yar` (+ `<dados>/signatures/active/yara/`) | Identificam ameaças. Cada correspondência vira uma evidência com fonte "Detecção por regra YARA". | Sim, por pacote offline assinado |
| **Indicadores de capacidade** | `signatures/internal/indicators.yar` (gerado) | Registram *o que o código pode fazer* (ex.: lê o banco de senhas do Chrome). Nunca decidem sozinhos: o motor heurístico correlaciona grupos de indicadores com imports e estrutura PE. | Junto com o aplicativo |

## Contrato de metadados (regras de detecção)

```
meta:
    description = "texto em pt-BR"
    category    = "<ThreatCategory>"          # obrigatório (ex.: rat, cryptominer, test_file)
    severity    = "CRITICAL|HIGH|MEDIUM|LOW|INFO"   # obrigatório
    confidence  = "HIGH|MEDIUM|LOW"
    verdict     = "malware|pua|suspicious|crack|mod|info|test"
    fp_note     = "quando pode ser falso positivo"
    reference   = "fonte pública"
```
`gk::yara::validate_rules_dir` (C++) rejeita pacotes cujas regras não tenham `category` e `severity`,
rejeita diretivas `include` e isola arquivos com erro de compilação.

## Regras iniciais

| Regra | Categoria | Severidade | Veredito | Lógica | Falso positivo possível |
|---|---|---|---|---|---|
| `GK_Test_EICAR` | test_file | HIGH | test | String EICAR no início, arquivo ≤ 128 bytes (especificação oficial) | Não é malware por definição |
| `GK_HackTool_Mimikatz` | credential_access | CRITICAL | malware | 2 comandos do Mimikatz, ou autor + nome, ou módulo kiwi + comando | Uso autorizado em pentest (nunca em jogos) |
| `GK_PUA_Miner_XMRig` | cryptominer | HIGH | pua | Nome `xmrig` + opção típica + algoritmo/pool | XMRig instalado conscientemente pelo usuário |
| `GK_Miner_Stratum_Configuration` | cryptominer | HIGH | suspicious | Pool Stratum + usuário + senha/algoritmo | Software de mineração legítimo |
| `GK_RAT_Quasar` | rat | CRITICAL | malware | Namespaces `Quasar.Client`/`Quasar.Common`/`xClient.Core` em executável | Uso administrativo legítimo (fora de jogos) |
| `GK_RAT_njRAT` | rat | CRITICAL | malware | 2 de: separador `|'|'|`, liberação no firewall, `SEE_MASK_NOZONECHECKS` | Improvável |
| `GK_RAT_Remcos` | rat | CRITICAL | malware | 2 de: nome, fornecedor, mutex | Uso administrativo legítimo |
| `GK_Stealer_Multi_Target` | password_stealer | CRITICAL | malware | Senhas de navegador **e** sessão do Discord **e** carteira **e** canal de envio | Improvável |
| `GK_Defender_Exclusion_With_Download` | defense_evasion | HIGH | malware | Cria exclusão no Defender **e** baixa conteúdo | Improvável em software legítimo |
| `GK_Ransomware_Recovery_Inhibition_With_Note` | ransomware | CRITICAL | malware | Destrói cópias de sombra **e** contém ≥ 2 frases de nota de resgate | Improvável |

Princípio: só entram regras de família quando os marcadores são públicos, estáveis e documentados. Nada foi
inventado: famílias sem marcadores confiáveis são cobertas pela correlação de capacidades (M7).

Strings sensíveis (EICAR, comandos do Mimikatz) ficam em hexadecimal/escapes `\xNN`, para que os arquivos de
regras não sejam detectados por outros antivírus na máquina do usuário ou de quem clona o repositório.

## Indicadores de capacidade

Tabela em `gamekernel/engines/indicators.py` (revisável), compilada para YARA por
`tools/core_gen_indicators.py`. Um teste falha se o arquivo gerado estiver desatualizado. Regras sem uma
substring fixa ("átomo" do YARA), como IP:porta, não entram na tabela: são detectadas por varredores C++
dedicados, mais rápidos e precisos.

## Assinaturas digitais (Authenticode, M4)

Duas camadas, ambas no núcleo C++ (`gk/authenticode.hpp`, `signature_rules.cpp`):

* **Estrutura e integridade (todas as plataformas, inclusive membros de compactados).** A tabela de
  certificados e cada PKCS#7 (inclusive assinaturas aninhadas) são lidos por um leitor DER limitado; o resumo
  da imagem (especificação Authenticode: exclui checksum, entrada do diretório de certificados e a própria
  tabela) é calculado com o algoritmo declarado (MD5, SHA-1, SHA-256, SHA-384, SHA-512) e comparado com o
  resumo assinado. Isso prova se o arquivo mudou depois de assinado, mas **não** prova quem assinou: sem a
  verificação da cadeia, o nome do assinante é apenas declarado.
* **Confiança (Windows).** `WinVerifyTrust` com `WTD_CACHE_ONLY_URL_RETRIEVAL`, `WTD_REVOKE_NONE` e
  `WTD_REVOCATION_CHECK_NONE` (nenhum acesso à rede: nem intermediários, nem CRL/OCSP, nem atualização de
  raízes) e consulta aos catálogos do sistema quando não há assinatura embutida.

| Regra | Severidade | Quando |
|---|---|---|
| `PE.Signature.Present` | INFO | assinatura íntegra, cadeia não verificada (fora do Windows ou dentro de compactados) |
| `PE.Signature.Trusted` | INFO | Windows confirma assinatura válida (embutida ou catálogo); preenche `signer` |
| `PE.Signature.Tampered` | LOW (alta confiança) | resumo assinado ≠ conteúdo: alterado depois de assinado. Marca o arquivo como *modificado*; traço esperado em componentes de crack reconhecidos (rebaixado para INFO) |
| `PE.Signature.Malformed` | LOW | tabela/PKCS#7 ilegível |
| `PE.Signature.HiddenData` | LOW | bytes não nulos depois do PKCS#7 dentro de `WIN_CERTIFICATE` (padrão do CVE-2013-3900) |
| `PE.Signature.UntrustedRoot` / `PE.Signature.Invalid` | LOW | cadeia termina em raiz não confiável / outra falha de verificação |
| `PE.Signature.SpoofedPublisher` | MEDIUM | assinatura não confiável cujo certificado declara o nome de uma empresa conhecida (Microsoft, Valve, NVIDIA, …; palavra inteira) |
| `PE.Signature.Revoked` / `PE.Signature.Distrusted` | HIGH | certificado revogado (dados locais) ou bloqueado pelo Windows |
| `PE.Signature.Expired` / `PE.Signature.Unverified` | INFO | expirado sem carimbo de tempo / cadeia não montável offline |

Política: **uma assinatura válida nunca reduz o risco** de outras evidências (certificados são roubados e a
revogação não pode ser consultada offline); ela aparece como informação e na explicação. Nomes vindos de
certificados são texto hostil: são decodificados e têm caracteres de controle e de direção (RLO etc.)
neutralizados antes de exibidos.
