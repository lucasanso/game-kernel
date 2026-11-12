"""Human explanations for every threat category: what it is, what it can do, what data it
puts at risk, how Game Kernel detects it, the limits of that detection, and what to do."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ThreatCategory as T


@dataclass(frozen=True)
class ThreatInfo:
    label: str
    summary: str
    can_do: str
    data_at_risk: str
    detection: str
    limitations: str
    recommendations: tuple[str, ...]


_GENERIC_REMOVE = (
    "Não execute o arquivo.",
    "Coloque o arquivo em quarentena (ação reversível) ou exclua-o após confirmar.",
    "Se já foi executado: desconecte a rede, faça uma verificação completa com o Microsoft Defender "
    "(incluindo a verificação offline) e troque senhas a partir de outro dispositivo confiável.",
)

CATALOG: dict[T, ThreatInfo] = {
    T.TROJAN: ThreatInfo(
        "Trojan",
        "Programa que se apresenta como legítimo (jogo, crack, instalador) mas executa ações ocultas.",
        "Instalar outros malwares, roubar dados, abrir acesso remoto ou danificar arquivos.",
        "Qualquer dado do usuário, dependendo da carga maliciosa.",
        "Assinaturas ClamAV, regras YARA de famílias, hashes locais e correlação de capacidades.",
        "Trojans novos ou ofuscados podem não ter assinatura; a heurística aponta capacidades, não intenção.",
        _GENERIC_REMOVE,
    ),
    T.RAT: ThreatInfo(
        "Remote Access Trojan (RAT)",
        "Ferramenta de controle remoto instalada sem consentimento.",
        "Controlar o computador, capturar tela/webcam/teclado, transferir arquivos e executar comandos.",
        "Arquivos pessoais, senhas, sessões, webcam e microfone.",
        "Regras YARA de RATs conhecidos (Quasar, njRAT, Remcos…), indicadores de configuração de C2, "
        "shell reverso e persistência combinados.",
        "RATs customizados sem indicadores públicos podem passar despercebidos na análise estática.",
        _GENERIC_REMOVE + ("Verifique contas importantes quanto a acessos desconhecidos.",),
    ),
    T.KEYLOGGER: ThreatInfo(
        "Keylogger",
        "Componente que registra o que é digitado.",
        "Capturar senhas, mensagens, dados bancários e enviá-los a terceiros.",
        "Senhas, mensagens, números de cartão, frases de recuperação de carteiras.",
        "Hook de teclado de baixo nível (SetWindowsHookEx + WH_KEYBOARD_LL) combinado com gravação "
        "em arquivo ou envio pela rede; regras YARA.",
        "Jogos leem o teclado legitimamente (GetAsyncKeyState, Raw Input); por isso a leitura isolada "
        "do teclado nunca é tratada como keylogger.",
        _GENERIC_REMOVE,
    ),
    T.SPYWARE: ThreatInfo(
        "Spyware",
        "Software que coleta informações do usuário sem consentimento.",
        "Capturar tela, histórico, documentos e informações do sistema.",
        "Documentos, histórico de navegação, capturas de tela, informações de hardware.",
        "Combinação de captura de tela/área de transferência, enumeração de dados pessoais e exfiltração.",
        "Ferramentas legítimas (overlays, gravadores) usam APIs semelhantes.",
        _GENERIC_REMOVE,
    ),
    T.PASSWORD_STEALER: ThreatInfo(
        "Ladrão de senhas (stealer)",
        "Malware que extrai senhas salvas em navegadores, clientes de jogos e carteiras.",
        "Ler bancos de senhas do Chrome/Edge/Firefox, decifrá-los com DPAPI e enviar a um servidor.",
        "Senhas salvas, cartões, carteiras de criptomoedas, contas Steam/Discord/Epic.",
        "Referências aos arquivos de credenciais (Login Data, Local State, logins.json, key4.db) "
        "combinadas com CryptUnprotectData e canal de exfiltração (webhook, Telegram, HTTP).",
        "Stealers empacotados (PyInstaller cifrado, .NET ofuscado) podem esconder essas strings.",
        _GENERIC_REMOVE + ("Troque todas as senhas salvas no navegador e ative autenticação em dois fatores.",),
    ),
    T.COOKIE_STEALER: ThreatInfo(
        "Ladrão de cookies/sessões",
        "Rouba cookies e tokens para sequestrar contas sem precisar da senha.",
        "Acessar contas (Discord, Steam, Google) usando sessões roubadas, mesmo com 2FA.",
        "Cookies de navegador, tokens do Discord, sessões de launchers.",
        "Referências a bancos de cookies, ao leveldb do Discord, ao padrão de token cifrado "
        "e a canais de exfiltração.",
        "Sessões roubadas continuam válidas até serem encerradas; a detecção estática pode falhar em código cifrado.",
        _GENERIC_REMOVE + ("Encerre todas as sessões ativas nas contas e troque as senhas.",),
    ),
    T.RANSOMWARE: ThreatInfo(
        "Ransomware",
        "Malware que cifra arquivos e exige resgate.",
        "Cifrar documentos, fotos e saves; apagar cópias de sombra para impedir recuperação.",
        "Todos os arquivos acessíveis, inclusive unidades externas e de rede.",
        "Exclusão de cópias de sombra (vssadmin/wbadmin/bcdedit), notas de resgate, combinação de "
        "criptografia com enumeração em massa de arquivos; na sandbox, alteração de arquivos-isca.",
        "Ransomware novo e empacotado pode não exibir strings; a sandbox detecta o comportamento apenas "
        "se ele ocorrer durante o tempo de observação.",
        _GENERIC_REMOVE + ("Mantenha backups offline; não pague resgate.",),
    ),
    T.CRYPTOMINER: ThreatInfo(
        "Minerador de criptomoedas",
        "Usa a CPU/GPU do computador para minerar criptomoedas para terceiros.",
        "Consumir recursos, aquecer o hardware, reduzir desempenho e vida útil.",
        "Recursos de hardware e energia; às vezes acompanhado de outros malwares.",
        "Strings de pools e protocolo stratum, parâmetros do XMRig, drivers WinRing0 e regras YARA.",
        "Mineradores podem baixar a configuração em tempo de execução, sem strings estáticas.",
        _GENERIC_REMOVE,
    ),
    T.BACKDOOR: ThreatInfo(
        "Backdoor",
        "Abre uma porta de entrada oculta para o atacante.",
        "Executar comandos remotos, instalar componentes, manter acesso persistente.",
        "Todo o sistema.",
        "Shell reverso (cmd.exe com pipes + socket), escuta em portas, regras YARA.",
        "Backdoors discretos podem usar canais legítimos e não ter assinatura.",
        _GENERIC_REMOVE,
    ),
    T.ROOTKIT: ThreatInfo(
        "Rootkit / driver suspeito",
        "Componente de kernel (driver .sys) capaz de ocultar processos, arquivos ou desativar proteções.",
        "Esconder malware, desativar antivírus, ler memória de qualquer processo.",
        "Todo o sistema, inclusive credenciais em memória.",
        "Drivers sem assinatura válida, drivers conhecidos por serem abusados (BYOVD), APIs de kernel "
        "de manipulação de memória física e callbacks.",
        "Anti-cheats (EasyAntiCheat, BattlEye, Vanguard) usam drivers legítimos com APIs semelhantes; "
        "a assinatura digital é o principal diferenciador. Rootkits já ativos não são vistos por análise de arquivos.",
        _GENERIC_REMOVE + ("Use a verificação offline do Microsoft Defender para rootkits ativos.",),
    ),
    T.LOADER: ThreatInfo(
        "Loader",
        "Carrega código adicional (geralmente cifrado) na memória.",
        "Descriptografar e executar uma carga maliciosa sem gravá-la em disco.",
        "Depende da carga.",
        "Poucas importações com resolução dinâmica de APIs, alocação executável, dados de alta entropia.",
        "Protetores de DRM e empacotadores legítimos têm estrutura parecida.",
        _GENERIC_REMOVE,
    ),
    T.DROPPER: ThreatInfo(
        "Dropper",
        "Carrega outro executável embutido e o grava/executa no sistema.",
        "Instalar malware adicional sem o usuário perceber.",
        "Depende da carga instalada.",
        "Executáveis embutidos em recursos ou no overlay, combinados com gravação em pastas temporárias e execução.",
        "Instaladores legítimos também carregam executáveis embutidos.",
        _GENERIC_REMOVE,
    ),
    T.DOWNLOADER: ThreatInfo(
        "Downloader malicioso",
        "Baixa e executa programas da internet.",
        "Instalar malware atualizado do servidor do atacante.",
        "Depende do que for baixado.",
        "URLDownloadToFile, WebClient, certutil/bitsadmin/Invoke-WebRequest combinados com execução; "
        "URLs de hospedagens frequentemente abusadas.",
        "Launchers e atualizadores legítimos também baixam arquivos; o destino e a forma de execução diferenciam.",
        _GENERIC_REMOVE,
    ),
    T.DLL_HIJACKING: ThreatInfo(
        "DLL hijacking / sideloading",
        "DLL com nome de biblioteca do sistema colocada ao lado do executável para ser carregada no lugar da original.",
        "Executar código dentro do processo do jogo a cada inicialização.",
        "Tudo o que o processo do jogo acessa.",
        "DLLs com nomes de bibliotecas do Windows na pasta do jogo, exportações encaminhadas (proxy), "
        "ausência de assinatura e capacidades perigosas no código.",
        "ReShade, ENB, ASI Loader, SpecialK, DXVK e muitos cracks usam exatamente esta técnica de forma legítima.",
        (
            "Verifique se a DLL pertence a um mod que você instalou conscientemente.",
            "Se não reconhecer a DLL, coloque-a em quarentena e teste o jogo.",
        ),
    ),
    T.PROCESS_INJECTION: ThreatInfo(
        "Injeção de processos",
        "Técnica para executar código dentro de outro processo.",
        "Esconder atividade maliciosa em processos confiáveis, roubar dados de navegadores.",
        "Dados de qualquer processo atingido.",
        "Conjuntos de APIs de injeção (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread; "
        "process hollowing com SetThreadContext/ResumeThread; APC).",
        "Trainers, overlays, mod loaders, anti-cheats e alguns cracks injetam código legitimamente.",
        ("Avalie se o arquivo é um trainer/mod que você instalou; caso contrário, quarentena.",),
    ),
    T.PERSISTENCE: ThreatInfo(
        "Persistência maliciosa",
        "Mecanismo para se manter ativo após reinicializações ou após fechar o jogo.",
        "Iniciar automaticamente com o Windows (Run, tarefas agendadas, serviços, WMI).",
        "Permite que qualquer outra ameaça continue ativa.",
        "Chaves Run/RunOnce, schtasks, serviços, pasta Inicializar, assinaturas WMI, Winlogon, IFEO.",
        "Launchers e atualizadores legítimos usam inicialização automática.",
        _GENERIC_REMOVE + ("Revise a inicialização no Gerenciador de Tarefas e no Agendador de Tarefas.",),
    ),
    T.MALICIOUS_SCRIPT: ThreatInfo(
        "Script malicioso",
        "Script (BAT, PowerShell, VBS, JS, HTA) que executa ações perigosas.",
        "Baixar malware, desativar proteções, alterar o sistema, roubar dados.",
        "Depende das ações do script.",
        "Análise linha a linha com decodificação de -EncodedCommand e detecção de ofuscação.",
        "Ofuscação avançada pode esconder a intenção; scripts de instalação legítimos também alteram o sistema.",
        _GENERIC_REMOVE,
    ),
    T.OBFUSCATION: ThreatInfo(
        "Executável ofuscado/empacotado",
        "Código comprimido, cifrado ou ofuscado para dificultar análise.",
        "Esconder a funcionalidade real do programa.",
        "Indefinido — a ofuscação por si só não causa dano.",
        "Entropia de seções, nomes de seções de empacotadores, importações mínimas, obfuscadores .NET.",
        "DRM (Denuvo, VMProtect, Themida) e anti-cheats usam ofuscação legítima. Nunca é prova isolada de malware.",
        ("Trate como evidência insuficiente; avalie em conjunto com os demais achados.",),
    ),
    T.SYSTEM_MODIFICATION: ThreatInfo(
        "Modificação suspeita do Windows",
        "Alterações em arquivos ou configurações do sistema.",
        "Alterar o arquivo hosts, substituir arquivos do System32, desativar UAC ou alterar políticas.",
        "Integridade e segurança do sistema.",
        "Comandos e chaves de registro sensíveis em scripts, arquivos .reg e executáveis.",
        "Cracks às vezes bloqueiam servidores de ativação pelo arquivo hosts — é uma alteração real do sistema, "
        "mesmo sem ser malware.",
        ("Revise o que será alterado antes de executar; faça um ponto de restauração.",),
    ),
    T.CREDENTIAL_ACCESS: ThreatInfo(
        "Acesso a credenciais",
        "Tentativa de ler senhas ou segredos do sistema.",
        "Ler a memória do LSASS, o SAM, cofres de credenciais ou senhas de Wi-Fi.",
        "Senhas do Windows, hashes, credenciais de rede.",
        "Ferramentas de dump (mimikatz), acesso a lsass, reg save SAM, netsh wlan show profile key=clear.",
        "Ferramentas administrativas legítimas podem acessar credenciais com autorização.",
        _GENERIC_REMOVE,
    ),
    T.STEALTH: ThreatInfo(
        "Ocultação de execução",
        "Componentes que tentam esconder sua execução ou se passar por processos do Windows.",
        "Rodar escondido, com nomes de processos do sistema, ou com atributos ocultos.",
        "Dificulta a identificação de outras ameaças.",
        "Nomes de processos do sistema fora do System32, nomes parecidos (typosquatting), "
        "janelas ocultas, attrib +h +s, extensões duplas.",
        "Alguns utilitários legítimos rodam sem janela.",
        _GENERIC_REMOVE,
    ),
    T.NETWORK_COMMUNICATION: ThreatInfo(
        "Comunicação não autorizada",
        "Indícios de comunicação com servidores do atacante.",
        "Enviar dados roubados ou receber comandos.",
        "Qualquer dado coletado.",
        "Webhooks do Discord, bots do Telegram, DNS dinâmico, sites de paste, .onion, IP:porta literais.",
        "Jogos e launchers usam a rede legitimamente; só destinos atípicos são sinalizados.",
        _GENERIC_REMOVE,
    ),
    T.DEFENSE_EVASION: ThreatInfo(
        "Desativação de proteções",
        "Tentativa de desativar o antivírus, o firewall ou adicionar exclusões.",
        "Abrir caminho para que outros malwares rodem sem detecção.",
        "Todo o sistema.",
        "Set-/Add-MpPreference (exclusões, desativar monitoramento), netsh advfirewall off, "
        "encerramento de processos de antivírus, alterações de políticas do Defender.",
        "Muitos guias de cracks pedem para desativar o antivírus — isso NÃO torna o pedido seguro.",
        _GENERIC_REMOVE + ("Verifique se o Defender está ativo e sem exclusões desconhecidas.",),
    ),
    T.PUA: ThreatInfo(
        "Potencialmente indesejado (PUA)",
        "Software que não é necessariamente malicioso, mas pode ser indesejado (keygens, patchers, adware).",
        "Exibir anúncios, alterar configurações, conter riscos de segurança.",
        "Varia.",
        "Assinaturas PUA do ClamAV e regras YARA de ferramentas.",
        "Keygens e patchers são classificados como PUA por natureza, mesmo sem carga maliciosa.",
        ("Avalie se o componente é realmente necessário.",),
    ),
    T.GENERIC_MALWARE: ThreatInfo(
        "Malware",
        "Arquivo identificado por assinatura ou indicador local como malicioso.",
        "Depende da família.",
        "Depende da família.",
        "Assinatura ClamAV ou hash de ameaça conhecido.",
        "Assinaturas genéricas podem raramente gerar falsos positivos.",
        _GENERIC_REMOVE,
    ),
    T.CRACK_COMPONENT: ThreatInfo(
        "Componente de crack",
        "Arquivo usado para contornar DRM (emulador de Steam/Epic/Ubisoft, exe modificado, patch).",
        "Por si só: permitir executar o jogo sem DRM. Pode ser usado como veículo de malware.",
        "Nenhum por si só.",
        "Arquivos de configuração e strings de grupos/emuladores, DLLs de API substituídas sem assinatura.",
        "Reconhecer um crack NÃO garante que ele seja seguro: a análise de ameaças continua sendo aplicada.",
        ("Prefira cracks cujo hash você possa comparar com fontes confiáveis.",),
    ),
    T.MOD_COMPONENT: ThreatInfo(
        "Componente de mod",
        "Ferramenta de modificação comum (ReShade, ENB, ASI Loader, SpecialK, DXVK).",
        "Alterar gráficos/comportamento do jogo.",
        "Nenhum por si só.",
        "Strings e estruturas características dos projetos.",
        "Cópias adulteradas de mods conhecidos existem; a análise de ameaças continua aplicada.",
        ("Baixe mods apenas das páginas oficiais dos projetos.",),
    ),
    T.STRUCTURAL_ANOMALY: ThreatInfo(
        "Anomalia estrutural",
        "Estrutura de arquivo incomum ou corrompida.",
        "Pode quebrar analisadores ou esconder dados.",
        "Indefinido.",
        "Validação do formato PE e de compactados.",
        "Arquivos corrompidos por download incompleto geram as mesmas anomalias.",
        ("Verifique a integridade do download (hash/SFV).",),
    ),
    T.TEST_FILE: ThreatInfo(
        "Arquivo de teste antivírus",
        "Arquivo padrão (EICAR) usado para testar antivírus. É inofensivo.",
        "Nada — serve apenas para validar a detecção.",
        "Nenhum.",
        "Assinatura, hash e regra YARA dedicadas.",
        "—",
        ("Nenhuma ação necessária além de remover o arquivo de teste.",),
    ),
    T.INFORMATIONAL: ThreatInfo(
        "Informação técnica",
        "Característica técnica registrada para contexto.",
        "—",
        "—",
        "Análise estática.",
        "Não representa risco por si só.",
        (),
    ),
}


def info(category: T) -> ThreatInfo:
    return CATALOG.get(category, CATALOG[T.INFORMATIONAL])
