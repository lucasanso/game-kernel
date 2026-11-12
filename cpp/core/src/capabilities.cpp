// Capability correlation: indicator groups (YARA, signatures/internal/indicators.yar) + imported APIs.
// A capability alone is weak evidence; combinations that have no legitimate use in games, cracks or mods
// raise the severity. Every rule documents its false-positive scenario.
#include <algorithm>
#include <map>
#include <set>
#include <string>

#include "evidence_util.hpp"
#include "gk/analysis.hpp"
#include "gk/filetype.hpp"

namespace gk::analysis {

namespace {

using detail::make;

class Correlator {
public:
    Correlator(const std::vector<IndicatorHit>& hits, const pe::PeInfo* pe, bool is_script,
               const std::vector<Location>& netlits, std::vector<Evidence>& out)
        : pe_(pe), script_(is_script), netlits_(netlits), out_(out) {
        for (const auto& h : hits) groups_[h.group].push_back(&h);
        if (pe != nullptr) {
            for (const auto& imp : pe->imports) {
                if (!imp.name.empty()) imports_.insert(lower_ascii(imp.name));
            }
        }
    }

    void run();

private:
    bool has(const std::string& g) const { return groups_.count(g) != 0; }
    bool imp(std::initializer_list<const char*> names) const {
        for (const char* n : names) {
            if (imports_.count(n)) return true;
        }
        return false;
    }
    bool imp_all(std::initializer_list<const char*> names) const {
        for (const char* n : names) {
            if (!imports_.count(n)) return false;
        }
        return true;
    }
    bool exfil() const {
        return has("exfil_webhook") || has("exfil_filehost") || has("ip_lookup") || !netlits_.empty();
    }
    bool network_api() const {
        return imp({"internetopena", "internetopenw", "internetopenurla", "internetopenurlw", "httpsendrequesta",
                    "httpsendrequestw", "winhttpopen", "winhttpsendrequest", "urldownloadtofilea", "urldownloadtofilew",
                    "send", "wsasend", "connect", "wsaconnect", "socket", "wsasocketa", "wsasocketw",
                    "internetconnecta", "internetconnectw"});
    }
    // Attach locations and matched texts of the given groups.
    void attach(Evidence& e, std::initializer_list<const char*> groups) const {
        std::set<std::string> matched;
        for (const char* g : groups) {
            auto it = groups_.find(g);
            if (it == groups_.end()) continue;
            for (const IndicatorHit* h : it->second) {
                for (const auto& l : h->locations) {
                    if (e.locations.size() < 10) e.locations.push_back(l);
                }
                for (const auto& m : h->matched) matched.insert(m);
                e.details["indicador:" + h->id] = h->description;
            }
        }
        std::string joined;
        for (const auto& m : matched) {
            if (joined.size() > 400) break;
            joined += (joined.empty() ? "" : " | ") + m;
        }
        if (!joined.empty()) e.details["trechos"] = joined;
    }
    void attach_netlits(Evidence& e) const {
        for (const auto& l : netlits_) {
            if (e.locations.size() < 10) e.locations.push_back(l);
        }
    }
    void imports_detail(Evidence& e, std::initializer_list<const char*> names) const {
        std::string list;
        for (const char* n : names) {
            if (imports_.count(n)) list += (list.empty() ? "" : ", ") + std::string(n);
        }
        if (!list.empty()) {
            e.details["imports"] = list;
            Location l;
            l.kind = "import";
            l.description = "APIs importadas: " + list;
            e.locations.push_back(l);
        }
    }
    void emit(Evidence e) {
        e.engine = "capabilities";
        out_.push_back(std::move(e));
    }

    std::map<std::string, std::vector<const IndicatorHit*>> groups_;
    std::set<std::string> imports_;
    const pe::PeInfo* pe_;
    bool script_;
    const std::vector<Location>& netlits_;
    std::vector<Evidence>& out_;
};

void Correlator::run() {
    const std::size_t start = out_.size();
    const bool decrypt = has("dpapi") || has("chrome_key") || imp({"cryptunprotectdata"});

    // ---- credentials and sessions -------------------------------------------------------------------
    if (has("browser_credentials")) {
        if (decrypt && exfil()) {
            Evidence e = make("HEUR.Stealer.BrowserPasswords", "Rouba senhas salvas no navegador e as envia",
                              Source::Heuristic, category::kPasswordStealer, Risk::High, Confidence::Medium,
                              "Lê o banco de senhas dos navegadores, usa DPAPI/chave do Chrome para decifrá-lo e "
                              "contém um canal de envio (webhook, API, IP).",
                              "Ferramentas de recuperação de senha fazem o mesmo, mas não enviam os dados pela internet.");
            attach(e, {"browser_credentials", "dpapi", "chrome_key", "exfil_webhook", "exfil_filehost", "ip_lookup"});
            attach_netlits(e);
            emit(std::move(e));
        } else if (decrypt) {
            Evidence e = make("HEUR.Stealer.BrowserPasswordDecryption", "Lê e decifra senhas salvas do navegador",
                              Source::Heuristic, category::kPasswordStealer, Risk::Medium, Confidence::Low,
                              "Referencia o banco de senhas dos navegadores e as funções usadas para decifrá-lo.",
                              "Gerenciadores e utilitários de migração de senhas fazem isso legitimamente.");
            attach(e, {"browser_credentials", "dpapi", "chrome_key"});
            emit(std::move(e));
        } else {
            Evidence e = make("HEUR.Credentials.BrowserStoreReference", "Referência ao banco de senhas do navegador",
                              Source::Heuristic, category::kCredentialAccess, Risk::Low, Confidence::Low,
                              "Menciona arquivos onde os navegadores guardam senhas.",
                              "Navegadores, limpadores e ferramentas de backup citam esses arquivos.");
            attach(e, {"browser_credentials"});
            emit(std::move(e));
        }
    }
    static const char* kTargets[] = {"browser_credentials", "browser_cookies", "discord_token", "game_sessions",
                                     "crypto_wallets",      "messenger_sessions", "app_credentials", "wifi_creds",
                                     "browser_profiles"};
    std::size_t targets = 0;
    for (const char* t : kTargets) targets += has(t) ? 1 : 0;
    if (targets >= 3) {
        Evidence e = make("HEUR.Stealer.Profile", "Perfil de ladrão de dados (" + std::to_string(targets) + " alvos)",
                          Source::Heuristic, category::kPasswordStealer, exfil() ? Risk::Critical : Risk::High,
                          Confidence::Medium,
                          "O arquivo visa vários depósitos de credenciais ao mesmo tempo (navegadores, sessões, "
                          "carteiras, mensageiros) — combinação característica de stealers.",
                          "Nenhum jogo, crack ou mod precisa acessar esses dados.");
        attach(e, {"browser_credentials", "browser_cookies", "discord_token", "game_sessions", "crypto_wallets",
                   "messenger_sessions", "app_credentials", "wifi_creds", "browser_profiles"});
        emit(std::move(e));
    }
    if (has("browser_cookies") || has("discord_token")) {
        const bool high = exfil();
        Evidence e = make("HEUR.Stealer.Sessions", "Coleta cookies ou tokens de sessão",
                          Source::Heuristic, category::kCookieStealer, high ? Risk::High : Risk::Medium,
                          high ? Confidence::Medium : Confidence::Low,
                          "Lê cookies de navegadores e/ou tokens do Discord, que permitem entrar nas contas sem senha" +
                              std::string(high ? ", e contém um canal de envio." : "."),
                          "Navegadores e o próprio Discord acessam esses arquivos; jogos e cracks não.");
        attach(e, {"browser_cookies", "discord_token", "exfil_webhook", "exfil_filehost"});
        emit(std::move(e));
    }
    if (has("game_sessions")) {
        Evidence e = make("HEUR.Stealer.GameAccounts", "Acessa sessões de contas de jogos",
                          Source::Heuristic, category::kCookieStealer, exfil() ? Risk::High : Risk::Low,
                          Confidence::Low,
                          "Referencia arquivos de sessão/credenciais de launchers (Steam, Epic, Riot, Battle.net, Minecraft).",
                          "Launchers e gerenciadores de contas leem esses arquivos; a combinação com envio de dados é que preocupa.");
        attach(e, {"game_sessions", "exfil_webhook", "exfil_filehost"});
        emit(std::move(e));
    }
    if (has("crypto_wallets")) {
        Evidence e = make("HEUR.Stealer.Wallets", "Procura carteiras de criptomoedas",
                          Source::Heuristic, category::kPasswordStealer,
                          (exfil() || targets >= 2) ? Risk::High : Risk::Medium, Confidence::Low,
                          "Referencia arquivos e extensões de carteiras (wallet.dat, Exodus, MetaMask...).",
                          "As próprias carteiras citam seus arquivos; jogos não.");
        attach(e, {"crypto_wallets"});
        emit(std::move(e));
    }
    if (has("mimikatz") || has("lsass_dump") || has("sam_dump")) {
        Evidence e = make("HEUR.Credentials.OsSecrets", "Extrai credenciais do Windows",
                          Source::Heuristic, category::kCredentialAccess,
                          has("mimikatz") ? Risk::Critical : Risk::High, Confidence::Medium,
                          "Comandos para copiar a memória do LSASS, as colmeias SAM/SECURITY ou ferramentas como o Mimikatz.",
                          "Só faz sentido em testes de intrusão autorizados.");
        attach(e, {"mimikatz", "lsass_dump", "sam_dump"});
        emit(std::move(e));
    }
    if (has("wifi_creds")) {
        Evidence e = make("HEUR.Credentials.WiFi", "Extrai senhas de redes Wi-Fi", Source::Heuristic,
                          category::kCredentialAccess, exfil() ? Risk::High : Risk::Medium, Confidence::Medium,
                          "Usa 'netsh wlan show profile ... key=clear' para revelar senhas de Wi-Fi.",
                          "Scripts de suporte técnico às vezes fazem isso.");
        attach(e, {"wifi_creds"});
        emit(std::move(e));
    }

    // ---- spying ---------------------------------------------------------------------------------
    if (has("keylog_labels")) {
        const bool hook = imp({"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate",
                               "getkeyboardstate", "registerrawinputdevices"});
        const Risk sev = hook ? ((exfil() || network_api()) ? Risk::High : Risk::Medium) : Risk::Low;
        Evidence e = make("HEUR.Keylogger", "Registra o que é digitado", Source::Heuristic, category::kKeylogger, sev,
                          hook ? Confidence::Medium : Confidence::Low,
                          "Contém rótulos de teclas usados para gravar digitação ([ENTER], [BACKSPACE]...)" +
                              std::string(hook ? " e lê o teclado globalmente." : "."),
                          "Jogos leem o teclado, mas não formatam um registro de teclas como este.");
        attach(e, {"keylog_labels"});
        imports_detail(e, {"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate"});
        emit(std::move(e));
    }
    if (has("clipboard") && has("crypto_regex")) {
        Evidence e = make("HEUR.Clipper", "Troca endereços de criptomoeda copiados (clipper)", Source::Heuristic,
                          category::kSpyware, Risk::High, Confidence::Medium,
                          "Monitora a área de transferência e reconhece endereços de carteiras — técnica para trocar o "
                          "destino de transferências pelo do atacante.",
                          "Carteiras legítimas validam endereços, mas não vigiam a área de transferência.");
        attach(e, {"clipboard", "crypto_regex"});
        emit(std::move(e));
    }
    if (has("screenshot") || has("webcam")) {
        Evidence e = make("HEUR.Spyware.Capture", "Captura tela ou webcam", Source::Heuristic, category::kSpyware,
                          exfil() ? Risk::High : Risk::Low, Confidence::Low,
                          "Funções/strings de captura de tela ou da webcam" +
                              std::string(exfil() ? ", com canal de envio de dados." : "."),
                          "Gravadores de jogo e overlays capturam a tela legitimamente.");
        attach(e, {"screenshot", "webcam"});
        emit(std::move(e));
    }
    if (has("av_enum")) {
        Evidence e = make("HEUR.Recon.Antivirus", "Verifica quais antivírus estão instalados", Source::Heuristic,
                          category::kSpyware, Risk::Low, Confidence::Low,
                          "Consulta o SecurityCenter2 do Windows (lista de antivírus) — reconhecimento típico de stealers.",
                          "Ferramentas de diagnóstico também consultam.");
        attach(e, {"av_enum"});
        emit(std::move(e));
    }

    // ---- ransomware / miners ----------------------------------------------------------------------
    if (has("ransom_shadow")) {
        const bool note = has("ransom_note");
        Evidence e = make("HEUR.Ransomware.RecoveryInhibition",
                          note ? "Destrói backups e contém nota de resgate" : "Apaga cópias de sombra/recuperação do Windows",
                          Source::Heuristic, category::kRansomware, note ? Risk::Critical : Risk::High,
                          note ? Confidence::High : Confidence::Medium,
                          "Comandos para apagar as cópias de sombra ou desativar a recuperação do Windows — passo "
                          "usado por ransomware para impedir a restauração dos arquivos.",
                          "Ferramentas de backup/limpeza raramente fazem isso, e nunca jogos.");
        attach(e, {"ransom_shadow", "ransom_note"});
        emit(std::move(e));
    } else if (has("ransom_note")) {
        Evidence e = make("HEUR.Ransomware.Note", "Texto de nota de resgate", Source::Heuristic, category::kRansomware,
                          Risk::Medium, Confidence::Low, "Frases típicas de notas de resgate.",
                          "Textos sobre segurança podem conter as mesmas frases.");
        attach(e, {"ransom_note"});
        emit(std::move(e));
    }
    if (has("miner")) {
        Evidence e = make("HEUR.Miner", "Minerador de criptomoedas", Source::Heuristic, category::kCryptominer,
                          Risk::High, Confidence::Medium,
                          "Protocolo/pools/parâmetros de mineração. Dentro de um jogo ou crack, indica um minerador oculto.",
                          "Só é legítimo em programas de mineração que você instalou conscientemente.");
        attach(e, {"miner"});
        emit(std::move(e));
    } else if (has("winring0")) {
        Evidence e = make("HEUR.WinRing0", "Driver WinRing0 (acesso direto ao hardware)", Source::Heuristic,
                          category::kPua, Risk::Low, Confidence::Low,
                          "Referência ao driver WinRing0, usado por mineradores para ajustar a CPU e por utilitários de hardware.",
                          "Ferramentas de controle de ventoinha/RGB o usam legitimamente.");
        attach(e, {"winring0"});
        emit(std::move(e));
    }

    // ---- persistence ------------------------------------------------------------------------------
    for (const char* g : {"persist_wmi", "persist_ifeo", "persist_appinit", "persist_winlogon"}) {
        if (!has(g)) continue;
        Evidence e = make(std::string("HEUR.Persistence.") + g, "Persistência furtiva no Windows", Source::Heuristic,
                          category::kPersistence, Risk::High, Confidence::Medium,
                          "Usa um mecanismo de inicialização pouco visível (WMI, Image File Execution Options, "
                          "AppInit_DLLs ou Winlogon) para continuar ativo.",
                          "Raríssimo em software de consumo; ferramentas corporativas podem usar WMI.");
        attach(e, {g});
        emit(std::move(e));
    }
    if (has("persist_run") || has("persist_schtasks") || has("persist_startup") || has("persist_service")) {
        Evidence e = make("HEUR.Persistence.Autostart", "Configura inicialização automática", Source::Heuristic,
                          category::kPersistence, Risk::Medium, Confidence::Low,
                          "Cria entrada de inicialização (chave Run, tarefa agendada, pasta Inicializar ou serviço) para "
                          "rodar quando o Windows inicia — mesmo depois de fechar o jogo.",
                          "Launchers, atualizadores e drivers de periféricos fazem isso legitimamente.");
        attach(e, {"persist_run", "persist_schtasks", "persist_startup", "persist_service"});
        emit(std::move(e));
    }

    // ---- defense evasion -----------------------------------------------------------------------------
    if (has("defender_tamper")) {
        Evidence e = make("HEUR.DefenseEvasion.Defender", "Altera ou desativa o Microsoft Defender", Source::Heuristic,
                          category::kDefenseEvasion, Risk::High, Confidence::High,
                          "Cria exclusões ou desativa proteções do Defender — passo comum para deixar outro malware rodar.",
                          "Guias de cracks pedem exclusões, mas um arquivo que as cria sozinho é um dropper.");
        attach(e, {"defender_tamper"});
        emit(std::move(e));
    }
    if (has("uac_bypass")) {
        Evidence e = make("HEUR.DefenseEvasion.UacBypass", "Técnica de contorno do UAC", Source::Heuristic,
                          category::kDefenseEvasion, Risk::High, Confidence::Medium,
                          "Altera chaves usadas para elevar privilégios sem o aviso do UAC (fodhelper, eventvwr, sdclt).",
                          "Sem uso legítimo em jogos.");
        attach(e, {"uac_bypass"});
        emit(std::move(e));
    }
    if (has("uac_disable") || has("firewall_tamper") || has("log_clear")) {
        Evidence e = make("HEUR.DefenseEvasion.SystemProtections", "Desativa proteções do Windows",
                          Source::Heuristic, category::kDefenseEvasion, Risk::Medium, Confidence::Low,
                          "Altera o UAC, o firewall ou apaga logs de eventos.",
                          "Ferramentas administrativas podem fazer isso com autorização.");
        attach(e, {"uac_disable", "firewall_tamper", "log_clear"});
        emit(std::move(e));
    }
    if (has("av_processes")) {
        const bool kill = has("taskkill");
        Evidence e = make("HEUR.DefenseEvasion.AntivirusProcesses",
                          kill ? "Encerra processos de antivírus" : "Lista processos de antivírus", Source::Heuristic,
                          category::kDefenseEvasion, kill ? Risk::High : Risk::Low, Confidence::Medium,
                          "Contém nomes de processos de vários antivírus" +
                              std::string(kill ? " e comandos para encerrá-los." : "."),
                          "Ferramentas de diagnóstico listam antivírus, mas não os encerram.");
        attach(e, {"av_processes", "taskkill"});
        emit(std::move(e));
    }
    if (has("amsi_bypass")) {
        Evidence e = make("HEUR.DefenseEvasion.Amsi", "Contorna o AMSI (varredura de scripts)", Source::Heuristic,
                          category::kDefenseEvasion, Risk::High, Confidence::Medium,
                          "Referências para desligar o AMSI, que permite ao antivírus inspecionar scripts em execução.",
                          "Sem uso legítimo em jogos.");
        attach(e, {"amsi_bypass"});
        emit(std::move(e));
    }
    if (has("anti_vm") || has("anti_analysis")) {
        Evidence e = make("HEUR.AntiAnalysis", "Detecta máquinas virtuais ou ferramentas de análise",
                          Source::Heuristic, category::kStealth, Risk::Low, Confidence::Low,
                          "Procura sinais de VM/sandbox ou de ferramentas de análise para mudar de comportamento.",
                          "DRM e anti-cheats também detectam VMs e depuradores.");
        attach(e, {"anti_vm", "anti_analysis"});
        emit(std::move(e));
    }

    // ---- download / execution ---------------------------------------------------------------------
    if (has("dl_powershell") || has("dl_lolbin")) {
        Evidence e = make("HEUR.Downloader.ScriptOrLolbin", "Baixa e executa código da internet", Source::Heuristic,
                          category::kDownloader, Risk::High, Confidence::Medium,
                          "Usa PowerShell (DownloadString/Invoke-WebRequest) ou ferramentas do Windows (certutil, "
                          "bitsadmin, mshta, regsvr32) para baixar e executar conteúdo.",
                          "Scripts de instalação legítimos raramente baixam e executam assim.");
        attach(e, {"dl_powershell", "dl_lolbin", "payload_host"});
        emit(std::move(e));
    } else if (has("dl_urlmon") || imp({"urldownloadtofilea", "urldownloadtofilew"})) {
        const bool staged = has("temp_exec") || has("payload_host");
        Evidence e = make("HEUR.Downloader.UrlMon", "Baixa arquivos da internet", Source::Heuristic,
                          category::kDownloader, staged ? Risk::Medium : Risk::Low, Confidence::Low,
                          "Usa URLDownloadToFile" +
                              std::string(staged ? " e grava/executa programas em pastas temporárias ou hospedagens abusadas." : "."),
                          "Atualizadores e launchers baixam arquivos legitimamente.");
        attach(e, {"dl_urlmon", "temp_exec", "payload_host"});
        emit(std::move(e));
    }
    if (has("ps_hidden") || has("ps_obfuscation")) {
        Evidence e = make("HEUR.Script.HiddenOrObfuscatedPowerShell", "PowerShell oculto ou ofuscado",
                          Source::Heuristic, script_ ? category::kMaliciousScript : category::kObfuscation,
                          Risk::Medium, Confidence::Medium,
                          "Executa PowerShell com janela oculta, política de execução desligada, comando codificado "
                          "ou técnicas de ofuscação.",
                          "Alguns instaladores usam -ExecutionPolicy Bypass; a combinação com ofuscação é rara.");
        attach(e, {"ps_hidden", "ps_obfuscation"});
        emit(std::move(e));
    }

    // ---- network --------------------------------------------------------------------------------------
    if (has("exfil_webhook")) {
        Evidence e = make("HEUR.Network.Webhook", "Canal de envio por webhook do Discord ou bot do Telegram",
                          Source::Heuristic, category::kNetwork, Risk::High, Confidence::Medium,
                          "Endereços de webhook/bot embutidos: o arquivo pode enviar dados diretamente para um canal do autor.",
                          "Bots e ferramentas de comunidade usam webhooks; jogos e cracks não.");
        attach(e, {"exfil_webhook"});
        emit(std::move(e));
    }
    if (has("exfil_filehost") || has("dyndns") || has("onion")) {
        Evidence e = make("HEUR.Network.AbusedInfrastructure", "Infraestrutura frequentemente usada por malware",
                          Source::Heuristic, category::kNetwork, Risk::Medium, Confidence::Low,
                          "Referências a sites de paste/upload anônimo, DNS dinâmico ou rede Tor.",
                          "Serviços legítimos também usam DNS dinâmico; a presença sozinha não é prova.");
        attach(e, {"exfil_filehost", "dyndns", "onion"});
        emit(std::move(e));
    }
    if (!netlits_.empty()) {
        Evidence e = make("HEUR.Network.HardcodedEndpoint", "Endereço IP e porta escritos no código",
                          Source::Heuristic, category::kNetwork, Risk::Low, Confidence::Low,
                          std::to_string(netlits_.size()) + " endereço(s) IP:porta fixo(s), típico de servidores de controle.",
                          "Jogos com servidores próprios podem ter IPs fixos.");
        attach_netlits(e);
        emit(std::move(e));
    }

    // ---- injection / backdoor / stealth / system ---------------------------------------------------
    const bool remote_write = imp_all({"openprocess", "virtualallocex", "writeprocessmemory"});
    const bool remote_exec = imp({"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread",
                                  "queueuserapc", "ntqueueapcthread"});
    const bool hollow = imp({"createprocessa", "createprocessw"}) && imp({"writeprocessmemory"}) &&
                        (imp({"ntunmapviewofsection", "zwunmapviewofsection"}) || has("hollowing_strings")) &&
                        imp({"setthreadcontext", "wow64setthreadcontext"}) && imp({"resumethread"});
    if (hollow) {
        Evidence e = make("HEUR.Injection.Hollowing", "Substitui o código de outro processo (process hollowing)",
                          Source::Heuristic, category::kProcessInjection, Risk::High, Confidence::Medium,
                          "Cria um processo suspenso, desmapeia sua imagem, grava código novo e o retoma — técnica para "
                          "rodar malware disfarçado de programa legítimo.",
                          "Protetores de software raramente usam esta sequência completa.");
        imports_detail(e, {"createprocessa", "createprocessw", "ntunmapviewofsection", "zwunmapviewofsection",
                           "writeprocessmemory", "setthreadcontext", "wow64setthreadcontext", "resumethread"});
        attach(e, {"hollowing_strings"});
        emit(std::move(e));
    } else if (remote_write && remote_exec) {
        Evidence e = make("HEUR.Injection.RemoteThread", "Injeta código em outros processos", Source::Heuristic,
                          category::kProcessInjection, Risk::Medium, Confidence::Medium,
                          "Abre outro processo, aloca memória, grava código e cria uma thread remota.",
                          "Trainers, overlays (Discord, Steam), mod loaders e anti-cheats injetam código legitimamente.");
        imports_detail(e, {"openprocess", "virtualallocex", "writeprocessmemory", "createremotethread",
                           "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc"});
        emit(std::move(e));
    } else if (has("injection_strings") && pe_ != nullptr && pe_->imports.size() <= 30) {
        Evidence e = make("HEUR.Injection.DynamicResolution", "APIs de injeção resolvidas em tempo de execução",
                          Source::Heuristic, category::kProcessInjection, Risk::Medium, Confidence::Low,
                          "Nomes de APIs de injeção aparecem como texto e são poucas as importações declaradas — "
                          "padrão para esconder a injeção da análise estática.",
                          "Mod loaders também resolvem APIs dinamicamente.");
        attach(e, {"injection_strings"});
        emit(std::move(e));
    }
    if (has("reverse_shell")) {
        const bool remote = has("dyndns") || !netlits_.empty();
        Evidence e = make("HEUR.Backdoor.ReverseShell", "Possível shell remoto (backdoor)", Source::Heuristic,
                          category::kBackdoor, remote ? Risk::High : Risk::Medium, Confidence::Low,
                          "Liga o prompt de comando/PowerShell a pipes e sockets — estrutura de shell reverso.",
                          "Ferramentas de administração remota legítimas têm a mesma estrutura.");
        attach(e, {"reverse_shell", "dyndns"});
        attach_netlits(e);
        emit(std::move(e));
    }
    if (has("stealth_attrib") || has("stealth_window")) {
        Evidence e = make("HEUR.Stealth.Hidden", "Esconde arquivos ou janelas", Source::Heuristic, category::kStealth,
                          Risk::Medium, Confidence::Low,
                          "Marca arquivos como ocultos/de sistema ou executa comandos com janela invisível.",
                          "Instaladores às vezes ocultam arquivos de configuração.");
        attach(e, {"stealth_attrib", "stealth_window"});
        emit(std::move(e));
    }
    if (has("hosts_file")) {
        Evidence e = make("HEUR.System.HostsFile", "Altera o arquivo hosts do Windows", Source::Heuristic,
                          category::kSystemModification, Risk::Medium, Confidence::Medium,
                          "Modifica o arquivo hosts, que redireciona ou bloqueia sites.",
                          "Cracks costumam bloquear servidores de ativação pelo hosts — é uma alteração real do "
                          "sistema, mesmo sem ser malware. Malware usa a mesma técnica para bloquear antivírus.");
        attach(e, {"hosts_file"});
        emit(std::move(e));
    }
    if (has("system32_write") || has("physical_drive") || has("boot_config")) {
        Evidence e = make("HEUR.System.CriticalAreas", "Mexe em áreas críticas do sistema", Source::Heuristic,
                          category::kSystemModification, Risk::High, Confidence::Medium,
                          "Toma posse de arquivos do sistema, grava diretamente no disco físico ou altera a "
                          "configuração de inicialização (ex.: desligar a verificação de assinatura de drivers).",
                          "Ferramentas de disco e de recuperação fazem isso; jogos não.");
        attach(e, {"system32_write", "physical_drive", "boot_config"});
        emit(std::move(e));
    }
    if (has("physical_memory") && (pe_ == nullptr || !pe_->is_driver)) {
        Evidence e = make("HEUR.Rootkit.PhysicalMemory", "Acesso à memória física", Source::Heuristic,
                          category::kRootkit, Risk::Medium, Confidence::Low,
                          "Referência a \\Device\\PhysicalMemory fora de um driver.",
                          "Utilitários de hardware de baixo nível podem fazer isso.");
        attach(e, {"physical_memory"});
        emit(std::move(e));
    }

    // ---- combination ------------------------------------------------------------------------------
    std::set<std::string> dangerous;
    for (std::size_t i = start; i < out_.size(); ++i) {
        if (out_[i].severity >= Risk::Medium) dangerous.insert(out_[i].category);
    }
    if (dangerous.size() >= 3) {
        std::string list;
        for (const auto& c : dangerous) list += (list.empty() ? "" : ", ") + c;
        Evidence e = make("HEUR.Combined.MalwareCapabilities",
                          "Combinação de capacidades típica de malware (" + std::to_string(dangerous.size()) + " categorias)",
                          Source::Heuristic, category::kTrojan, Risk::High, Confidence::Medium,
                          "Várias capacidades independentes e perigosas aparecem juntas: " + list + ".",
                          "Uma ferramenta administrativa poderia reunir algumas delas; um jogo, crack ou mod não.");
        e.details["categorias"] = list;
        emit(std::move(e));
    }
}

}  // namespace

void capability_evidence(const std::vector<IndicatorHit>& hits, const pe::PeInfo* pe, bool is_script,
                         const std::vector<Location>& network_literals, std::vector<Evidence>& out) {
    Correlator(hits, pe, is_script, network_literals, out).run();
}

}  // namespace gk::analysis
