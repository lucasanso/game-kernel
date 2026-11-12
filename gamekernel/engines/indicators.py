"""Capability indicators: literal strings / regexes whose *presence* reveals what code can do.

They are compiled into an internal YARA ruleset (Aho-Corasick, single pass, exact offsets,
ASCII + UTF-16LE). A single indicator never decides a verdict: ``static_heuristics``
correlates indicator *groups* with imports and PE structure, and the risk engine weighs the
result against context (signature, crack/mod recognition).

Design rules for patterns:
* prefer path fragments / command lines over single words (fewer false positives);
* never shorter than 5 characters (avoids slow YARA atoms);
* a regex is prefixed with ``re:``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Indicator:
    id: str
    group: str
    description: str
    patterns: tuple[str, ...]
    min_matches: int = 1
    wide: bool = True
    nocase: bool = True


I = Indicator  # noqa: E741 - short alias for the table below


def _x(hex_text: str) -> str:
    """Patterns of offensive tools are stored hex-encoded so that this source file (and the
    packaged application) does not itself contain strings that other antivirus products flag."""
    return bytes.fromhex(hex_text).decode("ascii")


INDICATORS: tuple[Indicator, ...] = (
    # ---------------------------------------------------------------- exfiltration / network
    I("discord_webhook", "exfil_webhook", "URL de webhook do Discord (canal comum de envio de dados roubados)",
      (r"re:discord(app)?\.com/api/webhooks/[0-9]{5,}",)),
    I("telegram_bot", "exfil_webhook", "API de bots do Telegram (canal comum de exfiltração)",
      ("api.telegram.org/bot", "re:/bot[0-9]{6,12}:[A-Za-z0-9_\\-]{30,}")),
    I("paste_sites", "exfil_filehost", "Site de paste usado para hospedar cargas/configurações",
      ("pastebin.com/raw", "paste.ee/r/", "hastebin.com", "rentry.co/", "ghostbin.", "controlc.com", "pastes.io")),
    I("file_hosts", "exfil_filehost", "Serviço de upload anônimo de arquivos",
      ("transfer.sh", "anonfiles.com", "gofile.io/uploadFile", "api.gofile.io", "file.io/", "catbox.moe",
       "temp.sh/", "0x0.st", "bashupload.com", "uploadfiles.io", "store1.gofile.io")),
    I("discord_cdn", "payload_host", "Anexo hospedado na CDN do Discord (usado para baixar cargas)",
      ("cdn.discordapp.com/attachments", "media.discordapp.net/attachments")),
    I("raw_github", "payload_host", "Conteúdo bruto do GitHub (às vezes usado para baixar cargas)",
      ("raw.githubusercontent.com",)),
    I("dynamic_dns", "dyndns", "Domínio de DNS dinâmico (comum em servidores de controle de RATs)",
      ("duckdns.org", ".ddns.net", ".no-ip.org", ".no-ip.biz", ".hopto.org", ".zapto.org", ".sytes.net",
       ".serveftp.com", ".ngrok.io", ".ngrok-free.app", "portmap.io", ".freedns.afraid.org", ".dynu.net",
       ".myftp.biz", ".servebeer.com", ".linkpc.net")),
    I("onion", "onion", "Endereço da rede Tor (.onion)", (r"re:[a-z2-7]{16,56}\.onion",)),
    I("ip_port", "ip_port", "Endereço IP com porta escrito no código",
      (r"re:[^0-9.](1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])){3}:[0-9]{2,5}[^0-9]",)),
    I("ip_lookup", "ip_lookup", "Serviço de descoberta de IP/geolocalização (reconhecimento da vítima)",
      ("ip-api.com", "ipinfo.io", "api.ipify.org", "checkip.amazonaws.com", "icanhazip.com", "ipwho.is",
       "geoplugin.net", "myexternalip.com", "ipapi.co")),
    # ---------------------------------------------------------------- credentials / sessions
    I("browser_login_db", "browser_credentials", "Banco de senhas de navegadores Chromium/Firefox",
      ("\\Login Data", "Login Data For Account", "logins.json", "key4.db", "signons.sqlite", "key3.db")),
    I("browser_profile_paths", "browser_profiles", "Caminhos de perfis de vários navegadores",
      ("Google\\Chrome\\User Data", "Microsoft\\Edge\\User Data", "BraveSoftware\\Brave-Browser",
       "Opera Software\\Opera Stable", "Opera Software\\Opera GX Stable", "Yandex\\YandexBrowser",
       "Vivaldi\\User Data", "Mozilla\\Firefox\\Profiles", "Chromium\\User Data"), min_matches=3),
    I("browser_cookie_db", "browser_cookies", "Banco de cookies de navegadores",
      ("\\Network\\Cookies", "Default\\Cookies", "cookies.sqlite", "SELECT host_key", "FROM cookies")),
    I("browser_queries", "browser_credentials", "Consulta SQL ao banco de senhas/cartões do navegador",
      ("SELECT origin_url", "FROM logins", "password_value", "SELECT name_on_card", "FROM credit_cards",
       "card_number_encrypted")),
    I("chrome_master_key", "chrome_key", "Leitura da chave mestra de criptografia do Chrome (Local State)",
      ("os_crypt", "encrypted_key", "app_bound_encrypted_key", "\\Local State")),
    I("dpapi", "dpapi", "Uso de DPAPI para decifrar segredos do usuário", ("CryptUnprotectData", "ProtectedData.Unprotect")),
    I("discord_token", "discord_token", "Coleta de tokens do Discord",
      ("discord\\Local Storage\\leveldb", "discordcanary\\Local Storage", "discordptb\\Local Storage",
       "dQw4w9WgXcQ:", r"re:[\w-]{24}\.[\w-]{6}\.[\w-]{27}")),
    I("steam_session", "game_sessions", "Arquivos de sessão/configuração da Steam (roubo de conta)",
      ("loginusers.vdf", "\\config\\config.vdf", "ssfn", "Steam\\config\\loginusers")),
    I("game_launcher_tokens", "game_sessions", "Credenciais de launchers de jogos",
      ("Epic Games\\EpicGamesLauncher\\Saved\\Config", "Riot Games\\Riot Client\\Data", "Battle.net\\Battle.net.config",
       "minecraft\\launcher_accounts", "launcher_profiles.json", "Ubisoft Game Launcher\\user")),
    I("crypto_wallets", "crypto_wallets", "Caminhos de carteiras de criptomoedas",
      ("wallet.dat", "Exodus\\exodus.wallet", "Electrum\\wallets", "atomic\\Local Storage", "Ethereum\\keystore",
       "nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "Coinomi\\Coinomi\\wallets",
       "Guarda\\Local Storage", "com.liberty.jaxx", "ibnejdfjmmkpcnlpebklmnkoeoihofec", "fhbohimaelbohpjbbldcngcnapndodjp")),
    I("messenger_sessions", "messenger_sessions", "Sessões de mensageiros (Telegram tdata, Signal)",
      ("Telegram Desktop\\tdata", "\\tdata\\key_datas", "Signal\\config.json", "Signal\\sql\\db.sqlite")),
    I("ftp_vpn_creds", "app_credentials", "Credenciais de FTP/VPN/clientes",
      ("FileZilla\\recentservers.xml", "FileZilla\\sitemanager.xml", "NordVPN\\NordVPN.exe", "OpenVPN Connect\\profiles",
       "ProtonVPN\\", "WinSCP 2\\Sessions", "\\.purple\\accounts.xml")),
    I("wifi_creds", "wifi_creds", "Extração de senhas de Wi-Fi", ("wlan show profile", "key=clear"), min_matches=2),
    I("lsass_dump", "lsass_dump", "Despejo da memória do LSASS (credenciais do Windows)",
      ("comsvcs.dll, MiniDump", "comsvcs.dll MiniDump", "procdump -ma lsass", "lsass.dmp")),
    I("sam_dump", "sam_dump", "Cópia das colmeias SAM/SECURITY do registro",
      ("reg save hklm\\sam", "reg save HKLM\\SECURITY", "\\config\\SAM", "reg.exe save hklm\\system")),
    I("mimikatz", "mimikatz", "Comandos/strings da ferramenta Mimikatz",
      (_x("73656b75726c73613a3a6c6f676f6e70617373776f726473"), _x("73656b75726c73613a3a"), _x("6c736164756d703a3a73616d"), _x("70726976696c6567653a3a6465627567"), _x("67656e74696c6b697769"), _x("6d696d696b61747a"))),
    I("vault_creds", "app_credentials", "Cofre de credenciais do Windows", ("VaultEnumerateItems", "VaultGetItem", "CredEnumerateW")),
    # ---------------------------------------------------------------- spying
    I("keylog_labels", "keylog_labels", "Rótulos de teclas típicos de registro de digitação",
      ("[BACKSPACE]", "[ENTER]", "[CAPSLOCK]", "[SHIFT]", "[TAB]", "[CTRL]", "[DELETE]", "[ESC]", "<BackSpace>", "[Back]",
       "[Enter]", "[Caps Lock]"), min_matches=3),
    I("clipboard_api", "clipboard", "Leitura/alteração da área de transferência",
      ("GetClipboardData", "SetClipboardData", "Clipboard.GetText", "Clipboard.SetText"), min_matches=1),
    I("crypto_address_regex", "crypto_regex", "Expressões para reconhecer endereços de criptomoedas (clipper)",
      ("^(bc1|[13])[a-zA-HJ-NP-Z0-9]", "^0x[a-fA-F0-9]{40}$", "^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",
       "^T[A-Za-z1-9]{33}$", "(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}")),
    I("screenshot", "screenshot", "Captura de tela", ("CopyFromScreen", "screenshot.png", "Screenshot.jpg", "\\screen.png")),
    I("webcam", "webcam", "Acesso à webcam", ("capCreateCaptureWindow", "avicap32.dll", "WebcamCapture")),
    I("av_enumeration", "av_enum", "Enumeração de antivírus instalados via WMI",
      ("SELECT * FROM AntiVirusProduct", "root\\SecurityCenter2", "FirewallProduct")),
    I("sysinfo_recon", "recon", "Coleta de informações do sistema/HWID",
      ("SELECT * FROM Win32_VideoController", "SELECT * FROM Win32_Processor", "Win32_ComputerSystemProduct",
       "MachineGuid", "systeminfo", "HWID"), min_matches=3),
    # ---------------------------------------------------------------- ransomware
    I("shadow_delete", "ransom_shadow", "Exclusão de cópias de sombra / desativação da recuperação",
      ("vssadmin delete shadows", "vssadmin.exe delete shadows", "shadowcopy delete", "wbadmin delete catalog",
       "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "Win32_ShadowCopy", "resize shadowstorage")),
    I("ransom_note", "ransom_note", "Texto típico de nota de resgate",
      ("your files have been encrypted", "all your files are encrypted", "files have been encrypted",
       "to decrypt your files", "decryption key", "pay the ransom", "send bitcoin", "HOW_TO_DECRYPT",
       "README_TO_DECRYPT", "your personal id", "restore your files", "Tor Browser"), min_matches=2),
    # ---------------------------------------------------------------- mining
    I("stratum", "miner", "Protocolo de mineração Stratum", ("stratum+tcp://", "stratum+ssl://", "stratum2+tcp://")),
    I("xmrig", "miner", "Parâmetros/strings do minerador XMRig",
      ("--donate-level", "xmrig", "randomx", "cryptonight", "--cpu-max-threads-hint", "\"donate-level\""), min_matches=2),
    I("mining_pools", "miner", "Pools de mineração conhecidos",
      ("minexmr.com", "nanopool.org", "supportxmr.com", "moneroocean.stream", "hashvault.pro", "2miners.com",
       "ethermine.org", "f2pool.com", "c3pool.com", "herominers.com", "unmineable.com", "nicehash.com", "minergate")),
    I("gpu_miners", "miner", "Mineradores de GPU",
      ("lolMiner", "PhoenixMiner", "nbminer", "t-rex.exe", "ethminer", "gminer", "--algo ethash", "kawpow"), min_matches=2),
    I("winring0", "winring0", "Driver WinRing0 (acesso direto a hardware; usado por mineradores e utilitários)",
      ("WinRing0", "WinRing0x64.sys")),
    # ---------------------------------------------------------------- persistence
    I("run_key", "persist_run", "Chave de inicialização automática (Run/RunOnce)",
      ("CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Policies\\Explorer\\Run", "CurrentVersion\\RunServices")),
    I("schtasks", "persist_schtasks", "Criação de tarefa agendada",
      ("schtasks /create", "schtasks.exe /create", "Register-ScheduledTask", "New-ScheduledTaskAction", "/sc onlogon",
       "/sc minute")),
    I("startup_folder", "persist_startup", "Pasta Inicializar do Windows",
      ("Start Menu\\Programs\\Startup", "shell:startup", "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
    I("service_create", "persist_service", "Criação de serviço do Windows", ("sc create", "sc.exe create", "New-Service ")),
    I("wmi_persistence", "persist_wmi", "Assinatura de eventos WMI (persistência furtiva)",
      ("__EventFilter", "CommandLineEventConsumer", "ActiveScriptEventConsumer", "__FilterToConsumerBinding")),
    I("winlogon", "persist_winlogon", "Alteração de Winlogon (Shell/Userinit)",
      ("Windows NT\\CurrentVersion\\Winlogon", "Winlogon\\Shell", "Winlogon\\Userinit")),
    I("ifeo", "persist_ifeo", "Image File Execution Options (sequestro de executáveis)",
      ("Image File Execution Options",)),
    I("appinit", "persist_appinit", "AppInit_DLLs (carregar DLL em todos os processos)", ("AppInit_DLLs", "LoadAppInit_DLLs")),
    # ---------------------------------------------------------------- defense evasion
    I("defender_tamper", "defender_tamper", "Alteração do Microsoft Defender (exclusões ou desativação)",
      ("Add-MpPreference", "Set-MpPreference", "DisableRealtimeMonitoring", "-ExclusionPath", "-ExclusionProcess",
       "-ExclusionExtension", "DisableAntiSpyware", "Windows Defender\\Exclusions", "-RemoveDefinitions",
       "DisableBehaviorMonitoring", "DisableIOAVProtection", "SubmitSamplesConsent", "Policies\\Microsoft\\Windows Defender")),
    I("firewall_tamper", "firewall_tamper", "Alteração/desativação do Firewall do Windows",
      ("advfirewall set allprofiles state off", "netsh firewall set opmode disable", "firewall add allowedprogram",
       "advfirewall firewall add rule", "Set-NetFirewallProfile -Enabled False")),
    I("uac_bypass", "uac_bypass", "Técnica conhecida de contorno do UAC",
      ("ms-settings\\shell\\open\\command", "mscfile\\shell\\open\\command", "DelegateExecute", "fodhelper.exe",
       "computerdefaults.exe", "sdclt.exe /kickoffelev", "Folder\\shell\\open\\command"), min_matches=2),
    I("uac_disable", "uac_disable", "Desativação do UAC", ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop")),
    I("av_process_names", "av_processes", "Lista de processos de antivírus (detecção ou encerramento)",
      ("MsMpEng.exe", "avp.exe", "avgnt.exe", "AvastUI.exe", "bdagent.exe", "ekrn.exe", "mbam.exe", "NortonSecurity.exe",
       "egui.exe", "avguard.exe", "SecurityHealthService.exe", "MBAMService.exe", "AvastSvc.exe", "avgui.exe"), min_matches=3),
    I("taskkill", "taskkill", "Encerramento forçado de processos", ("taskkill /f /im", "taskkill /im", "Stop-Process -Name")),
    I("log_clear", "log_clear", "Limpeza de logs de eventos do Windows", ("wevtutil cl", "wevtutil.exe cl", "Clear-EventLog")),
    I("anti_vm", "anti_vm", "Detecção de máquinas virtuais/sandboxes",
      ("VBoxService", "VBoxTray", "vmtoolsd", "vmwaretray", "VBOX HARDDISK", "VMware Virtual", "qemu-ga", "SbieDll.dll",
       "wine_get_unix_file_name", "cuckoomon", "vmGuestLib", "VirtualBox Guest"), min_matches=2),
    I("anti_analysis_tools", "anti_analysis", "Lista de ferramentas de análise (fuga de analistas)",
      ("procmon.exe", "wireshark.exe", "x64dbg.exe", "ollydbg.exe", "ida64.exe", "ProcessHacker.exe", "fiddler.exe",
       "httpdebuggerui.exe", "dnspy.exe", "tcpview.exe", "pestudio.exe", "processhacker"), min_matches=3),
    # ---------------------------------------------------------------- download / execution
    I("urlmon_download", "dl_urlmon", "Download de arquivos via URLDownloadToFile", ("URLDownloadToFile",)),
    I("ps_download", "dl_powershell", "PowerShell baixando/executando código",
      ("DownloadString(", "DownloadFile(", "DownloadData(", "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient",
       "Start-BitsTransfer", "iwr -uri", "IEX(", "IEX (", "Invoke-Expression")),
    I("ps_encoded", "ps_hidden", "PowerShell com comando codificado ou janela oculta",
      ("-EncodedCommand", "-enc ", "-e JAB", "-WindowStyle Hidden", "-w hidden", "-NoProfile -ExecutionPolicy Bypass",
       "-ExecutionPolicy Bypass", "-nop -w hidden")),
    I("certutil", "dl_lolbin", "certutil usado para baixar/decodificar", ("certutil -urlcache", "certutil.exe -urlcache",
       "certutil -decode", "certutil.exe -decode")),
    I("bitsadmin", "dl_lolbin", "bitsadmin usado para baixar arquivos", ("bitsadmin /transfer", "bitsadmin.exe /transfer")),
    I("lolbin_proxy", "dl_lolbin", "Execução indireta via mshta/rundll32/regsvr32",
      ("mshta http", "mshta.exe http", "mshta vbscript:", "javascript:\"\\..\\mshtml", "rundll32.exe javascript:",
       "regsvr32 /s /n /u /i:http", "scrobj.dll", "wmic process call create")),
    I("temp_exec", "temp_exec", "Gravação/execução de programas em pastas temporárias ou AppData",
      (r"re:%(TEMP|APPDATA|LOCALAPPDATA)%\\[^\x00\"]{1,80}\.(exe|dll|scr|bat|ps1|vbs)", r"re:AppData\\(Local|Roaming)\\[^\x00\"]{1,80}\.(exe|scr)",
       r"re:\\Temp\\[^\x00\"]{1,80}\.(exe|scr)")),
    # ---------------------------------------------------------------- injection / stealth
    I("injection_api_strings", "injection_strings", "Nomes de APIs de injeção resolvidos dinamicamente",
      ("WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
       "QueueUserAPC", "NtQueueApcThread"), min_matches=3, nocase=False),
    I("hollowing_strings", "hollowing_strings", "APIs de process hollowing resolvidas dinamicamente",
      ("NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext", "Wow64SetThreadContext", "NtResumeThread"),
      min_matches=2, nocase=False),
    I("attrib_hidden", "stealth_attrib", "Arquivos marcados como ocultos/de sistema", ("attrib +h +s", "attrib +s +h", "attrib +h ")),
    I("hidden_vbs", "stealth_window", "Execução oculta via WScript.Shell", (".Run \"", ", 0, False", "WScript.Shell"), min_matches=2),
    # ---------------------------------------------------------------- system modification / destructive
    I("hosts_file", "hosts_file", "Alteração do arquivo hosts", ("drivers\\etc\\hosts", "drivers/etc/hosts")),
    I("system32_write", "system32_write", "Tomar posse/alterar permissões de arquivos do sistema",
      ("takeown /f", "icacls", "\\System32\\drivers\\", "/grant administrators:F", "/grant *S-1-5-32-544:F"), min_matches=2),
    I("physical_drive", "physical_drive", "Acesso direto ao disco físico (MBR/bootkit/wiper)", ("\\\\.\\PhysicalDrive0", "\\\\.\\PhysicalDrive")),
    I("physical_memory", "physical_memory", "Acesso à memória física", ("\\Device\\PhysicalMemory",)),
    I("bcdedit", "boot_config", "Alteração da configuração de inicialização", ("bcdedit /set", "bcdedit.exe /set", "testsigning on",
       "nointegritychecks on")),
    I("reverse_shell", "reverse_shell", "Shell reverso (cmd/powershell ligado a socket)",
      ("cmd.exe", "powershell.exe", "CreatePipe", "WSASocket", "PeekNamedPipe"), min_matches=4, nocase=False),
    I("ps_obfuscation", "ps_obfuscation", "Ofuscação de PowerShell",
      ("FromBase64String", "-bxor", "[char[]]", "-join", "[Convert]::", "[Reflection.Assembly]::Load", "GzipStream",
       "IO.Compression.DeflateStream"), min_matches=2),
    I("amsi_bypass", "amsi_bypass", "Contorno do AMSI (antimalware scan interface)",
      ("AmsiScanBuffer", "amsiInitFailed", "AmsiUtils", "amsi.dll"), min_matches=2),
    I("etw_patch", "etw_patch", "Desativação de telemetria de segurança (ETW)", ("EtwEventWrite",)),
)

# Markers used to recognise packers/compilers/installers (feature extraction, not threats).
PACKER_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("PyInstaller", ("PyInstaller", "_MEIPASS", "pyi-runtime-tmpdir", "Cannot open PyInstaller archive")),
    ("Nuitka", ("Nuitka", "__compiled__", "NUITKA_ONEFILE_PARENT")),
    ("AutoIt", ("AU3!EA06", "AutoIt v3", ">>>AUTOIT SCRIPT<<<")),
    ("ConfuserEx", ("ConfusedByAttribute", "ConfuserEx")),
    (".NET Reactor", ("<PrivateImplementationDetails>{", "dotNET_Reactor")),
    ("SmartAssembly", ("SmartAssembly.Attributes", "PoweredByAttribute")),
    ("Eazfuscator", ("Eazfuscator",)),
    ("Babel", ("BabelObfuscatorAttribute",)),
    ("Themida/WinLicense", ("Themida", "WinLicense", "SecureEngine")),
    ("VMProtect", ("VMProtect", ".vmp0")),
    ("Enigma Protector", ("Enigma Protector", ".enigma1")),
    ("Electron", ("electron.asar", "Electron Framework")),
    ("Inno Setup", ("Inno Setup Setup Data", "InnoSetupLdrWindow", "JR.Inno.Setup")),
    ("NSIS", ("Nullsoft Install System", "NullsoftInst", "nsis.sf.net")),
    ("InstallShield", ("InstallShield",)),
    ("7-Zip SFX", ("7-Zip SFX", ";!@Install@!UTF-8!")),
    ("WinRAR SFX", ("WinRAR SFX", "RarSFX")),
    ("Denuvo", ("Denuvo",)),
)
