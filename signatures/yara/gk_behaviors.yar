// Game Kernel — combinações de comportamento de alta confiança (independentes de família).
// Cada regra exige vários elementos que, juntos, não têm uso legítimo em jogos, cracks ou mods.

rule GK_Stealer_Multi_Target
{
    meta:
        description = "Coleta simultânea de senhas de navegador, sessões do Discord e carteiras de criptomoedas, com canal de envio"
        category = "password_stealer"
        severity = "CRITICAL"
        confidence = "MEDIUM"
        verdict = "malware"
        fp_note = "Gerenciadores de senha legítimos não enviam dados por webhook/Telegram; falso positivo improvável."
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $b1 = "\\Login Data" ascii wide nocase
        $b2 = "logins.json" ascii wide nocase
        $b3 = "encrypted_key" ascii wide
        $d1 = "discord\\Local Storage\\leveldb" ascii wide nocase
        $d2 = "dQw4w9WgXcQ:" ascii wide
        $w1 = "wallet.dat" ascii wide nocase
        $w2 = "Exodus\\exodus.wallet" ascii wide nocase
        $w3 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $x1 = /discord(app)?\.com\/api\/webhooks\/[0-9]{5,}/ ascii wide nocase
        $x2 = "api.telegram.org/bot" ascii wide nocase
    condition:
        1 of ($b*) and 1 of ($d*) and 1 of ($w*) and 1 of ($x*)
}

rule GK_Defender_Exclusion_With_Download
{
    meta:
        description = "Adiciona exclusões ao Microsoft Defender e baixa/executa conteúdo da internet"
        category = "defense_evasion"
        severity = "HIGH"
        confidence = "HIGH"
        verdict = "malware"
        fp_note = "Instruções de cracks costumam pedir exclusões, mas um programa que as cria sozinho e baixa código é um dropper."
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $e1 = "Add-MpPreference" ascii wide nocase
        $e2 = "-ExclusionPath" ascii wide nocase
        $e3 = "-ExclusionProcess" ascii wide nocase
        $d1 = "DownloadString(" ascii wide nocase
        $d2 = "DownloadFile(" ascii wide nocase
        $d3 = "Invoke-WebRequest" ascii wide nocase
        $d4 = "URLDownloadToFile" ascii wide
        $d5 = "Start-BitsTransfer" ascii wide nocase
    condition:
        $e1 and 1 of ($e2, $e3) and 1 of ($d*)
}

rule GK_Ransomware_Recovery_Inhibition_With_Note
{
    meta:
        description = "Destrói cópias de sombra/recuperação e contém texto de nota de resgate"
        category = "ransomware"
        severity = "CRITICAL"
        confidence = "HIGH"
        verdict = "malware"
        fp_note = "Nenhum software legítimo combina exclusão de cópias de sombra com nota de resgate."
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $s1 = "vssadmin delete shadows" ascii wide nocase
        $s2 = "vssadmin.exe delete shadows" ascii wide nocase
        $s3 = "shadowcopy delete" ascii wide nocase
        $s4 = "wbadmin delete catalog" ascii wide nocase
        $s5 = "recoveryenabled no" ascii wide nocase
        $n1 = "your files have been encrypted" ascii wide nocase
        $n2 = "all your files are encrypted" ascii wide nocase
        $n3 = "to decrypt your files" ascii wide nocase
        $n4 = "decryption key" ascii wide nocase
        $n5 = "send bitcoin" ascii wide nocase
    condition:
        1 of ($s*) and 2 of ($n*)
}
