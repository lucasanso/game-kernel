// Game Kernel — mineração de criptomoedas.

rule GK_PUA_Miner_XMRig
{
    meta:
        description = "Minerador XMRig (ou derivado) embutido"
        category = "cryptominer"
        severity = "HIGH"
        confidence = "HIGH"
        verdict = "pua"
        fp_note = "O XMRig é software livre de mineração. Só é legítimo se você mesmo o instalou; dentro de um jogo ou crack é um minerador oculto."
        reference = "https://github.com/xmrig/xmrig"
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $n1 = "xmrig" ascii wide nocase
        $o1 = "--donate-level" ascii wide
        $o2 = "\"donate-level\"" ascii wide
        $o3 = "--cpu-max-threads-hint" ascii wide
        $a1 = "randomx" ascii wide nocase
        $a2 = "cryptonight" ascii wide nocase
        $p1 = "stratum+tcp://" ascii wide nocase
        $p2 = "stratum+ssl://" ascii wide nocase
    condition:
        $n1 and 1 of ($o*) and (1 of ($a*) or 1 of ($p*))
}

rule GK_Miner_Stratum_Configuration
{
    meta:
        description = "Configuração de mineração (pool Stratum com usuário/carteira) embutida"
        category = "cryptominer"
        severity = "HIGH"
        confidence = "MEDIUM"
        verdict = "suspicious"
        fp_note = "Aplicativos de mineração legítimos contêm esta configuração; jogos e cracks não."
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $pool1 = "stratum+tcp://" ascii wide nocase
        $pool2 = "stratum+ssl://" ascii wide nocase
        $user1 = "\"user\":" ascii wide
        $user2 = " -u " ascii wide
        $pass1 = "\"pass\":" ascii wide
        $pass2 = " -p x" ascii wide
        $algo = "\"algo\":" ascii wide
    condition:
        1 of ($pool*) and 1 of ($user*) and (1 of ($pass*) or $algo)
}
