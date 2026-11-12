// Game Kernel — Remote Access Trojans com indicadores públicos amplamente documentados.
// Apenas famílias cujos marcadores são estáveis e públicos; o restante é coberto pela correlação de
// capacidades do motor heurístico.

rule GK_RAT_Quasar
{
    meta:
        description = "Quasar RAT (ferramenta de acesso remoto .NET muito usada em malware)"
        category = "rat"
        severity = "CRITICAL"
        confidence = "HIGH"
        verdict = "malware"
        fp_note = "O Quasar é publicado como ferramenta de administração remota; dentro de um jogo/crack é um RAT."
        reference = "https://github.com/quasar/Quasar"
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $ns1 = "Quasar.Client" ascii wide
        $ns2 = "Quasar.Common" ascii wide
        $ns3 = "xClient.Core" ascii wide
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule GK_RAT_njRAT
{
    meta:
        description = "njRAT / Bladabindi (separador de protocolo e liberação no firewall)"
        category = "rat"
        severity = "CRITICAL"
        confidence = "MEDIUM"
        verdict = "malware"
        fp_note = "Combinação muito específica; falsos positivos não são esperados."
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $sep = "|'|'|" ascii wide
        $fw = "netsh firewall add allowedprogram" ascii wide nocase
        $zone = "SEE_MASK_NOZONECHECKS" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule GK_RAT_Remcos
{
    meta:
        description = "Remcos RAT"
        category = "rat"
        severity = "CRITICAL"
        confidence = "MEDIUM"
        verdict = "malware"
        fp_note = "O Remcos é vendido como ferramenta de controle remoto; dentro de um jogo/crack é um RAT."
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $a = "Remcos" ascii wide
        $b = "Breaking-Security.Net" ascii wide nocase
        $c = "remcos_mutex" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
