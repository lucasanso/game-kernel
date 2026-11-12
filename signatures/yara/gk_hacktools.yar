// Game Kernel — ferramentas ofensivas de roubo de credenciais.
// Strings em escapes \xNN para que este arquivo não seja sinalizado por outros antivírus.

rule GK_HackTool_Mimikatz
{
    meta:
        description = "Ferramenta Mimikatz (extração de senhas e hashes da memória do Windows)"
        category = "credential_access"
        severity = "CRITICAL"
        confidence = "HIGH"
        verdict = "malware"
        fp_note = "Profissionais de segurança usam o Mimikatz em testes autorizados; nunca faz parte de um jogo."
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $cmd1 = "\x73\x65\x6b\x75\x72\x6c\x73\x61\x3a\x3a\x6c\x6f\x67\x6f\x6e\x70\x61\x73\x73\x77\x6f\x72\x64\x73" ascii wide nocase
        $cmd2 = "\x6c\x73\x61\x64\x75\x6d\x70\x3a\x3a\x73\x61\x6d" ascii wide nocase
        $cmd3 = "\x70\x72\x69\x76\x69\x6c\x65\x67\x65\x3a\x3a\x64\x65\x62\x75\x67" ascii wide nocase
        $auth = "\x67\x65\x6e\x74\x69\x6c\x6b\x69\x77\x69" ascii wide nocase
        $name = "\x6d\x69\x6d\x69\x6b\x61\x74\x7a" ascii wide nocase
        $mod = "\x6b\x69\x77\x69\x5f\x6d\x73\x76\x31\x5f\x30" ascii wide
    condition:
        2 of ($cmd*) or ($auth and $name) or ($mod and 1 of ($cmd*))
}
