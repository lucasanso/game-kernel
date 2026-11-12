// Game Kernel — arquivos de teste de antivírus.
// O arquivo de teste EICAR é inofensivo; a regra segue a especificação oficial: o arquivo começa com
// a string de 68 bytes e tem no máximo 128 bytes. Escrita em hexadecimal para que este arquivo não
// seja, ele próprio, detectado como EICAR por outros antivírus.

rule GK_Test_EICAR
{
    meta:
        description = "Arquivo de teste antivírus EICAR (inofensivo)"
        category = "test_file"
        severity = "HIGH"
        confidence = "HIGH"
        verdict = "test"
        fp_note = "Não é malware: serve apenas para verificar se o antivírus funciona."
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        author = "Game Kernel"
        date = "2026-11-12"
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }
    condition:
        $eicar at 0 and filesize <= 128
}
