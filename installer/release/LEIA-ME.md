# Versão de release

Esta pasta guarda o que a CI precisa para publicar uma versão assinada com a chave de release — **nada aqui é
segredo**. O passo a passo completo está em `docs/RELEASE.md`.

| Arquivo | Quem coloca | Para quê |
|---|---|---|
| `release.pub` | o publicador, uma vez (`tools/gk_keygen.py`) | chave **pública**: a CI monta a versão de release com ela |
| `assinatura.json` | o publicador, a cada versão (`tools/release_sign.py sign`) | a assinatura do manifesto e a execução da CI que preparou a pasta |

A chave **privada** (`release.key`) nunca vem para cá: o `.gitignore` recusa `*.key` e o teste
`test_no_private_key_in_the_repository` falha se uma chave privada aparecer no repositório.
