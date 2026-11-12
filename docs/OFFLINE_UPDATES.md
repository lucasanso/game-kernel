# Game Kernel — Atualização offline de assinaturas

O Game Kernel **nunca** baixa nada. As assinaturas (ClamAV), as regras YARA e os indicadores locais (IOC)
só são atualizados por **pacotes `.gkpkg` assinados**, levados ao computador por pendrive ou pasta local.

> **Limitação importante**: sem atualização automática, ameaças surgidas depois do último pacote importado
> podem não ser reconhecidas por assinatura. O aplicativo avisa quando as assinaturas ficam desatualizadas
> (padrão: 7 dias, configurável). As análises estática e heurística continuam funcionando, mas não substituem
> assinaturas recentes.

## 1. Para o usuário: importar um pacote

1. Copie o arquivo `.gkpkg` (e, se for a primeira vez, a chave pública `.pub` do publicador) para o computador.
2. Em **Central de Atualização Offline**, escolha **Importar pacote**.
3. O aplicativo verifica o pacote **antes** de mostrar qualquer detalhe:
   assinatura Ed25519 de uma chave confiável → manifesto → compatibilidade de versão → SHA-256 de cada arquivo.
4. Confira o publicador, a versão, a identificação da chave e os componentes, e confirme.
5. A instalação é **atômica**: cada componente substituído é validado (as regras YARA são compiladas, a estrutura
   das bases ClamAV e dos IOC é conferida). Só então o conjunto novo é ativado. Se algo falhar, **nada muda**.
6. **Reverter** restaura o conjunto anterior (mantido em `signatures/previous`).

Pacotes recusados e o que significam:

| Código | Significado |
|---|---|
| `not_a_package` / `unsupported_format` | o arquivo não é um `.gkpkg` ou é de uma versão de formato desconhecida |
| `truncated` / `invalid_header` | arquivo incompleto ou corrompido |
| `no_trusted_keys` | nenhuma chave pública confiável instalada (veja §3) |
| `bad_signature` | assinatura inválida, conteúdo alterado ou chave não confiável: **não use este pacote** |
| `invalid_manifest` | pacote assinado, mas com conteúdo proibido (caminhos, extensões, nomes reservados, tamanhos) |
| `incompatible_app` | o pacote exige uma versão mais nova do Game Kernel |
| `hash_mismatch` / `trailing_data` | um arquivo do pacote foi adulterado depois da assinatura |
| `downgrade` | versão igual ou mais antiga que a instalada; reverter exige confirmação explícita |
| `validation_failed` | regras ou bases não carregariam (ex.: regra YARA com erro); nada foi alterado |
| `busy` | outra instalação ou uma varredura está usando as assinaturas |

## 2. Para o publicador: gerar um pacote

```bash
# 1. Uma única vez: par de chaves (a privada fica fora do repositório, de preferência offline)
python tools/gk_keygen.py --out-dir private --name release
```

```bash
# 2. Preparar indicadores (opcional): normalizar, deduplicar e detectar conflitos.
#    Fonte = caminho[:veredito_padrão[:categoria_padrão]]; listas simples precisam do veredito.
python tools/ti_build_ioc.py --version 2026.11.12 --out dist/ioc/local.json --report ioc-relatorio.json \
    fontes/hashes-ruins.txt:bad:trojan fontes/exportacao.csv fontes/anterior.json
```

```bash
# 3. Gerar, verificar e assinar o pacote (com relatório de atualização)
python tools/make_update_package.py build --key private/release.key --version 2026.11.12.1 \
    --publisher "Equipe Game Kernel" --yara dist/yara --ioc dist/ioc --clamav dist/clamav \
    --out GameKernel-assinaturas-2026.11.12.1.gkpkg --report relatorio-2026.11.12.1.json \
    --previous GameKernel-assinaturas-2026.11.05.1.gkpkg --keys keys/
```

```bash
# 4. Conferir como o usuário conferiria
python tools/make_update_package.py verify GameKernel-assinaturas-2026.11.12.1.gkpkg --keys keys/
```

Antes de assinar, `make_update_package.py build` **recusa** componentes que o aplicativo rejeitaria:

* **YARA**: compilação com yara-python (um *namespace* por arquivo, `include` proibido; variáveis externas
  `filename`, `filepath`, `extension`, `filetype`) e verificação de metadados obrigatórios (`description`,
  `category`, `severity`, `author`), com aviso quando faltam `fp_note` ou `reference_date`.
* **IOC**: formato `gamekernel-ioc`, SHA-256 normalizado, vereditos `bad`/`good`, conflitos entre arquivos.
* **ClamAV**: cabeçalhos `ClamAV-VDB` e contagens.
* Se o `gk-update` (validadores C++) estiver compilado, **os mesmos validadores do aplicativo** rodam antes da assinatura.

O relatório de atualização (`--report`) lista componentes, contagens (regras, entradas, assinaturas), arquivos
com SHA-256, avisos, o veredito dos validadores C++ e as diferenças em relação ao pacote anterior.

### Bases oficiais do ClamAV

Coloque `main.cvd`, `daily.cvd` e `bytecode.cvd` (obtidos com o `freshclam` numa máquina com internet) em
`dist/clamav/`. O pacote `.gkpkg` assinado pelo publicador garante a autenticidade do conjunto. O instalador
confere o cabeçalho e o MD5 do conteúdo de cada CVD (a mesma verificação de integridade que o libclamav faz).
A importação **direta** de CVD avulso, sem `.gkpkg`, depende da verificação RSA da Cisco Talos via `sigtool`
(componente do Agente A) e ainda não está disponível. Ver `docs/PROGRESS_B.md`.

## 3. Chaves confiáveis

* **Embutidas no build**: `signatures/keys/*.pub` (copiadas pelo script de *build*; a chave privada nunca é versionada).
* **Adicionadas pelo usuário**: `<dados>/trusted_keys/*.pub`, sempre com confirmação explícita mostrando a
  identificação da chave (16 primeiros caracteres hexadecimais do SHA-256 da chave pública).
* Identificador de chave: idêntico em Python (`crypto_utils.key_id`) e C++ (`gk::updates::keyIdOf`).

## 4. Formato `.gkpkg` v1

```
offset 0   magic        "GKPKG" 0x00 0x01 0x00        (8 bytes; byte 6 = versão do formato)
offset 8   manifest_len uint32 LE                      (1 … 1 MiB)
offset 12  manifest     JSON UTF-8 (gamekernel-update v1)
           sig_len      uint32 LE = 64
           signature    Ed25519( magic || manifest_len || manifest )
           payloads     arquivos concatenados na ordem do manifesto, tamanhos exatos; nada depois
```

**Por que não ZIP**: não há *parser* de arquivo compactado, descompressão (logo, nenhuma bomba de
descompressão) nem caminhos vindos dos metadados do arquivo. A verificação em C++ é feita num único fluxo, e os
arquivos são gravados na área temporária **enquanto** o hash é calculado, sem a janela de TOCTOU de "verificar e depois extrair".

Regras do manifesto (idênticas em Python e C++, com testes de equivalência):

* caminho `^(clamav|yara|ioc)/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (correspondência completa), sem `..`;
* extensões permitidas: ClamAV `.cvd .cld .cud .hdb .hsb .ndb .ldb .cdb .ign2 .fp .sfp`; YARA `.yar .yara`; IOC `.json`;
* nomes de dispositivo do Windows recusados (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`, com ou sem extensão);
* sem duplicatas (comparação sem diferenciar maiúsculas), até 512 arquivos, 1 GiB por arquivo e 4 GiB no total;
* `package_version` `AAAA.M.D[.N]`, monotônica; `min_app_version` `X.Y.Z`;
* números inteiros: aceitos se integrais (Qt não distingue `1` de `1.0`), recusados se booleanos ou fracionários.

Um componente presente no pacote **substitui** o instalado; os ausentes são **mantidos**.

### Conjunto ativo (`<dados>/signatures/active/manifest.json`)

```json
{"format": "gamekernel-signatures", "format_version": 1, "installed_at": "…", "package_id": "…",
 "package_version": "2026.11.13.1", "publisher": "…", "signing_key_id": "…",
 "components": {"yara": {"version": "…", "package_id": "…", "package_version": "…", "installed_at": "…",
                         "count": 42, "files": ["regras.yar"], "sha256": {"regras.yar": "…"}}},
 "history": [{"package_id": "…", "package_version": "…", "installed_at": "…", "signing_key_id": "…",
              "components": ["yara"], "downgrade": false}]}
```

Também é mantido um histórico de operações em `<dados>/signatures/install-history.jsonl`. O registro
administrativo encadeado por hash (`audit_log`) é gravado pelo aplicativo a partir do relatório do instalador.

## 5. Implementação

| Parte | Linguagem | Arquivo |
|---|---|---|
| Formato, construção e assinatura, verificador de referência | Python | `gamekernel/updates/package.py` |
| Preparação (YARA, IOC, ClamAV) e relatório de atualização | Python | `gamekernel/ti/` |
| Ferramentas do publicador | Python | `tools/gk_keygen.py`, `tools/make_update_package.py` |
| **Verificação criptográfica e instalação no aplicativo** | **C++ (libsodium, libyara, Qt Core)** | `native/updates/` (`gk::updates::verifyPackage`, `Installer`, validadores) |
| CLI de administração e testes | C++ | `native/updates/tools/gk_update_cli.cpp` (`gk-update`) |

Recuperação após queda de energia: se a energia cair entre as trocas de pasta, a próxima instalação ou
reversão (ou `Installer::recoverInterrupted()` na inicialização) restaura o conjunto anterior e remove os temporários.
