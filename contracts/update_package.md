# Contrato — pacote de atualização offline `.gkpkg` v1

Escrito e mantido pelo Agente B (formato, ferramentas de geração, verificação e instalação em `native/updates`).
Ver `docs/WORK_SPLIT.md` rev. 3 §4. Mudanças incompatíveis exigem `format_version` novo e
registro em `docs/WORK_SPLIT.md` §7.

Implementações que seguem este contrato e são testadas entre si (mesma decisão e mesmo código de erro):

* Python, publicador e referência: `gamekernel/updates/package.py`;
* C++, verificador e instalador do aplicativo: `native/updates/` (`gk::updates`, CLI `gk-update`), implementação
  única segundo `docs/WORK_SPLIT.md` rev. 3;
* testes: `tests/updates/test_equivalence.py` (válidos, 14 adulterações, 27 manifestos assinados porém
  inválidos, 60 mutações aleatórias) e `tests/updates/test_installer.py`.

## 1. Contêiner

Todos os inteiros são *little-endian*.

| Offset | Campo | Tamanho | Regra |
|---|---|---|---|
| 0 | `magic` | 8 | `47 4B 50 4B 47 00 01 00` (`"GKPKG"`, `0x00`, versão do formato `0x01`, reservado `0x00`) |
| 8 | `manifest_len` | 4 | 1 … 1 048 576 |
| 12 | `manifest` | `manifest_len` | JSON UTF-8 estrito (sem `NaN`/`Infinity`), objeto |
| … | `sig_len` | 4 | exatamente 64 |
| … | `signature` | 64 | Ed25519 sobre `magic ‖ manifest_len ‖ manifest` |
| … | *payloads* | Σ tamanhos | arquivos concatenados **na ordem de `files`**, tamanhos exatos; **nada depois** |

Ordem de verificação (a primeira falha decide o código):

1. `magic[0..5]` ≠ `GKPKG\0` → `not_a_package`; byte 6 ≠ 1 → `unsupported_format`;
2. leitura incompleta de qualquer campo → `truncated`;
3. `manifest_len` fora de 1…1 MiB ou `sig_len` ≠ 64 → `invalid_header`;
4. nenhuma chave confiável → `no_trusted_keys`; nenhuma chave confiável valida a assinatura → `bad_signature`;
5. manifesto ilegível ou que viola §2 → `invalid_manifest`;
6. `min_app_version` > versão do aplicativo → `incompatible_app`;
7. para cada arquivo, SHA-256 dos bytes ≠ manifesto → `hash_mismatch` (bytes faltando → `truncated`);
8. sobra qualquer byte após o último arquivo → `trailing_data`.

**Nada é confiável antes do passo 4.** Os arquivos são gravados na área temporária *enquanto* o hash é
calculado (passagem única). Um arquivo com hash errado nunca é ativado.

## 2. Manifesto `gamekernel-update` v1

```json
{
  "format": "gamekernel-update", "format_version": 1,
  "package_id": "uuid", "package_version": "2026.11.12.1", "created_at": "2026-11-12T10:00:00Z",
  "publisher": "Equipe Game Kernel", "description": "", "min_app_version": "1.0.0",
  "components": {"yara": {"version": "2026.11.12.1", "rule_count": 42}, "ioc": {"version": "…", "entry_count": 1000}},
  "files": [{"path": "yara/regras.yar", "size": 1234, "sha256": "<64 hex minúsculos>"}],
  "signing_key_id": "<16 hex>"
}
```

| Regra | Detalhe |
|---|---|
| Campos obrigatórios | os 10 acima, exceto `description` (opcional); textos não vazios |
| `package_version` | `AAAA.M.D` ou `AAAA.M.D.N`, comparada como tupla de 4 inteiros (versão ausente = 0) |
| `min_app_version` | `X.Y.Z` |
| `signing_key_id` | 16 caracteres hexadecimais minúsculos (informativo; a verificação tenta as chaves confiáveis) |
| `components` | objeto não vazio; nomes ∈ {`clamav`, `yara`, `ioc`}; cada um com `version` (texto não vazio); metadados extras permitidos |
| `files` | 1 … 512 entradas; soma ≤ 4 GiB; cada uma ≤ 1 GiB |
| `path` | correspondência **completa** com `(clamav|yara|ioc)/[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, sem `..`, componente declarado em `components` |
| Extensões | `clamav`: `.cvd .cld .cud .hdb .hsb .ndb .ldb .cdb .ign2 .fp .sfp`; `yara`: `.yar .yara`; `ioc`: `.json` |
| Nomes proibidos | dispositivos do Windows `CON PRN AUX NUL COM1-9 LPT1-9`, com ou sem extensão, sem diferenciar maiúsculas |
| Duplicatas | caminhos iguais sem diferenciar maiúsculas são proibidos |
| Componente sem arquivo | proibido |
| Inteiros | número integral com \|n\| ≤ 2^53; booleanos e frações são recusados (`1.0` vale 1, porque o Qt não distingue) |
| `sha256` | 64 hexadecimais **minúsculos** |

Campos desconhecidos são ignorados (adições compatíveis).

## 3. Instalação (semântica que o núcleo deve garantir)

* Uma instalação por vez (trava entre processos em `<dados>/signatures/.install.lock`) → senão `busy`.
* Um componente presente no pacote **substitui** o instalado; os ausentes são **mantidos**.
* `package_version` deve ser **maior** que a do conjunto ativo; igual ou menor → `downgrade`, a menos que o
  usuário confirme explicitamente (registrado em `history[].downgrade`).
* Antes de ativar, cada componente substituído é validado: YARA **compila** (`include` proibido, um *namespace*
  por arquivo, variáveis externas `filename`, `filepath`, `extension`, `filetype` como texto); ClamAV tem
  cabeçalho `ClamAV-VDB` válido e o MD5 do conteúdo do `.cvd` confere com o cabeçalho; bases de texto têm o
  número mínimo de campos (`hdb/hsb/fp/sfp` 3, `ndb` 4, `ldb` 4 separados por `;`, `cdb` 10); IOC segue §4.
  Falha → `validation_failed` e **nada muda**.
* Ativação: `previous/` é removida; `active/` → `previous/`; conjunto novo → `active/`. Falha na troca →
  `previous/` volta a ser `active/`. Recuperação após queda de energia: se `active/` não existe e `previous/`
  existe, `previous/` volta a ser `active/`; temporários em `staging/` são apagados.
* Reverter: troca `active/` ↔ `previous/` (sem anterior → `no_previous`).

Layout (`docs/WORK_SPLIT.md` rev. 1 §3.3, mantido): `<dados>/signatures/{active,previous,staging}/`,
`active/{clamav,yara,ioc}/`, `active/manifest.json`.

### `active/manifest.json` (`gamekernel-signatures` v1)

```json
{"format": "gamekernel-signatures", "format_version": 1, "installed_at": "…", "package_id": "…",
 "package_version": "…", "publisher": "…", "description": "…", "signing_key_id": "…",
 "components": {"<nome>": {"version": "…", "package_id": "…", "package_version": "…", "installed_at": "…",
                           "count": 0, "files": ["…"], "sha256": {"<arquivo>": "<hex>"}}},
 "history": [{"package_id": "…", "package_version": "…", "installed_at": "…", "signing_key_id": "…",
              "components": ["yara"], "downgrade": false}]}
```
Componentes mantidos conservam a entrada do conjunto anterior. `history` guarda as últimas 50 instalações.

## 4. Indicadores locais `gamekernel-ioc` v1

```json
{"format": "gamekernel-ioc", "version": "2026.11.12",
 "entries": [{"sha256": "<64 hex minúsculos>", "verdict": "bad", "name": "…", "category": "trojan",
              "severity": "HIGH", "source": "…", "note": "…"}]}
```
* `verdict` ∈ {`bad`, `good`}; `severity` ∈ {`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`};
  `category` casa com `[a-z_]{1,40}` (gerado pelas ferramentas a partir de `ThreatCategory`);
  `name`/`source`/`note` são texto de até 512 unidades UTF-16.
* O mesmo hash com vereditos diferentes **no componente inteiro** (todos os arquivos) é erro.
* Arquivo ≤ 256 MiB. Implementações: `gamekernel/ti/ioc.py` e `gk::updates::validateIocDir` (equivalência testada).

## 5. Chaves

Chave pública Ed25519 em PEM `SubjectPublicKeyInfo` (DER de 44 bytes com prefixo `302a300506032b6570032100`).
Identificador = 16 primeiros caracteres hexadecimais do SHA-256 dos 32 bytes da chave. Pastas confiáveis:
`<instalação>/signatures/keys/` (build) e `<dados>/trusted_keys/` (adicionadas pelo usuário com confirmação).
