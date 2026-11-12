# Game Kernel — Arquitetura (FASE 1)

Game Kernel é um aplicativo **desktop nativo para Windows 10/11 x64** (Python 3 + PySide6/Qt),
100% offline, especializado em investigar pastas de jogos, cracks, repacks, mods e launchers.

## 1. Princípios

| Princípio | Como é aplicado |
|---|---|
| Offline por construção | Nenhum módulo de rede é usado. Um *audit hook* do Python (`gamekernel/netguard.py`) bloqueia `connect`, `getaddrinfo`, `sendto`, `urllib`, `webbrowser` etc. em todos os processos do app. O instalador pode criar regras de firewall de saída. Atualizações apenas por pacote local assinado. |
| Nunca executar o que é analisado | Toda análise é estática (leitura de bytes). A análise comportamental só ocorre dentro de uma VM descartável (Windows Sandbox) sem rede; se o isolamento não estiver disponível, a execução é recusada. |
| Evidência, não palpite | Cada achado é um objeto `Evidence` com fonte, regra, local exato (offset/RVA/seção/linha), confiança qualitativa e nota de falso positivo. A classificação final é derivada por regras explicáveis. Nenhuma porcentagem inventada. |
| Contexto de jogos | Cracks, emuladores de Steam, proxies de DLL (ReShade, ASI Loader) e DRM têm características parecidas com malware. O módulo de contexto (`game_context.py`) reconhece esses componentes e rebaixa apenas indicadores *esperados* — nunca detecções por assinatura. |
| Preservação | Nada é apagado ou movido automaticamente. Quarentena é sempre ação do usuário (exceto se ele habilitar explicitamente a quarentena automática do monitor em tempo real). |

## 2. Visão geral

```
┌──────────────────────────── UI (PySide6) ─────────────────────────────┐
│ Dashboard │ Scanner │ Resultados │ Quarentena │ Histórico │ Tempo real │
│ Sandbox │ Atualizações │ Privacidade/Rede │ Configurações                │
└───────────────┬───────────────────────────────────────────────────────┘
                │ QThread (ScanWorker) / sinais Qt
┌───────────────▼──────────────── core ─────────────────────────────────┐
│ scanner.py (Orquestrador: enumeração → hash/cache → pool de processos │
│            → ClamAV em lote → contexto de pasta → risco → persistência)│
│ detection_engine.py (executa os motores sobre 1 arquivo, em worker)   │
│ risk_engine.py (agrega evidências → risco, classificação, explicação) │
│ threat_catalog.py (o que cada ameaça faz, dados em risco, ações)      │
│ report_engine.py (JSON / HTML / PDF)                                   │
└───────┬─────────────────────────────────────────────┬─────────────────┘
        │                                             │
┌───────▼──────── engines (independentes) ──────┐  ┌──▼── infraestrutura ──┐
│ clamav_engine   – clamscan em lote (assinat.) │  │ database (SQLite WAL)  │
│ yara_engine     – regras YARA compiladas      │  │ quarantine (AES-GCM)   │
│ pe_analyzer     – estrutura PE, seções, IAT,  │  │ updates (Ed25519)      │
│                   recursos, overlay, entropia │  │ realtime (watchdog)    │
│ authenticode    – WinVerifyTrust / signify    │  │ integrity, audit log   │
│ strings_analyzer– strings + IOCs com offset   │  │ netguard (offline)     │
│ static_heuristics–correlação de capacidades   │  └────────────────────────┘
│ script_analyzer – BAT/PS1/VBS/JS/REG/HTA/LNK  │
│ archive_engine  – ZIP/7z/RAR/ISO/TAR/CAB/MSI  │
│ pyinstaller     – arquivos embutidos          │
│ reputation      – hashes locais bons/ruins    │
│ game_context    – cracks, emuladores, mods    │
│ sandbox_manager – Windows Sandbox (opcional)  │
└───────────────────────────────────────────────┘
```

## 3. Pipeline de análise

1. **Enumeração** (`core/enumerator.py`): caminha a pasta sem seguir links, aplica exclusões,
   identifica o tipo **pelo conteúdo** (magic bytes) e não só pela extensão, e prioriza
   (executáveis e scripts primeiro). No modo rápido, arquivos de dados grandes (pak, vídeo, áudio)
   recebem apenas verificação de cabeçalho (detecta PE disfarçado).
2. **Hash + cache** (`core/hashing.py`): SHA-256 em streaming; cache `(caminho, tamanho, mtime)` →
   SHA-256 e `(SHA-256, impressão dos motores)` → evidências. Arquivos inalterados não são relidos.
3. **Análise por arquivo** (`core/worker.py`, pool de processos): YARA, PE, Authenticode, strings,
   scripts, arquivos compactados recursivos (com limites anti-bomba), PyInstaller, reputação.
   Membros executáveis extraídos de compactados são gravados (sem extensão executável) numa pasta
   temporária privada para a segunda passada do ClamAV.
4. **ClamAV em lote** (`engines/clamav_engine.py`): um único `clamscan --file-list` por lote
   (o banco é carregado uma vez). Pausável (suspensão do processo) e cancelável.
5. **Contexto de pasta** (`engines/game_context.py`): correlaciona arquivos irmãos
   (ex.: `steam_api64.dll` sem assinatura da Valve + `steam_settings/` = emulador Goldberg).
6. **Risco** (`core/risk_engine.py`): combina evidências → nível (CRÍTICO…INFORMATIVO),
   classificação (legítimo conhecido, desconhecido, modificado, PUA, suspeito, malware,
   inconclusivo), estado de crack e a explicação passo a passo.
7. **Persistência** (`database/db.py`): resultados, evidências e histórico em SQLite (WAL).

## 4. Escolha de tecnologias

| Tecnologia | Versão fixada | Avaliação |
|---|---|---|
| Python | 3.13 | Orquestração; empacotado com PyInstaller (usuário não precisa de Python). |
| PySide6 | 6.12.0 | Qt oficial, LGPL; UI nativa, QThread, pintura customizada (sem QtCharts/QtWebEngine). |
| ClamAV | 1.5.x (binários Windows oficiais) | Motor de assinaturas maduro; bancos CVD assinados digitalmente pela Cisco Talos. Executado via `clamscan` em lote — sem daemon e sem rede. |
| YARA (yara-python) | 4.5.4 | Padrão da indústria; módulos `pe`, `dotnet`, `math` disponíveis. |
| pefile | 2024.8.26 | Parser PE puro Python, tolerante a arquivos malformados. |
| signify | 0.9.3 | Parser Authenticode multiplataforma (fallback e detalhes de certificado). No Windows a validação principal usa `WinVerifyTrust` com recuperação de URL **apenas de cache** (sem CRL/OCSP online). |
| SQLite | embutido | WAL, `quick_check` na inicialização, recuperação automática. |
| cryptography | 50.0.2 | Ed25519 (pacotes de atualização, manifesto de integridade) e AES-256-GCM (quarentena). |
| py7zr / rarfile / pycdlib | 1.1.4 / 4.5 / 1.22.0 | Leitura de 7z, RAR (via `unrar`/`7z` locais) e ISO em memória. |
| 7-Zip (7z.exe) | 24.x | Backend opcional para RAR/CAB/MSI e formatos não suportados em Python. |
| watchdog | 7.1.0 | `ReadDirectoryChangesW` no Windows — sem hooks de kernel. |
| psutil | 7.2.2 | CPU/memória, prioridade de processos, auditoria de conexões. |
| reportlab | 5.1.0 | PDF offline. |
| Windows Sandbox | recurso do Windows Pro/Enterprise/Education | VM descartável baseada em Hyper-V; configurada sem rede, sem clipboard, pasta da amostra somente leitura. |

## 5. Dados e diretórios

| Caminho | Conteúdo |
|---|---|
| `<instalação>\` | Executável, regras YARA base, chaves públicas confiáveis, ClamAV, 7-Zip, `integrity_manifest.json(.sig)` |
| `%LOCALAPPDATA%\GameKernel\` | `gamekernel.db`, `settings.json`, `quarantine\`, `signatures\active\`, `reports\`, `logs\`, `temp\` |
| Versão portátil | igual, mas em `.\data\` ao lado do executável (arquivo `portable.flag`) |

## 6. Segurança do próprio aplicativo

* Subprocessos sempre com caminho absoluto, `shell=False`, sem janela e com diretório de trabalho
  no diretório da ferramenta (evita sequestro de DLL a partir da pasta do jogo).
* Binários auxiliares (clamscan, 7z, sigtool) verificados contra o manifesto de integridade antes do uso.
* Log administrativo encadeado por hash (adulteração detectável).
* Chave da quarentena protegida por DPAPI (Windows) — os arquivos isolados são cifrados com
  AES-256-GCM e gravados com extensão `.gkq`, impedindo execução acidental.

## 7. Extensibilidade

Cada motor implementa uma interface simples (`analyze(ctx) -> list[Evidence]`) e pode ser
desligado nas configurações. O `sandbox_manager` define um *backend* abstrato; o backend
Windows Sandbox é o implementado, e outros (VirtualBox/Hyper-V com snapshot) podem ser
adicionados sem alterar o resto do sistema.
