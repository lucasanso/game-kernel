<#
Teste do Game Kernel em uma máquina Windows limpa (Área Restrita do Windows ou máquina virtual nova).

Instala o programa a partir do instalador, confere o que um usuário recebe e desinstala:
  1. ambiente (Windows, runtime do Visual C++ ausente = máquina realmente limpa)
  2. instalação silenciosa
  3. o gk-cli abre (prova que o runtime do Visual C++ que vai junto com o programa funciona)
  4. integridade da instalação: manifesto assinado e, se informada, a chave de release esperada
  5. varredura de uma pasta (e do arquivo de teste EICAR, se o antivírus do Windows não o apagar antes)
  6. a interface abre e fecha
  7. desinstalação: programa removido, dados do usuário preservados
Nada é enviado pela rede (na Área Restrita, a rede fica desligada). O resultado é gravado em
resultado-teste-<data>.txt na mesma pasta do instalador.

Uso:  powershell -ExecutionPolicy Bypass -File teste.ps1 [-Pasta <pasta do instalador>] [-ChaveEsperada <id>]
      (-SemPausa e -SemInterface só para a CI, que não tem área de trabalho)
#>
param(
    [string]$Pasta = $PSScriptRoot,
    [string]$ChaveEsperada = "",
    [switch]$SemPausa,
    [switch]$SemInterface
)

$ErrorActionPreference = "Stop"
$resultados = New-Object System.Collections.Generic.List[object]
$inicio = Get-Date
$arquivoResultado = Join-Path $Pasta ("resultado-teste-{0}.txt" -f $inicio.ToString("yyyyMMdd-HHmmss"))

function Registrar([string]$passo, [bool]$ok, [string]$detalhe) {
    $linha = [pscustomobject]@{ Passo = $passo; Ok = $ok; Detalhe = $detalhe }
    $resultados.Add($linha) | Out-Null
    $marca = if ($ok) { "OK    " } else { "FALHOU" }
    Write-Host ("[{0}] {1} - {2}" -f $marca, $passo, $detalhe)
}

function Passo([string]$nome, [scriptblock]$acao) {
    try {
        $detalhe = & $acao
        Registrar $nome $true ([string]$detalhe)
        return $true
    } catch {
        Registrar $nome $false $_.Exception.Message
        return $false
    }
}

if (-not $ChaveEsperada) {
    $arquivoChave = Join-Path $Pasta "chave-esperada.txt"
    if (Test-Path $arquivoChave) { $ChaveEsperada = (Get-Content $arquivoChave -Raw).Trim() }
}
$instalador = Get-ChildItem -Path $Pasta -Filter "GameKernel-*-setup.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$destino = Join-Path $env:LOCALAPPDATA "Programs\Game Kernel (teste)"
$dados = Join-Path $env:LOCALAPPDATA "GameKernel"
$trabalho = Join-Path $env:TEMP ("gk-teste-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $trabalho | Out-Null

# 1. Ambiente
Passo "Ambiente" {
    $so = (Get-CimInstance Win32_OperatingSystem)
    $vc = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue
    $runtime = if ($vc -and $vc.Installed -eq 1) { "runtime do Visual C++ $($vc.Version) instalado no sistema" } else { "sem runtime do Visual C++ no sistema (máquina limpa)" }
    "{0} {1} (build {2}); {3}" -f $so.Caption, $so.OSArchitecture, $so.BuildNumber, $runtime
} | Out-Null

# 2. Instalação
$instalado = Passo "Instalação silenciosa" {
    if (-not $instalador) { throw "nenhum GameKernel-*-setup.exe em $Pasta" }
    $log = Join-Path $trabalho "instalacao.log"
    $p = Start-Process -FilePath $instalador.FullName -Wait -PassThru -ArgumentList @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/DIR=`"$destino`"", "/LOG=`"$log`"")
    if ($p.ExitCode -ne 0) { throw "o instalador terminou com código $($p.ExitCode) (log: $log)" }
    if (-not (Test-Path (Join-Path $destino "GameKernel.exe"))) { throw "GameKernel.exe não foi instalado" }
    "{0} instalado em {1}" -f $instalador.Name, $destino
}

$cli = Join-Path $destino "gk-cli.exe"
if ($instalado) {
    # 3. O programa abre sem nada além do que veio no instalador
    Passo "gk-cli abre (runtime incluído)" {
        $saida = & $cli --version 2>&1
        if ($LASTEXITCODE -ne 0) { throw "gk-cli --version terminou com código $LASTEXITCODE`: $saida" }
        ($saida | Out-String).Trim()
    } | Out-Null

    # 4. Integridade e assinatura
    Passo "Integridade e assinatura" {
        $json = Join-Path $trabalho "integridade.json"
        & $cli integrity --install-dir $destino --json $json | Out-Null
        $codigo = $LASTEXITCODE
        $r = Get-Content $json -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($codigo -ne 0 -or -not $r.ok) { throw "integridade não confirmada (código $codigo): $($r.detail)" }
        if ($r.signature_valid -ne $true) { throw "manifesto sem assinatura válida" }
        if ($ChaveEsperada -and $r.signer_key_id -ne $ChaveEsperada) {
            throw "assinado pela chave $($r.signer_key_id), mas a chave de release esperada é $ChaveEsperada"
        }
        $origem = if ($ChaveEsperada) { "a chave de release esperada" } else { "chave não conferida (informe -ChaveEsperada)" }
        "{0} arquivos conferidos; assinatura válida da chave {1} ({2})" -f $r.verified, $r.signer_key_id, $origem
    } | Out-Null

    # 5. Varredura
    Passo "Varredura" {
        $alvo = Join-Path $trabalho "Jogo de teste"
        New-Item -ItemType Directory -Force -Path $alvo | Out-Null
        Set-Content -Path (Join-Path $alvo "config.ini") -Value "[video]`r`nfullscreen=1" -Encoding ASCII
        $eicar = Join-Path $alvo "leia_eicar.com"
        # Arquivo de teste EICAR (inofensivo), montado aqui; o antivírus do Windows costuma apagá-lo na hora.
        $texto = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-' + 'TEST-FILE!$H+H*'
        try { [System.IO.File]::WriteAllText($eicar, $texto, [System.Text.Encoding]::ASCII) } catch { }
        Start-Sleep -Seconds 3
        $temEicar = Test-Path $eicar
        $relatorio = Join-Path $trabalho "varredura.json"
        & $cli scan $alvo --json $relatorio --quiet | Out-Null
        $codigo = $LASTEXITCODE
        if (-not (Test-Path $relatorio)) { throw "a varredura não gerou relatório (código $codigo)" }
        $r = Get-Content $relatorio -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($r.summary.status -ne "completed") { throw "varredura terminou como $($r.summary.status): $($r.summary.error)" }
        if ($temEicar) {
            $achado = $r.results | Where-Object { $_.name -eq "leia_eicar.com" -and $_.classification -eq "malware" }
            if (-not $achado -or $codigo -ne 3) { throw "o arquivo de teste EICAR não foi detectado (código $codigo)" }
            "{0} arquivos analisados; EICAR detectado como esperado" -f $r.summary.files_analyzed
        } else {
            if ($codigo -ne 0) { throw "pasta limpa, mas a varredura terminou com código $codigo" }
            "{0} arquivos analisados; o antivírus do Windows apagou o EICAR antes (normal), pasta limpa sem alertas" -f $r.summary.files_analyzed
        }
    } | Out-Null

    # 6. Interface
    if (-not $SemInterface) { Passo "Interface abre e fecha" {
        $app = Start-Process -FilePath (Join-Path $destino "GameKernel.exe") -PassThru
        $titulo = ""
        for ($i = 0; $i -lt 40 -and -not $titulo; $i++) {
            Start-Sleep -Milliseconds 500
            $app.Refresh()
            if ($app.HasExited) { throw "a interface fechou sozinha (código $($app.ExitCode))" }
            $titulo = $app.MainWindowTitle
        }
        if (-not $titulo) { throw "a janela do Game Kernel não apareceu em 20 s" }
        $app.CloseMainWindow() | Out-Null
        if (-not $app.WaitForExit(15000)) { Stop-Process -Id $app.Id -Force; throw "a interface não fechou" }
        "janela '$titulo' aberta e fechada normalmente"
    } | Out-Null }

    # 7. Desinstalação
    Passo "Desinstalação" {
        $desinstalador = Join-Path $destino "unins000.exe"
        if (-not (Test-Path $desinstalador)) { throw "desinstalador não encontrado" }
        Start-Process -FilePath $desinstalador -Wait -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
        for ($i = 0; $i -lt 120 -and (Test-Path (Join-Path $destino "GameKernel.exe")); $i++) { Start-Sleep -Seconds 1 }
        if (Test-Path (Join-Path $destino "GameKernel.exe")) { throw "o programa não foi removido" }
        if (-not (Test-Path (Join-Path $dados "gamekernel.db"))) { throw "os dados do usuário ($dados) não foram preservados" }
        "programa removido; histórico em $dados preservado"
    } | Out-Null
}

Remove-Item -Recurse -Force $trabalho -ErrorAction SilentlyContinue
$falhas = @($resultados | Where-Object { -not $_.Ok }).Count
$linhas = @("Teste do Game Kernel em máquina limpa - $($inicio.ToString('dd/MM/yyyy HH:mm'))",
            "Instalador: $(if ($instalador) { $instalador.Name } else { '(não encontrado)' })", "")
foreach ($r in $resultados) { $linhas += ("[{0}] {1}: {2}" -f $(if ($r.Ok) { "OK" } else { "FALHOU" }), $r.Passo, $r.Detalhe) }
$linhas += ""
$linhas += $(if ($falhas -eq 0) { "RESULTADO: todos os passos OK." } else { "RESULTADO: $falhas passo(s) falharam." })
$linhas | Set-Content -Path $arquivoResultado -Encoding UTF8
Write-Host ""
Write-Host $linhas[-1]
Write-Host "Resultado gravado em $arquivoResultado"
if (-not $SemPausa) {
    Start-Process notepad.exe $arquivoResultado
    Read-Host "Pressione Enter para fechar"
}
exit $falhas
