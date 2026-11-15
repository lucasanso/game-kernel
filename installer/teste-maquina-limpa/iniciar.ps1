<#
Abre a Área Restrita do Windows (Windows Sandbox) — um Windows limpo e descartável, sem rede — e roda nela o
teste do instalador (teste.ps1). Coloque nesta pasta o GameKernel-<versão>-setup.exe (ou informe -Instalador).
Ao terminar, o resultado aparece no Bloco de Notas e fica em resultado-teste-<data>.txt nesta pasta.

Requisitos: Windows 10/11 Pro, Enterprise ou Education com o recurso "Área Restrita do Windows" ativado
(Painel de Controle > Programas > Ativar ou desativar recursos do Windows). No Windows Home, use uma máquina
virtual nova e rode teste.ps1 dentro dela.

Uso:  powershell -ExecutionPolicy Bypass -File iniciar.ps1 [-Instalador <caminho do setup.exe>] [-ChaveEsperada <id>]
#>
param(
    [string]$Instalador = "",
    [string]$ChaveEsperada = ""
)

$ErrorActionPreference = "Stop"
$aqui = $PSScriptRoot
$sandbox = Join-Path $env:windir "System32\WindowsSandbox.exe"
if (-not (Test-Path $sandbox)) {
    Write-Host "A Área Restrita do Windows não está ativada neste computador."
    Write-Host "Ative em: Painel de Controle > Programas > Ativar ou desativar recursos do Windows > Área Restrita do Windows"
    Write-Host "(disponível no Windows 10/11 Pro, Enterprise e Education). No Windows Home, use uma máquina virtual"
    Write-Host "nova e rode teste.ps1 dentro dela."
    exit 1
}
if ($Instalador) { Copy-Item -Path $Instalador -Destination $aqui -Force }
if (-not (Get-ChildItem -Path $aqui -Filter "GameKernel-*-setup.exe")) {
    Write-Host "Coloque o GameKernel-<versão>-setup.exe nesta pasta ($aqui) ou use -Instalador."
    exit 1
}
if ($ChaveEsperada) { Set-Content -Path (Join-Path $aqui "chave-esperada.txt") -Value $ChaveEsperada -Encoding ASCII }

$dentro = "C:\GameKernelTeste"
$config = @"
<Configuration>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$([System.Security.SecurityElement]::Escape($aqui))</HostFolder>
      <SandboxFolder>$dentro</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dentro\teste.ps1 -Pasta $dentro</Command>
  </LogonCommand>
</Configuration>
"@
$wsb = Join-Path $aqui "GameKernel-teste.wsb"
Set-Content -Path $wsb -Value $config -Encoding UTF8
Write-Host "Abrindo a Área Restrita do Windows (sem rede). O teste começa sozinho em alguns segundos."
Start-Process -FilePath $wsb
