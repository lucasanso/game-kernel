#Requires -Version 5.1
<#
  Game Kernel - in-VM behaviour monitor (runs ONLY inside a disposable Windows Sandbox VM).

  Started by the sandbox LogonCommand. Reads C:\GKIn\job.json and C:\GKIn\sample.bin (read-only
  mapping), plants decoys, enables Windows auditing, runs the sample, observes it for the
  configured time and writes C:\GKOut\report.json and C:\GKOut\done.json.

  It never downloads, never opens network connections (the VM has networking disabled) and is
  never executed on the host. ASCII only: Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI.
  Report format: gamekernel-sandbox-report v1 (parsed by gamekernel/engines/sandbox_manager.py).
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$InDir = 'C:\GKIn'
$OutDir = 'C:\GKOut'
$Errors = New-Object 'System.Collections.Generic.List[string]'
$Report = [ordered]@{
    format = 'gamekernel-sandbox-report'; version = 1; observed_seconds = 0; sysmon_active = $false
    sample = [ordered]@{}; processes = @(); commands = @(); persistence = [ordered]@{}
    registry = [ordered]@{ changed = @() }; files = [ordered]@{}; credential_access = @()
    network = [ordered]@{ dns = @(); connections = @() }; injection = @(); cpu = [ordered]@{}
    lingering_processes = @(); hosts_modified = $false; errors = @()
}

function Add-Err([string]$Message) { $Errors.Add($Message) | Out-Null }

function Write-Result {
    $Report.errors = @($Errors)
    try {
        $json = $Report | ConvertTo-Json -Depth 8 -Compress
        [IO.File]::WriteAllText((Join-Path $OutDir 'report.json'), $json, (New-Object Text.UTF8Encoding($false)))
    } catch {
        [IO.File]::WriteAllText((Join-Path $OutDir 'report.json'),
            '{"format":"gamekernel-sandbox-report","version":1,"errors":["report serialization failed"]}')
    }
    [IO.File]::WriteAllText((Join-Path $OutDir 'done.json'), '{"ok":true}')
}

# ---------------------------------------------------------------------------------------- helpers
function Get-RegValues([string]$Key) {
    $out = @{}
    if (Test-Path -LiteralPath $Key) {
        $item = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
        if ($item) {
            foreach ($p in $item.PSObject.Properties) {
                if ($p.Name -notlike 'PS*') { $out[$p.Name] = [string]$p.Value }
            }
        }
    }
    return $out
}

function Add-KeyValues([hashtable]$Target, [string[]]$Keys) {
    foreach ($k in $Keys) {
        $values = Get-RegValues $k
        foreach ($n in $values.Keys) { $Target["$k\$n"] = $values[$n] }
    }
}

function Get-Sha256([string]$Path) {
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { return '' }
}

function Set-ReadAudit([string]$Path) {
    # SACL "Everyone (S-1-1-0): ReadData, success" -> event 4663 when anything reads the decoy.
    try {
        $acl = Get-Acl -LiteralPath $Path -Audit
        $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData', 'None', 'None', 'Success')
        $acl.AddAuditRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch { Add-Err "audit rule failed for $Path : $($_.Exception.Message)" }
}

function New-DecoyFile([string]$Path, [string]$Content) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    [IO.File]::WriteAllText($Path, $Content)
    Set-ReadAudit $Path
}

$Roaming = $env:APPDATA
$Local = $env:LOCALAPPDATA
$Pf86 = ${env:ProgramFiles(x86)}
if (-not $Pf86) { $Pf86 = $env:ProgramFiles }

$RunKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$PolicyKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions'
)
$WinlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$IfeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$StartupDirs = @("$Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                 "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
$DropDirs = @($env:TEMP, $Roaming, $Local, $env:ProgramData, "$env:SystemRoot\Temp")
$ExecExt = @('.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.lnk')
$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$SystemScanners = @('msmpeng.exe', 'mpdefendercoreservice.exe', 'searchprotocolhost.exe', 'searchindexer.exe',
                    'mpcopyaccelerator.exe')

function Get-ExecutableIndex {
    $index = @{}
    foreach ($d in $DropDirs) {
        if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
        Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $ExecExt -contains $_.Extension.ToLowerInvariant() } |
            Select-Object -First 20000 | ForEach-Object { $index[$_.FullName] = $_.Length }
    }
    return $index
}

function Get-Snapshot {
    $s = @{ run = @{}; policy = @{}; winlogon = @{}; ifeo = @{}; services = @{}; tasks = @{}; startup = @{}; wmi = @{} }
    Add-KeyValues $s.run $RunKeys
    Add-KeyValues $s.policy $PolicyKeys
    $w = Get-RegValues $WinlogonKey
    foreach ($n in @('Shell', 'Userinit')) { if ($w.ContainsKey($n)) { $s.winlogon[$n] = $w[$n] } }
    Get-ChildItem -LiteralPath $IfeoKey -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { $s.ifeo[$_.PSChildName] = [string]$dbg }
    }
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $s.services[$_.Name] = @{ path = [string]$_.PathName; type = 'service' } }
    Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
        $s.services[$_.Name] = @{ path = [string]$_.PathName; type = 'kernel driver' } }
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $actions = @($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        $s.tasks[$_.TaskPath + $_.TaskName] = $actions
    }
    foreach ($d in $StartupDirs) {
        Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $s.startup[$_.FullName] = $_.Length }
    }
    foreach ($cls in @('__EventConsumer', '__EventFilter', '__FilterToConsumerBinding')) {
        Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction SilentlyContinue | ForEach-Object {
            $s.wmi["$cls\" + [string]$_.Name] = [string]$_.CimClass.CimClassName }
    }
    $s.hosts = Get-Sha256 $HostsPath
    $s.files = Get-ExecutableIndex
    return $s
}

function Get-Added([hashtable]$Before, [hashtable]$After) {
    $out = @()
    foreach ($k in $After.Keys) {
        if (-not $Before.ContainsKey($k)) { $out += [ordered]@{ name = [string]$k; value = [string]$After[$k] } }
        elseif ([string]$Before[$k] -ne [string]$After[$k]) {
            $out += [ordered]@{ name = [string]$k; value = [string]$After[$k]; before = [string]$Before[$k] } }
    }
    return ,$out
}

function Get-EventData($Event) {
    $d = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($n in $xml.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
    } catch { }
    return $d
}

function ConvertFrom-HexPid([string]$Value) {
    try { if ($Value -like '0x*') { return [Convert]::ToInt32($Value.Substring(2), 16) } return [int]$Value }
    catch { return -1 }
}

# ---------------------------------------------------------------------------------------- main
try {
    $job = Get-Content -Raw -LiteralPath (Join-Path $InDir 'job.json') | ConvertFrom-Json
    $timeout = [Math]::Max(30, [Math]::Min(1800, [int]$job.timeout_seconds))
    $sampleName = ([string]$job.name) -replace '[^A-Za-z0-9._ -]', '_'
    $ext = [IO.Path]::GetExtension($sampleName).ToLowerInvariant()

    # 1. Auditing (subcategory GUIDs work on every Windows language).
    & auditpol.exe /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null   # File System
    & auditpol.exe /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null   # Process Creation
    & auditpol.exe /set /subcategory:'{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null  # WFP connection
    New-Item -Force -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
    & wevtutil.exe sl Security /ms:268435456 | Out-Null
    & wevtutil.exe sl 'Microsoft-Windows-DNS-Client/Operational' /e:true | Out-Null

    # 2. Decoys: fake credential stores (content is meaningless) and canary documents.
    $Decoys = @(
        @{ decoy = 'browser_passwords'; path = "$Local\Google\Chrome\User Data\Default\Login Data" },
        @{ decoy = 'browser_cookies';   path = "$Local\Google\Chrome\User Data\Default\Network\Cookies" },
        @{ decoy = 'browser_keys';      path = "$Local\Google\Chrome\User Data\Local State" },
        @{ decoy = 'browser_passwords'; path = "$Local\Microsoft\Edge\User Data\Default\Login Data" },
        @{ decoy = 'browser_cookies';   path = "$Local\Microsoft\Edge\User Data\Default\Network\Cookies" },
        @{ decoy = 'browser_passwords'; path = "$Roaming\Mozilla\Firefox\Profiles\gk.default-release\logins.json" },
        @{ decoy = 'browser_keys';      path = "$Roaming\Mozilla\Firefox\Profiles\gk.default-release\key4.db" },
        @{ decoy = 'browser_cookies';   path = "$Roaming\Mozilla\Firefox\Profiles\gk.default-release\cookies.sqlite" },
        @{ decoy = 'discord_tokens';    path = "$Roaming\discord\Local Storage\leveldb\000003.ldb" },
        @{ decoy = 'steam_session';     path = "$Pf86\Steam\config\loginusers.vdf" },
        @{ decoy = 'telegram_session';  path = "$Roaming\Telegram Desktop\tdata\key_datas" },
        @{ decoy = 'crypto_wallet';     path = "$Roaming\Exodus\exodus.wallet\passphrase.json" }
    )
    New-Item -ItemType Directory -Force -Path "$Roaming\Mozilla\Firefox" | Out-Null
    [IO.File]::WriteAllText("$Roaming\Mozilla\Firefox\profiles.ini",
        "[Profile0]`r`nName=default-release`r`nIsRelative=1`r`nPath=Profiles/gk.default-release`r`nDefault=1`r`n")
    foreach ($d in $Decoys) { New-DecoyFile $d.path ('GK-DECOY ' + [guid]::NewGuid().ToString() + ' ' + $d.decoy) }

    $Canaries = @{}
    $docDirs = @([Environment]::GetFolderPath('MyDocuments'), [Environment]::GetFolderPath('Desktop'),
                 [Environment]::GetFolderPath('MyPictures'))
    $names = @('relatorio_financeiro.docx', 'planilha_contas.xlsx', 'contrato.pdf', 'ferias_2026.jpg',
               'senhas_antigas.txt', 'save_game_backup.dat', 'notas.txt', 'foto_familia.png')
    foreach ($dir in $docDirs) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        foreach ($n in $names) {
            $p = Join-Path $dir ('gk_' + $n)
            $bytes = New-Object byte[] 4096
            (New-Object Random).NextBytes($bytes)
            [IO.File]::WriteAllBytes($p, $bytes)
            $Canaries[$p] = Get-Sha256 $p
        }
    }

    # 3. Optional Sysmon (user-provided, Sysinternals license) for injection visibility.
    if ($job.sysmon) {
        $sysmonExe = Get-ChildItem -LiteralPath (Join-Path $InDir 'sysmon') -Filter 'Sysmon*.exe' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($sysmonExe) {
            $cfg = Join-Path $env:TEMP 'gk-sysmon.xml'
            [IO.File]::WriteAllText($cfg, '<Sysmon schemaversion="4.50"><EventFiltering><RuleGroup name="gk" groupRelation="or">' +
                '<CreateRemoteThread onmatch="exclude"/><ProcessAccess onmatch="include"><GrantedAccess condition="contains any">' +
                '0x1F0FFF;0x1FFFFF;0x1F3FFF;0x143A;0x1438;0x0020;0x0028;0x0820</GrantedAccess></ProcessAccess>' +
                '</RuleGroup></EventFiltering></Sysmon>')
            $copy = Join-Path $env:TEMP $sysmonExe.Name
            Copy-Item -LiteralPath $sysmonExe.FullName -Destination $copy -Force
            & $copy -accepteula -i $cfg | Out-Null
            $Report.sysmon_active = ($LASTEXITCODE -eq 0)
            if (-not $Report.sysmon_active) { Add-Err "sysmon installation failed ($LASTEXITCODE)" }
        }
    }

    $before = Get-Snapshot

    # 4. Run the sample (copied from the read-only mapping under its original, sanitized name).
    $desk = [Environment]::GetFolderPath('Desktop')
    $dst = Join-Path $desk $sampleName
    Copy-Item -LiteralPath (Join-Path $InDir 'sample.bin') -Destination $dst -Force
    $Report.sample = [ordered]@{ name = $sampleName; sha256 = (Get-Sha256 $dst); expected_sha256 = [string]$job.sha256
                                 started = $false; main_exited = $false; exit_code = $null }
    if ($Report.sample.sha256 -ne [string]$job.sha256) { throw 'sample hash mismatch inside the VM' }
    $sys32 = "$env:SystemRoot\System32"
    $startTime = Get-Date
    $proc = $null
    try {
        switch ($ext) {
            '.exe' { $proc = Start-Process -FilePath $dst -WorkingDirectory $desk -PassThru }
            '.dll' { $proc = Start-Process -FilePath "$sys32\rundll32.exe" -ArgumentList "`"$dst`",#1" -PassThru }
            { $_ -in '.bat', '.cmd' } { $proc = Start-Process -FilePath "$sys32\cmd.exe" -ArgumentList "/c `"$dst`"" -WorkingDirectory $desk -PassThru }
            '.ps1' { $proc = Start-Process -FilePath "$sys32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$dst`"" -PassThru }
            { $_ -in '.vbs', '.js' } { $proc = Start-Process -FilePath "$sys32\wscript.exe" -ArgumentList "`"$dst`"" -PassThru }
            '.msi' { $proc = Start-Process -FilePath "$sys32\msiexec.exe" -ArgumentList "/i `"$dst`" /qn" -PassThru }
            default { throw "unsupported extension $ext" }
        }
        $Report.sample.started = $true
    } catch {
        $Report.sample.start_error = $_.Exception.Message
    }

    # 5. Observe.
    $tree = New-Object 'System.Collections.Generic.HashSet[int]'
    $procInfo = @{}
    $prevCpu = @{}
    $connections = @{}
    $samples = 0; $high = 0; $hasWindow = $false; $busiest = ''
    $logical = [Math]::Max(1, [Environment]::ProcessorCount)
    if ($proc) { [void]$tree.Add($proc.Id) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($proc -and $sw.Elapsed.TotalSeconds -lt $timeout) {
        Start-Sleep -Milliseconds 1000
        foreach ($w in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
            $id = [int]$w.ProcessId
            if (-not $tree.Contains($id) -and $tree.Contains([int]$w.ParentProcessId)) { [void]$tree.Add($id) }
            if ($tree.Contains($id) -and -not $procInfo.ContainsKey("$id")) {
                $procInfo["$id"] = [ordered]@{ pid = $id; ppid = [int]$w.ParentProcessId; name = [string]$w.Name
                                              command_line = [string]$w.CommandLine; path = [string]$w.ExecutablePath
                                              first_seen = [Math]::Round($sw.Elapsed.TotalSeconds, 1) }
            }
        }
        $cpu = 0.0
        foreach ($id in @($tree)) {
            $gp = Get-Process -Id $id -ErrorAction SilentlyContinue
            if (-not $gp) { continue }
            $t = $gp.TotalProcessorTime.TotalSeconds
            if ($prevCpu.ContainsKey("$id")) { $cpu += ($t - $prevCpu["$id"]) }
            $prevCpu["$id"] = $t
            if ($gp.MainWindowHandle -ne [IntPtr]::Zero) { $hasWindow = $true }
            $busiest = $gp.ProcessName
        }
        $samples++
        if (($cpu / $logical) -ge 0.85) { $high++ }
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $tree.Contains([int]$_.OwningProcess) } |
            ForEach-Object { $connections["$($_.RemoteAddress):$($_.RemotePort)"] = [ordered]@{
                remote = "$($_.RemoteAddress):$($_.RemotePort)"; state = [string]$_.State; pid = [int]$_.OwningProcess } }
    }
    $Report.observed_seconds = [Math]::Round($sw.Elapsed.TotalSeconds)
    if ($proc) {
        $Report.sample.main_exited = $proc.HasExited
        if ($proc.HasExited) { $Report.sample.exit_code = $proc.ExitCode }
    }

    # 6. Security log: full process tree (short-lived processes included), command lines, decoy reads.
    $creations = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $startTime } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated)
    foreach ($e in $creations) {
        $d = Get-EventData $e
        $newPid = ConvertFrom-HexPid $d['NewProcessId']
        $creator = ConvertFrom-HexPid $d['ProcessId']
        if ($tree.Contains($creator) -and -not $tree.Contains($newPid)) { [void]$tree.Add($newPid) }
        if ($tree.Contains($newPid) -and -not $procInfo.ContainsKey("$newPid")) {
            $procInfo["$newPid"] = [ordered]@{ pid = $newPid; ppid = $creator; name = (Split-Path -Leaf $d['NewProcessName'])
                                               command_line = $d['CommandLine']; path = $d['NewProcessName']; first_seen = $null }
        }
    }
    $Report.processes = @($procInfo.Values)
    $Report.commands = @($procInfo.Values | Where-Object { $_.command_line } |
        ForEach-Object { [ordered]@{ process = $_.name; command_line = $_.command_line } })

    $decoyByPath = @{}
    foreach ($d in $Decoys) { $decoyByPath[$d.path.ToLowerInvariant()] = $d.decoy }
    $reads = @{}
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $startTime } -ErrorAction SilentlyContinue)) {
        $d = Get-EventData $e
        $obj = ([string]$d['ObjectName']).ToLowerInvariant()
        if (-not $decoyByPath.ContainsKey($obj)) { continue }
        $readerPid = ConvertFrom-HexPid $d['ProcessId']
        $reader = [string]$d['ProcessName']
        if ($readerPid -eq $PID -or $SystemScanners -contains (Split-Path -Leaf $reader).ToLowerInvariant()) { continue }
        $reads["$obj|$readerPid"] = [ordered]@{ decoy = $decoyByPath[$obj]; path = $d['ObjectName']; process = $reader
                                                in_tree = $tree.Contains($readerPid) }
    }
    $Report.credential_access = @($reads.Values)

    # 7. Network attempts (networking is disabled: these never left the VM).
    $ignore = '(^|\.)(microsoft|windows|windowsupdate|msftncsi|msftconnecttest|live|bing|msn|office|azure|azureedge|digicert|skype)\.(com|net)$'
    $dns = @{}
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Id = 3006; StartTime = $startTime } -ErrorAction SilentlyContinue)) {
        $q = [string](Get-EventData $e)['QueryName']
        if ($q -and $q -notmatch $ignore) { $dns[$q.ToLowerInvariant()] = $true }
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5156, 5157); StartTime = $startTime } -ErrorAction SilentlyContinue)) {
        $d = Get-EventData $e
        if ($tree.Contains((ConvertFrom-HexPid $d['ProcessID']))) {
            $remote = "$($d['DestAddress']):$($d['DestPort'])"
            $connections[$remote] = [ordered]@{ remote = $remote; state = ('wfp-' + $e.Id); pid = (ConvertFrom-HexPid $d['ProcessID']) }
        }
    }
    $Report.network = [ordered]@{ dns = @($dns.Keys); connections = @($connections.Values) }

    # 8. Injection (Sysmon 8 = CreateRemoteThread, 10 = ProcessAccess) from the sample tree into other processes.
    if ($Report.sysmon_active) {
        $inj = @()
        foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = @(8, 10); StartTime = $startTime } -ErrorAction SilentlyContinue)) {
            $d = Get-EventData $e
            $src = [int]$d['SourceProcessId']; $dst2 = [int]$d['TargetProcessId']
            if ($tree.Contains($src) -and -not $tree.Contains($dst2)) {
                $inj += [ordered]@{ kind = $(if ($e.Id -eq 8) { 'CreateRemoteThread' } else { 'ProcessAccess ' + $d['GrantedAccess'] })
                                    source = $d['SourceImage']; target = $d['TargetImage'] }
            }
        }
        $Report.injection = @($inj | Select-Object -First 100)
    }

    # 9. After-state and differences.
    $after = Get-Snapshot
    $persist = [ordered]@{}
    $persist.run_keys_added = Get-Added $before.run $after.run
    $persist.tasks_added = Get-Added $before.tasks $after.tasks
    $persist.startup_files_added = Get-Added $before.startup $after.startup
    $persist.wmi_added = Get-Added $before.wmi $after.wmi
    $persist.ifeo_added = Get-Added $before.ifeo $after.ifeo
    $persist.winlogon_changed = Get-Added $before.winlogon $after.winlogon
    $svc = @()
    foreach ($k in $after.services.Keys) {
        if (-not $before.services.ContainsKey($k)) {
            $svc += [ordered]@{ name = [string]$k; path = $after.services[$k].path; type = $after.services[$k].type } }
    }
    $persist.services_added = $svc
    $Report.persistence = $persist
    $policy = @()
    foreach ($item in (Get-Added $before.policy $after.policy)) {
        $key = Split-Path -Parent $item.name
        $policy += [ordered]@{ key = $key; value = (Split-Path -Leaf $item.name); after = $item.value }
    }
    $Report.registry = [ordered]@{ changed = $policy }
    $Report.hosts_modified = ($before.hosts -ne $after.hosts)

    $modified = @(); $deleted = @()
    foreach ($p in $Canaries.Keys) {
        if (-not (Test-Path -LiteralPath $p)) { $deleted += [ordered]@{ path = $p } }
        elseif ((Get-Sha256 $p) -ne $Canaries[$p]) { $modified += [ordered]@{ path = $p } }
    }
    $dropped = @()
    foreach ($f in $after.files.Keys) {
        if (-not $before.files.ContainsKey($f) -and $f -notlike "$OutDir*" -and $f -ne $dst) {
            $dropped += [ordered]@{ path = $f; size = $after.files[$f]; sha256 = (Get-Sha256 $f) }
            if ($dropped.Count -ge 100) { break }
        }
    }
    $Report.files = [ordered]@{ canaries_modified = $modified; canaries_deleted = $deleted; dropped_executables = $dropped }
    $Report.cpu = [ordered]@{ samples = $samples; high_usage_ratio = $(if ($samples) { [Math]::Round($high / $samples, 2) } else { 0 })
                             has_window = $hasWindow; process = $busiest }
    $Report.lingering_processes = @($tree | ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue } |
        Where-Object { $_ } | ForEach-Object { [ordered]@{ pid = $_.Id; name = $_.ProcessName } })
} catch {
    Add-Err ("monitor failure: " + $_.Exception.Message)
} finally {
    Write-Result
}
