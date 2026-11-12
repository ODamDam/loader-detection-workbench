#requires -Version 5.1
<#
.SYNOPSIS
Workbench guest runner: execute one target for a fixed time and export every
Sysmon event of the run window as a single <Events> XML document.
.DESCRIPTION
Copied into the isolated analysis VM by the Workbench host (ADR-024) and run
through VBoxManage guestcontrol. Never run on the host. No network access,
downloads, Sysmon configuration changes or credential handling.

Mode Sample   : verify the transferred file's SHA-256, then start it.
Mode Scenario : run one fixed benign scenario (no arbitrary commands).

The target runs for the full TimeoutSeconds (child activity after the root
process exits is still collected), then the whole process tree is stopped,
SettleSeconds are waited for Sysmon to flush, and every event with
EventRecordID greater than the pre-run baseline is exported to
<WorkDirectory>\out\events.xml with run-manifest.json (SHA-256, counts).
Exit codes: 0 ok, 10 invalid arguments, 11 Sysmon not running, 12 log
unreadable, 13 sample hash mismatch, 14 start failed, 15 output exists,
16 export failed, 1 other.
#>
[CmdletBinding()]
param(
    [string]$WorkDirectory = '',
    [string]$RunId = '',
    [ValidateSet('Sample', 'Scenario')][string]$Mode = 'Scenario',
    [string]$SampleFileName = '',
    [string]$ExpectedSha256 = '',
    [string]$Scenario = '',
    [int]$TimeoutSeconds = 0,
    [int]$SettleSeconds = 5
)

$script:WorkbenchExitCodes = @{
    INVALID_ARGUMENTS = 10; SYSMON_NOT_RUNNING = 11; SYSMON_LOG_UNREADABLE = 12
    SAMPLE_HASH_MISMATCH = 13; TARGET_START_FAILED = 14; OUTPUT_EXISTS = 15
    EXPORT_FAILED = 16
}

# Fixed benign scenarios; keep identical to BENIGN_SCENARIOS in
# execution/domain.py (a unit test compares the identifiers).
$script:WorkbenchScenarios = [ordered]@{
    'notepad-open-close'   = '$p = Start-Process -FilePath notepad.exe -PassThru; Start-Sleep -Seconds 3; Stop-Process -Id $p.Id -Force'
    'powershell-inventory' = 'Get-Process | Out-Null; Get-Service | Out-Null; Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot ''System32'') -Filter *.dll | Select-Object -First 50 | Out-Null'
    'registry-probe'       = '$k = ''HKCU:\Software\WorkbenchScenario''; New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name probe -Value 1; Remove-Item -Path $k -Recurse -Force'
    'file-write'           = '$d = Join-Path $env:TEMP ''workbench-scenario''; New-Item -ItemType Directory -Path $d -Force | Out-Null; $f = Join-Path $d ''probe.txt''; Set-Content -LiteralPath $f -Value probe; Add-Content -LiteralPath $f -Value more; Remove-Item -LiteralPath $d -Recurse -Force'
    'dns-invalid'          = 'Resolve-DnsName -Name workbench-probe.example.invalid -ErrorAction SilentlyContinue | Out-Null'
}

function Assert-WorkbenchArguments {
    param([string]$Work, [string]$Run, [string]$RunMode, [string]$File, [string]$Sha, [string]$Name, [int]$Timeout, [int]$Settle)
    if ($Run -notmatch '^VMR-[0-9]{4,}$') { throw 'INVALID_ARGUMENTS: run id' }
    if ($Work -cne "C:\WorkbenchRun\$Run") { throw 'INVALID_ARGUMENTS: work directory' }
    if ($Timeout -lt 10 -or $Timeout -gt 900) { throw 'INVALID_ARGUMENTS: timeout' }
    if ($Settle -lt 0 -or $Settle -gt 60) { throw 'INVALID_ARGUMENTS: settle time' }
    if ($RunMode -eq 'Sample') {
        if ($File -cnotmatch '^[0-9a-f]{64}$' -or $Sha -cnotmatch '^[0-9a-f]{64}$' -or $Name) {
            throw 'INVALID_ARGUMENTS: sample'
        }
    } elseif (-not $script:WorkbenchScenarios.Contains($Name) -or $File -or $Sha) {
        throw 'INVALID_ARGUMENTS: scenario'
    }
}

function Get-WorkbenchLogRecords {
    param([string]$XPath, [int]$MaxEvents = 0)
    $options = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; FilterXPath = $XPath; ErrorAction = 'Stop' }
    if ($MaxEvents -gt 0) { $options.MaxEvents = $MaxEvents }
    try { @(Get-WinEvent @options) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw 'SYSMON_LOG_UNREADABLE: cannot query the Operational log'
    }
}

function Assert-WorkbenchSysmon {
    $services = @(Get-Service -Name Sysmon, Sysmon64 -ErrorAction SilentlyContinue)
    if (@($services | Where-Object { $_.Status -eq 'Running' }).Count -eq 0) {
        throw 'SYSMON_NOT_RUNNING: no running Sysmon service'
    }
    try { $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop }
    catch { throw 'SYSMON_LOG_UNREADABLE: cannot inspect the Operational log' }
    if (-not $log.IsEnabled) { throw 'SYSMON_LOG_UNREADABLE: the Operational log is disabled' }
}

function Get-WorkbenchBaseline {
    $latest = @(Get-WorkbenchLogRecords -XPath '*' -MaxEvents 1)
    if ($latest.Count -eq 0) { return [long]0 }
    return [long]$latest[0].RecordId
}

function Get-WorkbenchSha256 {
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-WorkbenchDescendants {
    param([int]$RootId, [object[]]$Processes)
    $children = @{}
    foreach ($item in $Processes) {
        $parent = [int]$item.ParentProcessId
        if (-not $children.ContainsKey($parent)) { $children[$parent] = New-Object System.Collections.ArrayList }
        [void]$children[$parent].Add([int]$item.ProcessId)
    }
    $result = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($RootId)
    $seen = @{ $RootId = $true }
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        if (-not $children.ContainsKey($current)) { continue }
        foreach ($child in $children[$current]) {
            if ($seen.ContainsKey($child)) { continue }
            $seen[$child] = $true
            [void]$result.Add($child)
            $queue.Enqueue($child)
        }
    }
    return $result.ToArray()
}

function Stop-WorkbenchProcessTree {
    param([int]$RootId)
    $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Select-Object ProcessId, ParentProcessId)
    $ids = @(Get-WorkbenchDescendants -RootId $RootId -Processes $processes)
    [array]::Reverse($ids)
    foreach ($id in @($ids) + @($RootId)) {
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
}

function Start-WorkbenchTarget {
    param([string]$RunMode, [string]$Work, [string]$File, [string]$Sha, [string]$Name)
    if ($RunMode -eq 'Sample') {
        $source = Join-Path $Work $File
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'SAMPLE_HASH_MISMATCH: sample missing' }
        if ((Get-WorkbenchSha256 $source) -cne $Sha) { throw 'SAMPLE_HASH_MISMATCH: sample hash differs' }
        $target = Join-Path $Work ('target-' + $Sha.Substring(0, 12) + '.exe')
        Move-Item -LiteralPath $source -Destination $target -ErrorAction Stop
        if ((Get-WorkbenchSha256 $target) -cne $Sha) { throw 'SAMPLE_HASH_MISMATCH: moved sample hash differs' }
        try { return Start-Process -FilePath $target -WorkingDirectory $Work -PassThru -ErrorAction Stop }
        catch { throw 'TARGET_START_FAILED: sample could not be started' }
    }
    $command = $script:WorkbenchScenarios[$Name]
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        return Start-Process -FilePath $shell -WorkingDirectory $Work -PassThru -WindowStyle Hidden -ErrorAction Stop `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)
    } catch { throw 'TARGET_START_FAILED: scenario could not be started' }
}

function Export-WorkbenchEvents {
    param([long]$Baseline, [string]$OutDirectory, [System.Collections.IDictionary]$Manifest)
    $records = @(Get-WorkbenchLogRecords -XPath "*[System[EventRecordID > $Baseline]]")
    # Get-WinEvent returns newest first; export in record order.
    $ordered = @($records | Sort-Object { [long]$_.RecordId })
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('<Events>')
    foreach ($record in $ordered) {
        $xml = $record.ToXml()
        if ($xml -match '<!DOCTYPE') { throw 'EXPORT_FAILED: DTD in event XML' }
        [void]$builder.Append($xml)
    }
    [void]$builder.Append('</Events>')
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $eventsPath = Join-Path $OutDirectory 'events.xml'
    [IO.File]::WriteAllText($eventsPath, $builder.ToString(), $encoding)
    $Manifest.event_count = $ordered.Count
    $Manifest.events_file = 'events.xml'
    $Manifest.events_sha256 = Get-WorkbenchSha256 $eventsPath
    $Manifest.completed_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $manifestPath = Join-Path $OutDirectory 'run-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ($Manifest | ConvertTo-Json -Depth 3), $encoding)
    if ((Get-WorkbenchSha256 $eventsPath) -cne $Manifest.events_sha256) { throw 'EXPORT_FAILED: events changed' }
    return $ordered.Count
}

function Invoke-WorkbenchGuestRun {
    param([string]$Work, [string]$Run, [string]$RunMode, [string]$File, [string]$Sha, [string]$Name, [int]$Timeout, [int]$Settle)
    $ErrorActionPreference = 'Stop'
    Assert-WorkbenchArguments -Work $Work -Run $Run -RunMode $RunMode -File $File -Sha $Sha -Name $Name -Timeout $Timeout -Settle $Settle
    $out = Join-Path $Work 'out'
    if (Test-Path -LiteralPath $out) { throw 'OUTPUT_EXISTS: output directory exists' }
    Assert-WorkbenchSysmon
    $baseline = Get-WorkbenchBaseline
    $manifest = [ordered]@{
        collector = 'workbench-guest-run'; version = 1; run_id = $Run; mode = $RunMode
        scenario = $null; target_sha256 = $null; baseline_record_id = $baseline
        process_outcome = $null; started_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($RunMode -eq 'Sample') { $manifest.target_sha256 = $Sha } else { $manifest.scenario = $Name }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-WorkbenchTarget -RunMode $RunMode -Work $Work -File $File -Sha $Sha -Name $Name
    try {
        $exited = $process.WaitForExit($Timeout * 1000)
        $manifest.process_outcome = if ($exited) { 'exited' } else { 'timeout_killed' }
        # Keep observing children of an early-exiting root for the full window.
        $remaining = ($Timeout * 1000) - [int]$watch.ElapsedMilliseconds
        if ($remaining -gt 0) { Start-Sleep -Milliseconds $remaining }
    } finally {
        Stop-WorkbenchProcessTree -RootId $process.Id
        $process.Dispose()
    }
    if ($Settle -gt 0) { Start-Sleep -Seconds $Settle }
    [void][IO.Directory]::CreateDirectory($out)
    try { $count = Export-WorkbenchEvents -Baseline $baseline -OutDirectory $out -Manifest $manifest }
    catch {
        if ($_.Exception.Message -match '^(SYSMON_LOG_UNREADABLE|EXPORT_FAILED)') { throw }
        throw 'EXPORT_FAILED: events could not be written'
    }
    Write-Output "collection: complete ($count events)"
}

function Get-WorkbenchExitCode {
    param([string]$Message)
    if ($Message -match '^([A-Z_]+)(:|$)' -and $script:WorkbenchExitCodes.ContainsKey($Matches[1])) {
        return $script:WorkbenchExitCodes[$Matches[1]]
    }
    return 1
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-WorkbenchGuestRun -Work $WorkDirectory -Run $RunId -RunMode $Mode -File $SampleFileName `
            -Sha $ExpectedSha256 -Name $Scenario -Timeout $TimeoutSeconds -Settle $SettleSeconds
        exit 0
    } catch {
        # Never echo event XML, command lines or paths; the host maps exit codes.
        exit (Get-WorkbenchExitCode $_.Exception.Message)
    }
}
