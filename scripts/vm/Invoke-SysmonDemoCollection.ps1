#requires -Version 5.1
<#
.SYNOPSIS
Collect one correlated benign Sysmon Process Create / File Create pair in a guest.
.DESCRIPTION
Run manually in the prepared Windows guest, not on the host. No VM control,
credentials, Sysmon configuration changes, downloads or network requests.
OutputDirectory must not exist. Raw XML is runtime data and must stay outside Git.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 20,
    [string]$DemoRoot = (Join-Path $env:SystemDrive 'SysmonDemo')
)

function Get-DemoLogRecords {
    param([string]$XPath, [int]$MaxEvents = 0)
    $options = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; FilterXPath = $XPath; ErrorAction = 'Stop' }
    if ($MaxEvents -gt 0) { $options.MaxEvents = $MaxEvents }
    try { @(Get-WinEvent @options) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw 'SYSMON_LOG_UNREADABLE: cannot query the local Operational log.'
    }
}

function Assert-DemoReadiness {
    $services = @(Get-Service -Name Sysmon, Sysmon64 -ErrorAction SilentlyContinue)
    if (@($services | Where-Object { $_.Status -eq 'Running' }).Count -eq 0) {
        throw 'SYSMON_NOT_RUNNING: a Sysmon service must already be running.'
    }
    try { $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop }
    catch { throw 'SYSMON_LOG_UNREADABLE: cannot inspect the local Operational log.' }
    if (-not $log.IsEnabled) { throw 'SYSMON_LOG_DISABLED: enablement must be prepared manually.' }
    # Read-only evidence of coverage, not an attempt to infer arbitrary config rules.
    foreach ($id in @(1, 11)) {
        if (@(Get-DemoLogRecords -XPath "*[System[EventID=$id]]" -MaxEvents 1).Count -eq 0) {
            throw 'SYSMON_COVERAGE_UNVERIFIED: prepare and manually verify Event IDs 1 and 11 first.'
        }
    }
}

function ConvertTo-DemoEvent {
    param($Record)
    $raw = $Record.ToXml()
    if ($raw -match '<!DOCTYPE') { throw 'INVALID_EVENT_XML: DTD is not allowed.' }
    $document = New-Object System.Xml.XmlDocument
    $document.XmlResolver = $null
    $document.LoadXml($raw)
    $ns = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $root = $document.SelectSingleNode('/e:Event', $ns)
    if ($null -eq $root) { throw 'INVALID_EVENT_XML: expected a single namespaced Event.' }
    $provider = $root.SelectSingleNode('e:System/e:Provider', $ns)
    if ($null -eq $provider -or $provider.GetAttribute('Name') -ne 'Microsoft-Windows-Sysmon') {
        throw 'INVALID_EVENT_XML: incorrect provider.'
    }
    $idNodes = @($root.SelectNodes('e:System/e:EventID', $ns))
    $recordNodes = @($root.SelectNodes('e:System/e:EventRecordID', $ns))
    if ($idNodes.Count -ne 1 -or $recordNodes.Count -ne 1) { throw 'INVALID_EVENT_XML: ambiguous identity.' }
    $recordId = [long]0
    $eventId = [int]0
    if (-not [long]::TryParse($recordNodes[0].InnerText, [ref]$recordId) -or $recordId -le 0 -or
        -not [int]::TryParse($idNodes[0].InnerText, [ref]$eventId) -or $eventId -notin @(1, 11)) {
        throw 'INVALID_EVENT_XML: unsupported event or record identity.'
    }
    $data = @{}
    foreach ($node in $root.SelectNodes('e:EventData/e:Data', $ns)) {
        $name = $node.GetAttribute('Name')
        if (-not $name -or $data.ContainsKey($name)) { throw 'INVALID_EVENT_XML: ambiguous EventData.' }
        $data[$name] = $node.InnerText
    }
    [pscustomobject]@{ EventId = $eventId; RecordId = $recordId; Data = $data; Xml = $raw }
}

function Select-DemoPair {
    param([object[]]$Events, [long]$Baseline, [string]$RunId, [string]$Target, [int]$ChildId)
    $processes = @($Events | Where-Object {
        $_.EventId -eq 1 -and $_.RecordId -gt $Baseline -and
        $_.Data['ProcessId'] -eq [string]$ChildId -and
        $_.Data['CommandLine'] -and $_.Data['CommandLine'].Contains($RunId) -and
        $_.Data['CommandLine'].Contains("hello-workbench-$RunId")
    })
    if ($processes.Count -gt 1) { throw 'AMBIGUOUS_PROCESS: more than one matching Process Create.' }
    if ($processes.Count -eq 0) { return }
    $process = $processes[0]
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($process.Data['ProcessGuid'], [ref]$guid)) { throw 'INVALID_PROCESS_GUID' }
    $files = @($Events | Where-Object {
        $_.EventId -eq 11 -and $_.RecordId -gt $process.RecordId -and
        $_.Data['ProcessGuid'] -eq $process.Data['ProcessGuid'] -and
        $_.Data['ProcessId'] -eq $process.Data['ProcessId'] -and
        [string]::Equals($_.Data['TargetFilename'], $Target, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($files.Count -gt 1) { throw 'AMBIGUOUS_FILE: more than one matching File Create.' }
    if ($files.Count -eq 0) { return }
    foreach ($event in @($process, $files[0])) {
        $required = @('UtcTime', 'ProcessGuid', 'ProcessId', 'Image')
        if ($event.EventId -eq 1) { $required += 'CommandLine' }
        else { $required += @('TargetFilename', 'CreationUtcTime') }
        foreach ($name in $required) {
            if ([string]::IsNullOrWhiteSpace($event.Data[$name])) { throw 'INVALID_EVENT_DATA: missing required value.' }
        }
    }
    @($process, $files[0])
}

function Start-DemoChild {
    param([string]$Target, [string]$RunId)
    $directory = [IO.Path]::GetDirectoryName($Target)
    if ([IO.Directory]::Exists($directory)) { throw 'DEMO_RUN_EXISTS' }
    [void][IO.Directory]::CreateDirectory($directory)
    $literal = "'" + $Target.Replace("'", "''") + "'"
    $command = '[System.IO.File]::WriteAllText({0}, ''hello-workbench-{1}'', [System.Text.UTF8Encoding]::new($false))' -f $literal, $RunId
    $executable = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $child = Start-Process -FilePath $executable -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', ('"' + $command + '"')) -WindowStyle Hidden -PassThru -ErrorAction Stop
    # Retain the native handle so Windows PowerShell can read ExitCode after exit.
    $null = $child.Handle
    return $child
}

function Publish-DemoCollection {
    param([string]$Output, [object[]]$Pair, [string]$RunId, [string]$StartedAt)
    if (Test-Path -LiteralPath $Output) { throw 'OUTPUT_EXISTS: choose a new output directory.' }
    $parent = [IO.Path]::GetDirectoryName($Output)
    [void][IO.Directory]::CreateDirectory($parent)
    $staging = Join-Path $parent ('.sysmon-demo-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [void][IO.Directory]::CreateDirectory($staging)
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $entries = @()
        $names = @('process-create.xml', 'file-create.xml')
        if ($Pair.Count -ne 2 -or $Pair[0].EventId -ne 1 -or $Pair[1].EventId -ne 11) { throw 'INVALID_PAIR' }
        for ($index = 0; $index -lt 2; $index++) {
            $path = Join-Path $staging $names[$index]
            [IO.File]::WriteAllText($path, $Pair[$index].Xml, $encoding)
            $entries += [ordered]@{
                event_id = $Pair[$index].EventId; record_id = $Pair[$index].RecordId
                file = $names[$index]; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
        $metadata = [ordered]@{
            collector = 'sysmon-demo'; version = 1; run_id = $RunId
            collection_started_at = $StartedAt
            collection_completed_at = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            events = $entries
        }
        $metadataPath = Join-Path $staging 'collection-metadata.json'
        [IO.File]::WriteAllText($metadataPath, ($metadata | ConvertTo-Json -Depth 4), $encoding)
        $check = [IO.File]::ReadAllText($metadataPath) | ConvertFrom-Json
        foreach ($entry in $check.events) {
            $path = Join-Path $staging $entry.file
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw 'EXPORT_HASH_MISMATCH' }
        }
        # Same-parent no-replace directory move; existing/racing output is never merged.
        [IO.Directory]::Move($staging, $Output)
    } finally {
        if (Test-Path -LiteralPath $staging) {
            # Validate the resolved cleanup target and parent before recursive removal.
            $resolved = (Resolve-Path -LiteralPath $staging -ErrorAction Stop).ProviderPath
            $resolvedParent = (Resolve-Path -LiteralPath $parent -ErrorAction Stop).ProviderPath
            if ([IO.Path]::GetDirectoryName($resolved) -ne $resolvedParent -or
                [IO.Path]::GetFileName($resolved) -notlike '.sysmon-demo-*.tmp') { throw 'UNSAFE_CLEANUP_TARGET' }
            Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
        }
    }
}

function Invoke-DemoCollection {
    param([string]$Output, [string]$Root, [int]$Timeout)
    $ErrorActionPreference = 'Stop'
    if ([string]::IsNullOrWhiteSpace($Output) -or [string]::IsNullOrWhiteSpace($Root)) { throw 'INVALID_DIRECTORY' }
    $outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
    $demoPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Root)
    if ($demoPath.StartsWith('\\') -or $demoPath.Substring(2).Contains(':') -or $demoPath.Contains('"')) {
        throw 'INVALID_DEMO_ROOT: benign activity requires a local filesystem directory.'
    }
    $ancestor = $demoPath
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'INVALID_DEMO_ROOT: filesystem links are not allowed for activity.'
            }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
    if (Test-Path -LiteralPath $outputPath) { throw 'OUTPUT_EXISTS: choose a new output directory.' }
    Assert-DemoReadiness
    Write-Verbose 'Historical ID 1/11 coverage verified; current filter rules are not inferred. New pair required.'
    $latest = @(Get-DemoLogRecords -XPath '*' -MaxEvents 1)
    if ($latest.Count -ne 1) { throw 'BASELINE_UNAVAILABLE' }
    $baseline = [long]$latest[0].RecordId
    $startedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $runId = [guid]::NewGuid().ToString('N')
    $target = Join-Path (Join-Path $demoPath "run-$runId") "demo-$runId.txt"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $child = $null
    try {
        $child = Start-DemoChild -Target $target -RunId $runId
        $remaining = [Math]::Max(1, ($Timeout * 1000) - [int]$watch.ElapsedMilliseconds)
        if (-not $child.WaitForExit($remaining)) { throw 'CHILD_TIMEOUT' }
        if ($child.ExitCode -ne 0) { throw 'CHILD_FAILED' }
        while ($watch.Elapsed.TotalSeconds -lt $Timeout) {
            $records = @(Get-DemoLogRecords -XPath "*[System[(EventID=1 or EventID=11) and EventRecordID > $baseline]]")
            $events = @($records | ForEach-Object { ConvertTo-DemoEvent $_ })
            $pair = @(Select-DemoPair -Events $events -Baseline $baseline -RunId $runId -Target $target -ChildId $child.Id)
            if ($pair.Count -eq 2) {
                Publish-DemoCollection -Output $outputPath -Pair $pair -RunId $runId -StartedAt $startedAt
                Write-Output 'collection: complete (2 events)'
                return
            }
            Start-Sleep -Milliseconds 250
        }
        throw 'COLLECTION_TIMEOUT: no unambiguous correlated Event 1/11 pair; check prepared Sysmon filters.'
    } finally {
        if ($null -ne $child) {
            if (-not $child.HasExited) { $child.Kill() }
            $child.Dispose()
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-DemoCollection -Output $OutputDirectory -Root $DemoRoot -Timeout $TimeoutSeconds
        exit 0
    }
    catch {
        # Never echo raw event XML, command lines, paths or exception payloads.
        $code = 'COLLECTION_FAILED'
        if ($_.Exception.Message -match '^([A-Z_]+)(:|$)') { $code = $Matches[1] }
        Write-Error -Message "$code`: Sysmon demo collection failed; no successful collection was reported." -ErrorAction Continue
        exit 1
    }
}
