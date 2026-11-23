#requires -Version 5.1
<#
.SYNOPSIS
Validate a completed benign collection and demonstrate the existing host CLI.
.DESCRIPTION
Reads only the explicit collection. No guest execution, telemetry discovery,
policy changes or downloads. Runtime evidence stays outside the repository.
Failure preserves partial output. Console and diagnostics contain safe status only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CollectionDirectory,
    [string]$WorkbenchExecutable = (Join-Path (Split-Path $PSScriptRoot -Parent) '.venv/Scripts/workbench.exe'),
    [string]$OutputParent = [IO.Path]::GetTempPath()
)

$script:HostDemoRepository = Split-Path $PSScriptRoot -Parent
$script:HostDemoFiles = @('collection-metadata.json', 'file-create.xml', 'process-create.xml')

function Resolve-HostDemoPath {
    param([string]$Path, [bool]$Directory)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSProvider.Name -ne 'FileSystem' -or $item.PSIsContainer -ne $Directory) { throw 'INVALID_PATH' }
    $ancestor = $item
    while ($null -ne $ancestor) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'LINK_NOT_ALLOWED' }
        if ($ancestor -is [IO.DirectoryInfo]) { $ancestor = $ancestor.Parent }
        else { $ancestor = $ancestor.Directory }
    }
    return $item.FullName
}

function Test-HostDemoUnder {
    param([string]$Path, [string]$Root)
    $prefix = $Root.TrimEnd('\', '/')
    return ($Path.Equals($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($prefix + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))
}

function Get-HostDemoSnapshot {
    param([string]$Directory)
    $null = Resolve-HostDemoPath $Directory $true
    $items = @(Get-ChildItem -LiteralPath $Directory -Force -ErrorAction Stop)
    if ($items.Count -ne 3) { throw 'COLLECTION_LAYOUT_INVALID' }
    $result = @{}
    foreach ($name in $script:HostDemoFiles) {
        $matches = @($items | Where-Object { $_.Name -ceq $name })
        if ($matches.Count -ne 1 -or $matches[0].PSIsContainer) { throw 'COLLECTION_LAYOUT_INVALID' }
        $item = $matches[0]
        $null = Resolve-HostDemoPath $item.FullName $false
        if ($item.Length -le 0 -or $item.Length -gt 4MB) { throw 'COLLECTION_SIZE_INVALID' }
        $result[$name] = [pscustomobject]@{
            Hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            Size = $item.Length; Modified = $item.LastWriteTimeUtc.Ticks
        }
    }
    return $result
}

function Copy-HostDemoFile {
    param([string]$Source, [string]$Destination)
    $reader = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $writer = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $reader.CopyTo($writer) } finally { $writer.Dispose() }
    } finally { $reader.Dispose() }
}

function Write-HostDemoNewText {
    param([string]$Path, [string]$Text)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}

function Read-HostDemoUtc {
    param([string]$Value)
    $time = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($Value, 'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$time)) {
        throw 'METADATA_INVALID'
    }
    return $time
}

function Read-HostDemoEvent {
    param([string]$Path)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 4MB
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
    } finally { $reader.Dispose() }
    $ns = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    foreach ($xpath in @('/e:Event', '/e:Event/e:System', '/e:Event/e:EventData',
        '/e:Event/e:System/e:Provider', '/e:Event/e:System/e:EventID', '/e:Event/e:System/e:EventRecordID')) {
        if ($document.SelectNodes($xpath, $ns).Count -ne 1) { throw 'XML_INVALID' }
    }
    if ($document.SelectSingleNode('/e:Event/e:System/e:Provider', $ns).GetAttribute('Name') -cne 'Microsoft-Windows-Sysmon') {
        throw 'XML_INVALID'
    }
    $eventId = 0
    $recordId = [long]0
    if (-not [int]::TryParse($document.SelectSingleNode('/e:Event/e:System/e:EventID', $ns).InnerText, [ref]$eventId) -or
        $eventId -notin @(1, 11) -or
        -not [long]::TryParse($document.SelectSingleNode('/e:Event/e:System/e:EventRecordID', $ns).InnerText, [ref]$recordId) -or
        $recordId -le 0) { throw 'XML_INVALID' }
    $data = @{}
    foreach ($node in $document.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $name = $node.GetAttribute('Name')
        if (-not $name -or $data.ContainsKey($name)) { throw 'XML_INVALID' }
        $data[$name] = $node.InnerText
    }
    $required = @('UtcTime', 'ProcessGuid', 'ProcessId', 'Image')
    if ($eventId -eq 1) { $required += 'CommandLine' }
    else { $required += @('TargetFilename', 'CreationUtcTime') }
    foreach ($name in $required) {
        if ([string]::IsNullOrWhiteSpace($data[$name])) { throw 'XML_INVALID' }
    }
    $guid = [guid]::Empty
    $processId = [long]0
    if (-not [guid]::TryParse($data.ProcessGuid, [ref]$guid) -or $guid -eq [guid]::Empty -or
        -not [long]::TryParse($data.ProcessId, [ref]$processId) -or $processId -le 0) { throw 'XML_INVALID' }
    return [pscustomobject]@{ EventId = $eventId; RecordId = $recordId; Guid = $guid; ProcessId = $processId }
}

function Assert-HostDemoCollection {
    param([string]$Directory, [hashtable]$Snapshot)
    $raw = [IO.File]::ReadAllText((Join-Path $Directory 'collection-metadata.json'), [Text.UTF8Encoding]::new($false, $true))
    if (-not $raw.TrimStart().StartsWith('{')) { throw 'METADATA_INVALID' }
    $metadata = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    # Count decoded property names too: ConvertFrom-Json alone can hide duplicate keys.
    $keys = @([regex]::Matches($raw, '"(?:[^"\\]|\\.)*"\s*:') | ForEach-Object {
        $quoted = $_.Value.Substring(0, $_.Value.LastIndexOf(':')).Trim()
        (ConvertFrom-Json -InputObject ('{"key":' + $quoted + '}')).key
    })
    $counts = @{ collector = 1; version = 1; run_id = 1; collection_started_at = 1;
        collection_completed_at = 1; events = 1; event_id = 2; record_id = 2; file = 2; sha256 = 2 }
    if ($keys.Count -ne 14) { throw 'METADATA_INVALID' }
    foreach ($key in $counts.Keys) {
        if (@($keys | Where-Object { $_ -ceq $key }).Count -ne $counts[$key]) { throw 'METADATA_INVALID' }
    }
    if (@($metadata.PSObject.Properties).Count -ne 6 -or
        $metadata.collector -cne 'sysmon-demo' -or $metadata.version -isnot [int] -or $metadata.version -ne 1 -or
        $metadata.run_id -isnot [string] -or $metadata.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        $metadata.events -isnot [array] -or $metadata.events.Count -ne 2) { throw 'METADATA_INVALID' }
    $started = Read-HostDemoUtc $metadata.collection_started_at
    $completed = Read-HostDemoUtc $metadata.collection_completed_at
    if ($completed -lt $started) { throw 'METADATA_INVALID' }
    $names = @('process-create.xml', 'file-create.xml')
    $ids = @(1, 11)
    $pair = @()
    for ($index = 0; $index -lt 2; $index++) {
        $entry = $metadata.events[$index]
        if (@($entry.PSObject.Properties).Count -ne 4 -or $entry.file -cne $names[$index] -or
            $entry.event_id -isnot [int] -or $entry.event_id -ne $ids[$index] -or
            ($entry.record_id -isnot [int] -and $entry.record_id -isnot [long]) -or $entry.record_id -le 0 -or
            $entry.sha256 -isnot [string] -or $entry.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'METADATA_INVALID' }
        if ($Snapshot[$names[$index]].Hash -ne $entry.sha256) { throw 'HASH_MISMATCH' }
        $event = Read-HostDemoEvent (Join-Path $Directory $names[$index])
        if ($event.EventId -ne $ids[$index] -or $event.RecordId -ne $entry.record_id) { throw 'EVENT_IDENTITY_MISMATCH' }
        $pair += $event
    }
    if ($pair[0].Guid -ne $pair[1].Guid -or $pair[0].ProcessId -ne $pair[1].ProcessId -or
        $pair[0].RecordId -ge $pair[1].RecordId) { throw 'EVENT_CORRELATION_INVALID' }
    return ,$pair
}

function Invoke-HostDemoCli {
    param([string]$Executable, [string[]]$Arguments)
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        # Windows PowerShell 5.1 writes native exit codes to the global automatic
        # variable. A local sentinel would shadow the value and stay null.
        $global:LASTEXITCODE = $null
        $invoked = $false
        $lines = @(
            & $Executable @Arguments 2>&1
            # Capture immediately: the surrounding array assignment resets $?.
            $invoked = $?
        )
        $code = $global:LASTEXITCODE
        return [pscustomobject]@{ Invoked = $invoked; ExitCode = $code; Lines = @($lines | ForEach-Object { $_.ToString() }) }
    } finally { $ErrorActionPreference = $saved }
}

function Invoke-HostDemoChecked {
    param([string]$Executable, [string[]]$Arguments)
    $result = Invoke-HostDemoCli $Executable $Arguments
    if (-not $result.Invoked -or $null -eq $result.ExitCode -or $result.ExitCode -ne 0) {
        $failure = [InvalidOperationException]::new('CLI_FAILED')
        if ($result.ExitCode -is [int]) { $failure.Data['CliExit'] = $result.ExitCode }
        throw $failure
    }
    return ($result.Lines -join "`n")
}

function Get-HostDemoField {
    param([string]$Text, [string]$Name)
    $found = [regex]::Matches($Text, ('(?m)^' + [regex]::Escape($Name) + ':\s*([^\r\n]+)\r?$'))
    if ($found.Count -ne 1) { throw 'CLI_OUTPUT_INVALID' }
    return $found[0].Groups[1].Value.Trim()
}

function New-HostDemoRunName { return ('workbench-host-demo-' + [guid]::NewGuid().ToString('N')) }

function Invoke-SysmonHostDemo {
    param([string]$Collection, [string]$Executable, [string]$Parent)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $stage = 'preflight'
    $run = $null
    $runName = $null
    $locks = @()
    $status = 'failed'
    $code = 'HOST_DEMO_FAILED'
    $cliExit = $null
    try {
        $source = Resolve-HostDemoPath $Collection $true
        $parentPath = Resolve-HostDemoPath $Parent $true
        # The explicitly selected installed executable may be in a cloud-backed
        # repository. The no-reparse restriction applies to runtime data paths.
        $executableItem = Get-Item -LiteralPath $Executable -Force -ErrorAction Stop
        if ($executableItem.PSProvider.Name -ne 'FileSystem' -or $executableItem.PSIsContainer -or
            $executableItem.Extension -ine '.exe') { throw 'INVALID_PATH' }
        $executablePath = $executableItem.FullName
        $repo = [IO.Path]::GetFullPath($script:HostDemoRepository)
        if ($parentPath.StartsWith('\\') -or (Test-HostDemoUnder $parentPath $repo) -or
            (Test-HostDemoUnder $parentPath $source)) { throw 'OUTPUT_LOCATION_INVALID' }
        $before = Get-HostDemoSnapshot $source
        $runName = New-HostDemoRunName
        if ($runName -cnotmatch '^workbench-host-demo-[0-9a-f]{32}$') { throw 'OUTPUT_LOCATION_INVALID' }
        $candidate = Join-Path $parentPath $runName
        # New-Item without Force refuses an existing directory, including collisions.
        $null = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop
        $run = $candidate
        $stage = 'copy'
        $copy = Join-Path $run 'collection'
        $null = New-Item -ItemType Directory -Path $copy
        foreach ($name in $script:HostDemoFiles) { Copy-HostDemoFile (Join-Path $source $name) (Join-Path $copy $name) }
        $after = Get-HostDemoSnapshot $source
        foreach ($name in $script:HostDemoFiles) {
            if ($before[$name].Hash -ne $after[$name].Hash -or $before[$name].Size -ne $after[$name].Size -or
                $before[$name].Modified -ne $after[$name].Modified) { throw 'INPUT_CHANGED' }
            $locks += [IO.File]::Open((Join-Path $copy $name), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        }
        $snapshot = Get-HostDemoSnapshot $copy
        foreach ($name in $script:HostDemoFiles) {
            if ($before[$name].Hash -ne $snapshot[$name].Hash -or $before[$name].Size -ne $snapshot[$name].Size) { throw 'INPUT_CHANGED' }
        }
        $stage = 'validate'
        $pair = Assert-HostDemoCollection $copy $snapshot
        $stage = 'project'
        $project = Join-Path $run 'project'
        $text = Invoke-HostDemoChecked $executablePath @('project', 'create', $project, '--name', 'VM Sysmon Demo')
        $projectId = Get-HostDemoField $text 'display_id'
        if ($projectId -cnotmatch '^PRJ-[0-9]{4,}$' -or $projectId -match '^PRJ-0+$') { throw 'CLI_OUTPUT_INVALID' }
        $null = Resolve-HostDemoPath $project $true
        Push-Location -LiteralPath $project
        try {
            $stage = 'case'
            $text = Invoke-HostDemoChecked $executablePath @('case', 'create', '--name', 'Benign Sysmon Demo', '--kind', 'benign')
            $caseId = Get-HostDemoField $text 'display_id'
            if ($caseId -cnotmatch '^CASE-[0-9]{4,}$' -or $caseId -match '^CASE-0+$' -or
                (Get-HostDemoField $text 'kind') -cne 'benign') { throw 'CLI_OUTPUT_INVALID' }
            $artifactIds = @()
            $names = @('process-create.xml', 'file-create.xml')
            for ($index = 0; $index -lt 2; $index++) {
                $stage = 'artifact-' + ($index + 1)
                $text = Invoke-HostDemoChecked $executablePath @('case', 'artifact', 'add', $caseId, (Join-Path $copy $names[$index]), '--kind', 'sysmon')
                $rows = @($text -split '\r?\n' | Where-Object { $_ -match '^ART-' })
                if ($rows.Count -ne 1) { throw 'CLI_OUTPUT_INVALID' }
                $fields = $rows[0] -split "`t"
                if ($fields.Count -ne 5 -or $fields[0] -cnotmatch '^ART-[0-9]{6,}$' -or $fields[0] -match '^ART-0+$' -or $fields[1] -cne 'sysmon' -or
                    $fields[2] -ne $snapshot[$names[$index]].Hash -or $fields[3] -cne [string]$snapshot[$names[$index]].Size -or
                    $artifactIds -contains $fields[0]) { throw 'CLI_OUTPUT_INVALID' }
                $artifactIds += $fields[0]
            }
            $stage = 'timeline'
            $timeline = Invoke-HostDemoChecked $executablePath @('case', 'timeline', $caseId)
            if ((Get-HostDemoField $timeline 'case') -cne $caseId -or
                (Get-HostDemoField $timeline 'sysmon_artifacts') -cne '2' -or
                (Get-HostDemoField $timeline 'observations') -cne '2') { throw 'CLI_OUTPUT_INVALID' }
            $events = [regex]::Matches($timeline, '(?m)^\S+\s+EventID=(\d+)\s+(process_create|file_create)\r?\n(?<body>(?:[ \t]+[^\r\n]*\r?\n?)*)')
            if ($events.Count -ne 2 -or [regex]::Matches($timeline, '(?m)^\S+\s+EventID=').Count -ne 2) { throw 'CLI_OUTPUT_INVALID' }
            for ($index = 0; $index -lt 2; $index++) {
                if ($events[$index].Groups[1].Value -ne [string]$pair[$index].EventId -or
                    $events[$index].Groups[2].Value -cne @('process_create', 'file_create')[$index]) { throw 'CLI_OUTPUT_INVALID' }
                $provenance = $artifactIds[$index] + '#' + $pair[$index].RecordId
                $body = ($events[$index].Groups['body'].Value -split '\r?\n' | ForEach-Object { $_.TrimStart() }) -join "`n"
                if ((Get-HostDemoField $body 'source') -cne $provenance -or
                    (Get-HostDemoField $body 'pid') -cne [string]$pair[$index].ProcessId) { throw 'CLI_OUTPUT_INVALID' }
            }
            Write-HostDemoNewText (Join-Path $run 'timeline.txt') $timeline
            $stage = 'report'
            $report = Join-Path $project 'vm-demo.md'
            if (Test-Path -LiteralPath $report) { throw 'REPORT_OUTPUT_EXISTS' }
            $text = Invoke-HostDemoChecked $executablePath @('report', 'build', $caseId, 'vm-demo.md')
            if ((Get-HostDemoField $text 'report') -cne 'created') { throw 'CLI_OUTPUT_INVALID' }
            $null = Resolve-HostDemoPath $report $false
            $markdown = [IO.File]::ReadAllText($report, [Text.UTF8Encoding]::new($false, $true))
            foreach ($heading in @('Case Overview', 'Evidence Summary', 'Timeline', 'Collection / Analysis Limits')) {
                if ([regex]::Matches($markdown, ('(?m)^## ' + [regex]::Escape($heading) + '\r?$')).Count -ne 1) { throw 'REPORT_INVALID' }
            }
            $summary = $markdown -replace '(?m)^- ', ''
            if ((Get-HostDemoField $summary 'Case ID') -cne $caseId -or
                (Get-HostDemoField $summary 'Normalized Observations') -cne '2' -or
                (Get-HostDemoField $summary 'Sysmon Artifacts') -cne '2') { throw 'REPORT_INVALID' }
            $sections = [regex]::Matches($markdown, '(?ms)^### [^\r\n]+\r?\n(?<body>.*?)(?=^#{1,3} |\z)')
            if ($sections.Count -ne 2) { throw 'REPORT_INVALID' }
            for ($index = 0; $index -lt 2; $index++) {
                $body = $sections[$index].Groups['body'].Value -replace '(?m)^- ', ''
                if ((Get-HostDemoField $body 'Event ID') -cne [string]$pair[$index].EventId -or
                    (Get-HostDemoField $body 'Process ID') -cne [string]$pair[$index].ProcessId -or
                    (Get-HostDemoField $body 'Source Artifact') -cne $artifactIds[$index] -or
                    (Get-HostDemoField $body 'Source Record') -cne [string]$pair[$index].RecordId) { throw 'REPORT_INVALID' }
            }
        } finally { Pop-Location }
        $status = 'success'; $stage = 'complete'; $code = 'OK'
    } catch {
        # Allowlisted codes only. Never serialize exceptions or captured CLI output.
        $safe = @('INVALID_PATH', 'LINK_NOT_ALLOWED', 'COLLECTION_LAYOUT_INVALID', 'COLLECTION_SIZE_INVALID',
            'OUTPUT_LOCATION_INVALID', 'INPUT_CHANGED', 'METADATA_INVALID', 'XML_INVALID', 'HASH_MISMATCH',
            'EVENT_IDENTITY_MISMATCH', 'EVENT_CORRELATION_INVALID', 'CLI_FAILED', 'CLI_OUTPUT_INVALID',
            'REPORT_OUTPUT_EXISTS', 'REPORT_INVALID')
        if ($safe -ccontains $_.Exception.Message) { $code = $_.Exception.Message }
        if ($_.Exception.Data['CliExit'] -is [int]) { $cliExit = $_.Exception.Data['CliExit'] }
    } finally {
        foreach ($handle in $locks) { $handle.Dispose() }
    }
    $result = [ordered]@{ status = $status; stage = $stage; code = $code; cli_exit = $cliExit; run = $runName; diagnostic = 'not_created' }
    if ($null -ne $run) {
        try {
            $result.diagnostic = 'written'
            Write-HostDemoNewText (Join-Path $run 'diagnostic.json') ($result | ConvertTo-Json)
        } catch {
            $result.diagnostic = 'failed'
            if ($result.status -eq 'success') {
                $result.status = 'failed'; $result.stage = 'diagnostic'; $result.code = 'DIAGNOSTIC_WRITE_FAILED'
            }
        }
    }
    return [pscustomobject]$result
}

if ($MyInvocation.InvocationName -ne '.') {
    $result = Invoke-SysmonHostDemo $CollectionDirectory $WorkbenchExecutable $OutputParent
    Write-Output ($result | ConvertTo-Json -Compress)
    if ($result.status -eq 'success') { exit 0 }
    exit 1
}
