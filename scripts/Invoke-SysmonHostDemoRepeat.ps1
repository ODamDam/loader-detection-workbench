#requires -Version 5.1
<#
.SYNOPSIS
Repeat the existing benign Host Sysmon demo and validate reproducibility.
.DESCRIPTION
Uses only an explicit completed collection. Each iteration runs the existing
Host demo in an independent Windows PowerShell process and a unique output
directory. Runtime evidence remains outside the repository. Failures stop later
iterations and preserve every completed or partial output. Console and batch
diagnostics contain safe status only.
#>
[CmdletBinding()]
param(
    [string]$CollectionDirectory,
    [string]$WorkbenchExecutable,
    [string]$OutputParent,
    [int]$Iterations = 2
)

$script:RepeatInvocationName = $MyInvocation.InvocationName
$script:RepeatInitializationCode = $null
$script:RepeatScriptRoot = [string]$PSScriptRoot
$savedCollectionDirectory = $CollectionDirectory
$savedWorkbenchExecutable = $WorkbenchExecutable
$savedOutputParent = $OutputParent
$savedErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Stop'
    if ([string]::IsNullOrWhiteSpace($script:RepeatScriptRoot)) { throw 'SCRIPT_CONTEXT_INVALID' }
    $rootItem = Get-Item -LiteralPath $script:RepeatScriptRoot -Force -ErrorAction Stop
    if ($rootItem.PSProvider.Name -ne 'FileSystem' -or -not $rootItem.PSIsContainer -or
        $null -eq $rootItem.Parent) { throw 'SCRIPT_CONTEXT_INVALID' }
    $script:RepeatRepository = $rootItem.Parent.FullName
    $script:RepeatHostScript = Join-Path $rootItem.FullName 'Invoke-SysmonHostDemo.ps1'
    $hostItem = Get-Item -LiteralPath $script:RepeatHostScript -Force -ErrorAction Stop
    if ($hostItem.PSProvider.Name -ne 'FileSystem' -or $hostItem.PSIsContainer) {
        throw 'SCRIPT_CONTEXT_INVALID'
    }
    # Explicit arguments prevent the imported script's default expressions from
    # depending on caller scope. Restore this script's parameters after import.
    . $script:RepeatHostScript -CollectionDirectory 'unused' `
        -WorkbenchExecutable 'unused.exe' -OutputParent ([IO.Path]::GetTempPath())
} catch {
    if ($_.Exception.Message -ceq 'SCRIPT_CONTEXT_INVALID') {
        $script:RepeatInitializationCode = 'SCRIPT_CONTEXT_INVALID'
    } else {
        $script:RepeatInitializationCode = 'SCRIPT_INITIALIZATION_FAILED'
    }
} finally {
    $CollectionDirectory = $savedCollectionDirectory
    $WorkbenchExecutable = $savedWorkbenchExecutable
    $OutputParent = $savedOutputParent
    $ErrorActionPreference = $savedErrorActionPreference
}

function Get-HostDemoRepeatDigest {
    param([string]$Text)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($Text))
        return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Test-HostDemoRepeatSnapshot {
    param([hashtable]$Expected, [hashtable]$Actual, [bool]$IncludeModified)
    foreach ($name in $script:HostDemoFiles) {
        if (-not $Expected.ContainsKey($name) -or -not $Actual.ContainsKey($name) -or
            $Expected[$name].Hash -ne $Actual[$name].Hash -or
            $Expected[$name].Size -ne $Actual[$name].Size -or
            ($IncludeModified -and $Expected[$name].Modified -ne $Actual[$name].Modified)) {
            return $false
        }
    }
    return $true
}

function Invoke-HostDemoRepeatChild {
    param(
        [string]$PowerShellExecutable,
        [string]$Collection,
        [string]$Executable,
        [string]$Parent
    )
    $global:LASTEXITCODE = $null
    $invoked = $false
    $lines = @(
        & $PowerShellExecutable -NoProfile -NonInteractive -File $script:RepeatHostScript `
            -CollectionDirectory $Collection -WorkbenchExecutable $Executable -OutputParent $Parent 2>&1
        $invoked = $?
    )
    $exitCode = $global:LASTEXITCODE
    $text = @($lines | ForEach-Object { $_.ToString() }) -join "`n"
    try { $result = ConvertFrom-Json -InputObject $text -ErrorAction Stop }
    catch { throw 'CHILD_RESULT_INVALID' }
    $child = [pscustomobject]@{
        Invoked = $invoked
        ExitCode = $exitCode
        Result = $result
    }
    Assert-HostDemoRepeatChildResult $child
    return $child
}

function Assert-HostDemoRepeatChildResult {
    param([object]$Child)
    if ($null -eq $Child -or
        @(Compare-Object @($Child.PSObject.Properties.Name) @('Invoked', 'ExitCode', 'Result')).Count -ne 0 -or
        $Child.Invoked -isnot [bool] -or $null -eq $Child.ExitCode -or
        $Child.ExitCode -isnot [int] -or $null -eq $Child.Result) {
        throw 'CHILD_RESULT_INVALID'
    }
    $result = $Child.Result
    $expected = @('status', 'stage', 'code', 'cli_exit', 'run', 'diagnostic')
    if (@(Compare-Object @($result.PSObject.Properties.Name) $expected).Count -ne 0 -or
        $result.status -notin @('success', 'failed') -or
        $result.stage -isnot [string] -or $result.stage -cnotmatch '^[a-z0-9-]+$' -or
        $result.code -isnot [string] -or $result.code -cnotmatch '^[A-Z0-9_]+$' -or
        $result.diagnostic -notin @('written', 'failed', 'not_created') -or
        ($null -ne $result.cli_exit -and $result.cli_exit -isnot [int])) {
        throw 'CHILD_RESULT_INVALID'
    }
}

function Invoke-HostDemoRepeatCli {
    param([string]$Executable, [string[]]$Arguments)
    $result = Invoke-HostDemoCli $Executable $Arguments
    if (-not $result.Invoked -or $null -eq $result.ExitCode -or $result.ExitCode -ne 0) {
        $failure = [InvalidOperationException]::new('CLI_FAILED')
        if ($result.ExitCode -is [int]) { $failure.Data['CliExit'] = $result.ExitCode }
        throw $failure
    }
    return ($result.Lines -join "`n")
}

function ConvertTo-HostDemoRepeatTimeline {
    param(
        [string]$Timeline,
        [string]$CaseId,
        [string[]]$ArtifactIds
    )
    $canonical = $Timeline.Replace("`r`n", "`n").Replace($CaseId, '<CASE>')
    for ($index = 0; $index -lt 2; $index++) {
        $canonical = $canonical.Replace($ArtifactIds[$index], @('<PROCESS_ARTIFACT>', '<FILE_ARTIFACT>')[$index])
    }
    return $canonical.TrimEnd([char[]]@([char]10, [char]13))
}

function ConvertTo-HostDemoRepeatReport {
    param(
        [string]$Report,
        [string]$CaseId,
        [string[]]$ArtifactIds
    )
    $generated = [regex]::Matches($Report, '(?m)^- Generated At: [^\r\n]+\r?$')
    if ($generated.Count -ne 1) { throw 'REPORT_INVALID' }
    $canonical = [regex]::Replace(
        $Report,
        '(?m)^- Generated At: [^\r\n]+\r?$',
        '- Generated At: <GENERATED_AT>'
    ).Replace("`r`n", "`n").Replace($CaseId, '<CASE>')
    for ($index = 0; $index -lt 2; $index++) {
        $canonical = $canonical.Replace($ArtifactIds[$index], @('<PROCESS_ARTIFACT>', '<FILE_ARTIFACT>')[$index])
    }
    return $canonical.TrimEnd([char[]]@([char]10, [char]13))
}

function Test-HostDemoRepeatRun {
    param(
        [string]$RunDirectory,
        [string]$Executable,
        [hashtable]$SourceSnapshot
    )
    $copy = Join-Path $RunDirectory 'collection'
    $copySnapshot = Get-HostDemoSnapshot $copy
    if (-not (Test-HostDemoRepeatSnapshot $SourceSnapshot $copySnapshot $false)) { throw 'COPY_MISMATCH' }
    $pair = Assert-HostDemoCollection $copy $copySnapshot

    $project = Join-Path $RunDirectory 'project'
    $null = Resolve-HostDemoPath $project $true
    $validation = Invoke-HostDemoRepeatCli $Executable @('project', 'validate', $project, '--full')
    if ($validation.Trim() -cne 'valid') { throw 'PROJECT_VALIDATION_FAILED' }

    $timelinePath = Join-Path $RunDirectory 'timeline.txt'
    $null = Resolve-HostDemoPath $timelinePath $false
    $storedTimeline = [IO.File]::ReadAllText($timelinePath, [Text.UTF8Encoding]::new($false, $true))
    $caseId = Get-HostDemoField $storedTimeline 'case'
    if ($caseId -cnotmatch '^CASE-[0-9]{4,}$' -or $caseId -match '^CASE-0+$') { throw 'TIMELINE_INVALID' }

    Push-Location -LiteralPath $project
    try {
        $freshTimeline = Invoke-HostDemoRepeatCli $Executable @('case', 'timeline', $caseId)
        $artifactText = Invoke-HostDemoRepeatCli $Executable @('case', 'artifact', 'list', $caseId)
    } finally { Pop-Location }
    if ($storedTimeline.Replace("`r`n", "`n") -cne $freshTimeline.Replace("`r`n", "`n")) {
        throw 'TIMELINE_REPEAT_MISMATCH'
    }
    if ((Get-HostDemoField $storedTimeline 'sysmon_artifacts') -cne '2' -or
        (Get-HostDemoField $storedTimeline 'observations') -cne '2') { throw 'TIMELINE_INVALID' }

    $artifactRows = @($artifactText -split '\r?\n' | Where-Object { $_ -ne '' })
    if ($artifactRows.Count -ne 2) { throw 'ARTIFACT_VALIDATION_FAILED' }
    $artifactMap = @{}
    foreach ($row in $artifactRows) {
        $fields = $row -split "`t"
        if ($fields.Count -ne 5 -or $fields[0] -cnotmatch '^ART-[0-9]{6,}$' -or
            $fields[1] -cne 'sysmon' -or $artifactMap.ContainsKey($fields[0])) {
            throw 'ARTIFACT_VALIDATION_FAILED'
        }
        $artifactMap[$fields[0]] = [pscustomobject]@{ Hash = $fields[2]; Size = $fields[3] }
    }

    $events = [regex]::Matches($storedTimeline, '(?m)^\S+\s+EventID=(\d+)\s+(process_create|file_create)\r?\n(?<body>(?:[ \t]+[^\r\n]*\r?\n?)*)')
    if ($events.Count -ne 2 -or [regex]::Matches($storedTimeline, '(?m)^\S+\s+EventID=').Count -ne 2) {
        throw 'TIMELINE_INVALID'
    }
    $names = @('process-create.xml', 'file-create.xml')
    $artifactIds = @()
    for ($index = 0; $index -lt 2; $index++) {
        if ($events[$index].Groups[1].Value -ne [string]$pair[$index].EventId -or
            $events[$index].Groups[2].Value -cne @('process_create', 'file_create')[$index]) {
            throw 'TIMELINE_INVALID'
        }
        $body = ($events[$index].Groups['body'].Value -split '\r?\n' | ForEach-Object { $_.TrimStart() }) -join "`n"
        $source = Get-HostDemoField $body 'source'
        $match = [regex]::Match($source, '^(ART-[0-9]{6,})#([0-9]+)$')
        if (-not $match.Success -or $match.Groups[2].Value -ne [string]$pair[$index].RecordId -or
            (Get-HostDemoField $body 'pid') -ne [string]$pair[$index].ProcessId) {
            throw 'PROVENANCE_INVALID'
        }
        $artifactId = $match.Groups[1].Value
        if (-not $artifactMap.ContainsKey($artifactId) -or $artifactIds -contains $artifactId -or
            $artifactMap[$artifactId].Hash -ne $copySnapshot[$names[$index]].Hash -or
            $artifactMap[$artifactId].Size -cne [string]$copySnapshot[$names[$index]].Size) {
            throw 'ARTIFACT_VALIDATION_FAILED'
        }
        $artifactIds += $artifactId
    }

    $reports = @(Get-ChildItem -LiteralPath $project -File -Force -Filter '*.md')
    if ($reports.Count -ne 1 -or $reports[0].Name -cne 'vm-demo.md') { throw 'REPORT_INVALID' }
    $report = [IO.File]::ReadAllText($reports[0].FullName, [Text.UTF8Encoding]::new($false, $true))
    foreach ($heading in @('Case Overview', 'Evidence Summary', 'Timeline', 'Collection / Analysis Limits')) {
        if ([regex]::Matches($report, ('(?m)^## ' + [regex]::Escape($heading) + '\r?$')).Count -ne 1) {
            throw 'REPORT_INVALID'
        }
    }
    $summary = $report -replace '(?m)^- ', ''
    if ((Get-HostDemoField $summary 'Case ID') -cne $caseId -or
        (Get-HostDemoField $summary 'Normalized Observations') -cne '2' -or
        (Get-HostDemoField $summary 'Sysmon Artifacts') -cne '2') { throw 'REPORT_INVALID' }
    $sections = [regex]::Matches($report, '(?ms)^### [^\r\n]+\r?\n(?<body>.*?)(?=^#{1,3} |\z)')
    if ($sections.Count -ne 2) { throw 'REPORT_INVALID' }
    for ($index = 0; $index -lt 2; $index++) {
        $body = $sections[$index].Groups['body'].Value -replace '(?m)^- ', ''
        if ((Get-HostDemoField $body 'Event ID') -cne [string]$pair[$index].EventId -or
            (Get-HostDemoField $body 'Process ID') -cne [string]$pair[$index].ProcessId -or
            (Get-HostDemoField $body 'Source Artifact') -cne $artifactIds[$index] -or
            (Get-HostDemoField $body 'Source Record') -cne [string]$pair[$index].RecordId) {
            throw 'REPORT_INVALID'
        }
    }

    $timelineCanonical = ConvertTo-HostDemoRepeatTimeline $storedTimeline $caseId $artifactIds
    $reportCanonical = ConvertTo-HostDemoRepeatReport $report $caseId $artifactIds
    return [pscustomobject]@{
        TimelineDigest = Get-HostDemoRepeatDigest $timelineCanonical
        ReportDigest = Get-HostDemoRepeatDigest $reportCanonical
    }
}

function New-HostDemoRepeatName { return ('workbench-host-repeat-' + [guid]::NewGuid().ToString('N')) }

function Invoke-SysmonHostDemoRepeat {
    param([string]$Collection, [string]$Executable, [string]$Parent, [int]$Count)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $stage = 'preflight'
    $status = 'failed'
    $code = 'HOST_REPEAT_FAILED'
    $cliExit = $null
    $batch = $null
    $batchName = $null
    $failedIteration = $null
    $completed = 0
    $sourceSnapshot = $null
    $sourceUnchanged = $false
    $copiesMatch = $false
    $artifactsValid = $false
    $projectsValid = $false
    $timelinesConsistent = $false
    $reportsConsistent = $false
    $innerStage = $null
    $innerCode = $null
    $runNames = @()
    try {
        if ($null -ne $script:RepeatInitializationCode) { throw $script:RepeatInitializationCode }
        if ($Count -lt 2 -or $Count -gt 10) { throw 'ITERATION_COUNT_INVALID' }
        if ([string]::IsNullOrWhiteSpace($Collection)) { throw 'PATH_ARGUMENT_INVALID' }
        if ([string]::IsNullOrWhiteSpace($Executable)) {
            $Executable = Join-Path $script:RepeatRepository '.venv/Scripts/workbench.exe'
        }
        if ([string]::IsNullOrWhiteSpace($Parent)) { $Parent = [IO.Path]::GetTempPath() }
        if ([string]::IsNullOrWhiteSpace($Executable) -or [string]::IsNullOrWhiteSpace($Parent)) {
            throw 'PATH_ARGUMENT_INVALID'
        }
        $source = Resolve-HostDemoPath $Collection $true
        $parentPath = Resolve-HostDemoPath $Parent $true
        $executableItem = Get-Item -LiteralPath $Executable -Force -ErrorAction Stop
        if ($executableItem.PSProvider.Name -ne 'FileSystem' -or $executableItem.PSIsContainer -or
            $executableItem.Extension -ine '.exe') { throw 'INVALID_PATH' }
        $executablePath = $executableItem.FullName
        $repo = [IO.Path]::GetFullPath($script:HostDemoRepository)
        if ($parentPath.StartsWith('\\') -or (Test-HostDemoUnder $parentPath $repo) -or
            (Test-HostDemoUnder $parentPath $source)) { throw 'OUTPUT_LOCATION_INVALID' }
        $powerShell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        $null = Get-Item -LiteralPath $powerShell -ErrorAction Stop
        $sourceSnapshot = Get-HostDemoSnapshot $source
        $null = Assert-HostDemoCollection $source $sourceSnapshot

        $batchName = New-HostDemoRepeatName
        if ($batchName -cnotmatch '^workbench-host-repeat-[0-9a-f]{32}$') { throw 'OUTPUT_LOCATION_INVALID' }
        $candidate = Join-Path $parentPath $batchName
        if (Test-Path -LiteralPath $candidate) { throw 'OUTPUT_LOCATION_INVALID' }
        $null = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop
        $batch = $candidate
        $seenRuns = @{}
        $expectedTimeline = $null
        $expectedReport = $null
        for ($iteration = 1; $iteration -le $Count; $iteration++) {
            $failedIteration = $iteration
            $stage = 'iteration-' + $iteration + '-run'
            # Keep each Host run at the same path depth as a direct invocation.
            # Nesting the already-long run name under the batch directory can
            # exceed legacy Windows path limits in the Artifact Store.
            $child = Invoke-HostDemoRepeatChild $powerShell $source $executablePath $parentPath
            Assert-HostDemoRepeatChildResult $child
            $innerStage = [string]$child.Result.stage
            $innerCode = [string]$child.Result.code
            if (-not $child.Invoked -or $child.ExitCode -ne 0 -or
                $child.Result.status -cne 'success' -or $child.Result.stage -cne 'complete' -or
                $child.Result.code -cne 'OK' -or $child.Result.diagnostic -cne 'written') {
                if ($child.Result.cli_exit -is [int]) { $cliExit = $child.Result.cli_exit }
                elseif ($child.ExitCode -is [int]) { $cliExit = $child.ExitCode }
                throw 'HOST_RUN_FAILED'
            }
            $runName = [string]$child.Result.run
            if ($runName -cnotmatch '^workbench-host-demo-[0-9a-f]{32}$' -or $seenRuns.ContainsKey($runName)) {
                throw 'RUN_ID_INVALID'
            }
            $seenRuns[$runName] = $true
            $runNames += $runName
            $runPath = Resolve-HostDemoPath (Join-Path $parentPath $runName) $true
            if (-not (Test-HostDemoUnder $runPath $parentPath)) { throw 'OUTPUT_LOCATION_INVALID' }

            $stage = 'iteration-' + $iteration + '-validate'
            try { $verified = Test-HostDemoRepeatRun $runPath $executablePath $sourceSnapshot }
            catch {
                throw
            }
            $iterationSource = Get-HostDemoSnapshot $source
            if (-not (Test-HostDemoRepeatSnapshot $sourceSnapshot $iterationSource $true)) {
                throw 'INPUT_CHANGED'
            }
            if ($null -eq $expectedTimeline) {
                $expectedTimeline = $verified.TimelineDigest
                $expectedReport = $verified.ReportDigest
            } else {
                if ($verified.TimelineDigest -cne $expectedTimeline) {
                    throw 'TIMELINE_SEMANTIC_MISMATCH'
                }
                if ($verified.ReportDigest -cne $expectedReport) {
                    throw 'REPORT_SEMANTIC_MISMATCH'
                }
            }
            $completed++
            $failedIteration = $null
        }
        $copiesMatch = $true
        $artifactsValid = $true
        $projectsValid = $true
        $timelinesConsistent = $true
        $reportsConsistent = $true
        $status = 'success'
        $stage = 'complete'
        $code = 'OK'
    } catch {
        $safe = @('SCRIPT_CONTEXT_INVALID', 'SCRIPT_INITIALIZATION_FAILED', 'PATH_ARGUMENT_INVALID',
            'INVALID_PATH', 'LINK_NOT_ALLOWED', 'COLLECTION_LAYOUT_INVALID', 'COLLECTION_SIZE_INVALID',
            'OUTPUT_LOCATION_INVALID', 'INPUT_CHANGED', 'METADATA_INVALID', 'XML_INVALID', 'HASH_MISMATCH',
            'EVENT_IDENTITY_MISMATCH', 'EVENT_CORRELATION_INVALID', 'ITERATION_COUNT_INVALID',
            'CHILD_RESULT_INVALID', 'HOST_RUN_FAILED', 'RUN_ID_INVALID', 'COPY_MISMATCH', 'CLI_FAILED',
            'PROJECT_VALIDATION_FAILED', 'TIMELINE_INVALID', 'TIMELINE_REPEAT_MISMATCH',
            'TIMELINE_SEMANTIC_MISMATCH', 'ARTIFACT_VALIDATION_FAILED', 'PROVENANCE_INVALID',
            'REPORT_INVALID', 'REPORT_SEMANTIC_MISMATCH')
        if ($safe -ccontains $_.Exception.Message) { $code = $_.Exception.Message }
        if ($_.Exception.Data['CliExit'] -is [int]) { $cliExit = $_.Exception.Data['CliExit'] }
    } finally {
        if ($null -ne $sourceSnapshot) {
            try {
                $finalSnapshot = Get-HostDemoSnapshot $source
                $sourceUnchanged = Test-HostDemoRepeatSnapshot $sourceSnapshot $finalSnapshot $true
            } catch { $sourceUnchanged = $false }
            if (-not $sourceUnchanged -and $status -eq 'success') {
                $status = 'failed'
                $stage = 'source-final'
                $code = 'INPUT_CHANGED'
            }
        }
    }
    $result = [ordered]@{
        status = $status
        stage = $stage
        code = $code
        cli_exit = $cliExit
        batch = $batchName
        iterations_requested = $Count
        iterations_completed = $completed
        failed_iteration = $failedIteration
        runs = $runNames
        source_unchanged = $sourceUnchanged
        copies_match = $copiesMatch
        artifacts_valid = $artifactsValid
        projects_valid = $projectsValid
        timelines_consistent = $timelinesConsistent
        reports_consistent = $reportsConsistent
        inner_stage = $innerStage
        inner_code = $innerCode
        diagnostic = 'not_created'
    }
    if ($null -ne $batch) {
        try {
            $result.diagnostic = 'written'
            Write-HostDemoNewText (Join-Path $batch 'repeat-diagnostic.json') ($result | ConvertTo-Json)
        } catch {
            $result.diagnostic = 'failed'
            if ($result.status -eq 'success') {
                $result.status = 'failed'
                $result.stage = 'diagnostic'
                $result.code = 'DIAGNOSTIC_WRITE_FAILED'
            }
        }
    }
    return [pscustomobject]$result
}

if ($script:RepeatInvocationName -ne '.') {
    $result = Invoke-SysmonHostDemoRepeat $CollectionDirectory $WorkbenchExecutable $OutputParent $Iterations
    Write-Output ($result | ConvertTo-Json -Compress)
    if ($result.status -eq 'success') { exit 0 }
    exit 1
}
