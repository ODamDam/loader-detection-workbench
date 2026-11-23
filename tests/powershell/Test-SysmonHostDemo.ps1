#requires -Version 5.1
# Offline synthetic filesystem tests. All Workbench calls are mocked.
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'scripts/Invoke-SysmonHostDemo.ps1') -CollectionDirectory 'unused'
$script:checks = 0
function Assert-HostTest {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw "FAILED: $Label" }
    $script:checks++
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('host-demo-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
$fakeExecutable = Join-Path $testRoot 'mock-workbench.exe'
[IO.File]::WriteAllText($fakeExecutable, 'Never executed: the CLI boundary is mocked.')
$fixtures = Join-Path $repo 'tests/fixtures/public/sysmon'
$script:realCopy = ${function:Copy-HostDemoFile}
$script:realCli = ${function:Invoke-HostDemoCli}
$script:realRunName = ${function:New-HostDemoRunName}
$script:realWriteText = ${function:Write-HostDemoNewText}

function Write-HostDemoNewText {
    param([string]$Path, [string]$Text)
    if ($script:scenario -in @('diagnostic-failure', 'failure-diagnostic') -and [IO.Path]::GetFileName($Path) -eq 'diagnostic.json') {
        throw 'PRIVATE-SENTINEL diagnostic write failure'
    }
    & $script:realWriteText $Path $Text
}

function New-TestCollection {
    param([string]$Directory)
    $null = New-Item -ItemType Directory -Path $Directory
    foreach ($name in @('process-create.xml', 'file-create.xml')) {
        [IO.File]::Copy((Join-Path $fixtures $name), (Join-Path $Directory $name))
    }
    $metadata = [ordered]@{
        collector = 'sysmon-demo'; version = 1; run_id = ('a' * 32)
        collection_started_at = '2026-10-06T01:02:00Z'; collection_completed_at = '2026-10-06T01:02:10Z'
        events = @(
            [ordered]@{ event_id = 1; record_id = 42; file = 'process-create.xml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $Directory 'process-create.xml')).Hash },
            [ordered]@{ event_id = 11; record_id = 43; file = 'file-create.xml'; sha256 = (Get-FileHash -LiteralPath (Join-Path $Directory 'file-create.xml')).Hash }
        )
    }
    Write-HostDemoNewText (Join-Path $Directory 'collection-metadata.json') ($metadata | ConvertTo-Json -Depth 4)
}

function Update-TestHashes {
    param([string]$Directory)
    $path = Join-Path $Directory 'collection-metadata.json'
    $metadata = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    foreach ($entry in $metadata.events) { $entry.sha256 = (Get-FileHash -LiteralPath (Join-Path $Directory $entry.file)).Hash }
    [IO.File]::WriteAllText($path, ($metadata | ConvertTo-Json -Depth 4))
}

function Copy-HostDemoFile {
    param([string]$Source, [string]$Destination)
    & $script:realCopy $Source $Destination
    if ($script:scenario -eq 'source-change' -and [IO.Path]::GetFileName($Source) -eq 'process-create.xml') {
        [IO.File]::AppendAllText($Source, 'synthetic mutation')
    }
    if ($script:scenario -eq 'layout-change' -and [IO.Path]::GetFileName($Source) -eq 'process-create.xml') {
        [IO.File]::WriteAllText((Join-Path ([IO.Path]::GetDirectoryName($Source)) 'extra.txt'), 'synthetic')
    }
    if ($script:scenario -eq 'copy-change' -and [IO.Path]::GetFileName($Source) -eq 'process-create.xml') {
        [IO.File]::AppendAllText($Destination, 'synthetic mutation')
    }
    if ($script:scenario -eq 'timestamp-change' -and [IO.Path]::GetFileName($Source) -eq 'process-create.xml') {
        [IO.File]::SetLastWriteTimeUtc($Source, [DateTime]::UtcNow.AddHours(1))
    }
}

function New-HostDemoRunName {
    if ($script:scenario -eq 'existing-run') { return ('workbench-host-demo-' + ('b' * 32)) }
    return (& $script:realRunName)
}

function Invoke-HostDemoCli {
    param([string]$Executable, [string[]]$Arguments)
    $script:calls += ,$Arguments
    $step = $script:calls.Count
    if ($script:scenario -eq 'launch-failed') { throw 'PRIVATE-SENTINEL synthetic exception' }
    if ($script:scenario -eq "fail-$step" -or ($script:scenario -eq 'failure-diagnostic' -and $step -eq 4)) {
        return [pscustomobject]@{ Invoked = $true; ExitCode = 2; Lines = @('PRIVATE-SENTINEL fake command line') }
    }
    if ($script:scenario -eq 'unset-exit') { return [pscustomobject]@{ Invoked = $true; ExitCode = $null; Lines = @() } }
    if ($script:scenario -eq 'invocation-false') { return [pscustomobject]@{ Invoked = $false; ExitCode = 0; Lines = @() } }
    $text = ''
    switch ($step) {
        1 {
            $null = New-Item -ItemType Directory -Path $Arguments[2]
            $script:project = $Arguments[2]
            $text = "display_id: PRJ-0001`nextra: harmless"
            if ($script:scenario -eq 'missing-id') { $text = 'extra: harmless' }
            if ($script:scenario -eq 'duplicate-id') { $text += "`ndisplay_id: PRJ-0002" }
        }
        2 {
            $text = "display_id: CASE-0001`nkind: benign`nextra: harmless"
            if ($script:scenario -eq 'case-kind') { $text = $text.Replace('benign', 'malware') }
        }
        { $_ -in @(3, 4) } {
            $artifactId = 'ART-00000' + ($step - 2)
            $inputPath = $Arguments[4]
            Assert-HostTest (-not (Test-HostDemoUnder $inputPath $script:collection)) 'only copy registered'
            Assert-HostTest (Test-HostDemoUnder $inputPath ([IO.Path]::GetDirectoryName($script:project))) 'copy in independent run'
            $locked = $false
            try { $handle = [IO.File]::OpenWrite($inputPath); $handle.Dispose() } catch { $locked = $true }
            Assert-HostTest $locked 'validated copy locked against writes'
            $hash = (Get-FileHash -LiteralPath $inputPath).Hash
            if ($script:scenario -eq 'artifact-hash') { $hash = '0' * 64 }
            if ($script:scenario -eq 'duplicate-artifact') { $artifactId = 'ART-000001' }
            $size = (Get-Item -LiteralPath $inputPath).Length
            $text = "$artifactId`tsysmon`t$hash`t$size`tartifacts/synthetic.xml"
        }
        5 {
            $text = @"
case: CASE-0001
sysmon_artifacts: 2
observations: 2
extra: harmless
2026-10-06T01:02:03Z  EventID=1  process_create
  image: benign-demo.exe
  pid: 1234
  command_line: PRIVATE-SENTINEL synthetic
  source: ART-000001#42
2026-10-06T01:02:05Z  EventID=11  file_create
  image: benign-demo.exe
  pid: 1234
  target: synthetic-demo/output.txt
  source: ART-000002#43
"@
            if ($script:scenario -eq 'provenance') { $text = $text.Replace('ART-000002#43', 'ART-000002#99') }
            if ($script:scenario -eq 'observations') { $text = $text.Replace('observations: 2', 'observations: 1') }
            if ($script:scenario -eq 'timeline-kind') { $text = $text.Replace('EventID=1  process_create', 'EventID=1  file_create') }
            if ($script:scenario -eq 'existing-report') { [IO.File]::WriteAllText((Join-Path $script:project 'vm-demo.md'), 'original') }
        }
        6 {
            if ($script:scenario -eq 'racing-report') {
                Write-HostDemoNewText (Join-Path $script:project 'vm-demo.md') 'original'
                return [pscustomobject]@{ Invoked = $true; ExitCode = 2; Lines = @('error: REPORT_OUTPUT_EXISTS') }
            }
            $report = @"
# Case Report
## Case Overview
- Case ID: CASE-0001
## Evidence Summary
- Normalized Observations: 2
- Sysmon Artifacts: 2
## Timeline
### 2026-10-06T01:02:03Z - Process Create
- Event ID: 1
- Process ID: 1234
- Source Artifact: ART-000001
- Source Record: 42
### 2026-10-06T01:02:05Z - File Create
- Event ID: 11
- Process ID: 1234
- Source Artifact: ART-000002
- Source Record: 43
## Collection / Analysis Limits
"@
            if ($script:scenario -eq 'bad-report') { $report = 'incomplete' }
            if ($script:scenario -eq 'report-provenance') { $report = $report.Replace('Source Record: 43', 'Source Record: 99') }
            if ($script:scenario -ne 'missing-report') { Write-HostDemoNewText (Join-Path $script:project 'vm-demo.md') $report }
            $text = 'report: created'
        }
        default { throw 'Unexpected CLI call' }
    }
    return [pscustomobject]@{ Invoked = $true; ExitCode = 0; Lines = @($text -split "`n") }
}

try {
    $scenarios = @('success', 'missing', 'extra', 'bad-hash', 'bad-json', 'duplicate-key', 'bad-version',
        'bad-time', 'bad-record', 'bad-xml', 'dtd', 'guid', 'pid', 'event-id', 'source-change', 'layout-change',
        'copy-change', 'launch-failed', 'unset-exit', 'invocation-false', 'missing-id', 'artifact-hash',
        'observations', 'provenance', 'existing-run', 'existing-report', 'bad-report', 'missing-report',
        'fail-1', 'fail-2', 'fail-3', 'fail-4', 'fail-5', 'fail-6', 'timestamp-change', 'duplicate-id',
        'case-kind', 'duplicate-artifact', 'timeline-kind', 'racing-report', 'report-provenance',
        'directory-entry', 'empty-file', 'unknown-metadata', 'record-order', 'duplicate-data', 'wrong-provider',
        'array-metadata', 'diagnostic-failure', 'failure-diagnostic')
    foreach ($script:scenario in $scenarios) {
        $area = Join-Path $testRoot ($scenario + ' space ' + [char]0xac00)
        $null = New-Item -ItemType Directory -Path $area
        $script:collection = Join-Path $area 'input'
        New-TestCollection $collection
        $xmlPath = Join-Path $collection 'file-create.xml'
        $metadataPath = Join-Path $collection 'collection-metadata.json'
        switch ($scenario) {
            'missing' { Remove-Item -LiteralPath $xmlPath }
            'extra' { [IO.File]::WriteAllText((Join-Path $collection 'extra.txt'), 'synthetic') }
            'bad-hash' { [IO.File]::AppendAllText($xmlPath, 'synthetic mutation') }
            'bad-json' { [IO.File]::WriteAllText($metadataPath, '{broken') }
            'duplicate-key' { [IO.File]::WriteAllText($metadataPath, ([IO.File]::ReadAllText($metadataPath).Replace('"version":', '"version": 1, "version":'))) }
            'bad-version' { [IO.File]::WriteAllText($metadataPath, ([IO.File]::ReadAllText($metadataPath) -replace '"version":\s*1', '"version": 2')) }
            'bad-time' { [IO.File]::WriteAllText($metadataPath, ([IO.File]::ReadAllText($metadataPath).Replace('2026-10-06T01:02:10Z', 'not-a-time'))) }
            'bad-record' { [IO.File]::WriteAllText($metadataPath, ([IO.File]::ReadAllText($metadataPath) -replace '"record_id":\s*43', '"record_id": 44')) }
            'bad-xml' { [IO.File]::WriteAllText($xmlPath, '<broken'); Update-TestHashes $collection }
            'dtd' { [IO.File]::WriteAllText($xmlPath, '<!DOCTYPE Event [<!ENTITY x "synthetic">]><Event>&x;</Event>'); Update-TestHashes $collection }
            'guid' { [IO.File]::WriteAllText($xmlPath, ([IO.File]::ReadAllText($xmlPath).Replace('11111111-2222', '99999999-2222'))); Update-TestHashes $collection }
            'pid' { [IO.File]::WriteAllText($xmlPath, ([IO.File]::ReadAllText($xmlPath).Replace('1234', '5678'))); Update-TestHashes $collection }
            'event-id' { [IO.File]::WriteAllText($xmlPath, ([IO.File]::ReadAllText($xmlPath).Replace('<EventID>11', '<EventID>1'))); Update-TestHashes $collection }
            'directory-entry' { Remove-Item -LiteralPath $xmlPath; $null = New-Item -ItemType Directory -Path $xmlPath }
            'empty-file' { [IO.File]::WriteAllText($xmlPath, '') }
            'unknown-metadata' { [IO.File]::WriteAllText($metadataPath, ([IO.File]::ReadAllText($metadataPath).Replace('"version":', '"unknown": 1, "version":'))) }
            'record-order' {
                [IO.File]::WriteAllText($xmlPath, ([IO.File]::ReadAllText($xmlPath).Replace('<EventRecordID>43', '<EventRecordID>41')))
                [IO.File]::WriteAllText($metadataPath, ([IO.File]::ReadAllText($metadataPath) -replace '"record_id":\s*43', '"record_id": 41'))
                Update-TestHashes $collection
            }
            'duplicate-data' { [IO.File]::WriteAllText($xmlPath, ([IO.File]::ReadAllText($xmlPath).Replace('</EventData>', '<Data Name="ProcessId">1234</Data></EventData>'))); Update-TestHashes $collection }
            'wrong-provider' { [IO.File]::WriteAllText($xmlPath, ([IO.File]::ReadAllText($xmlPath).Replace('Microsoft-Windows-Sysmon', 'Synthetic-Other'))); Update-TestHashes $collection }
            'array-metadata' { [IO.File]::WriteAllText($metadataPath, ('[' + [IO.File]::ReadAllText($metadataPath) + ']')) }
            'existing-run' {
                $existing = Join-Path $area ('workbench-host-demo-' + ('b' * 32))
                $null = New-Item -ItemType Directory -Path $existing
                [IO.File]::WriteAllText((Join-Path $existing 'keep.txt'), 'original')
            }
        }
        $script:calls = @()
        $original = @(Get-ChildItem -LiteralPath $collection -File | ForEach-Object { $_.Name + ':' + (Get-FileHash -LiteralPath $_.FullName).Hash })
        $location = (Get-Location).Path
        $result = Invoke-SysmonHostDemo $collection $fakeExecutable $area
        Assert-HostTest ((Get-Location).Path -eq $location) "$scenario restores working directory"
        Assert-HostTest ($result.status -eq $(if ($scenario -eq 'success') { 'success' } else { 'failed' })) "$scenario outcome ($($result.stage)/$($result.code))"
        if ($scenario -notin @('source-change', 'layout-change')) {
            $current = @(Get-ChildItem -LiteralPath $collection -File | ForEach-Object { $_.Name + ':' + (Get-FileHash -LiteralPath $_.FullName).Hash })
            Assert-HostTest (@(Compare-Object $original $current).Count -eq 0) "$scenario source unchanged"
        }
        if ($scenario -eq 'success') { Assert-HostTest ($calls.Count -eq 6) 'all six CLI calls' }
        if ($scenario -match '^fail-(\d)$') { Assert-HostTest ($calls.Count -eq [int]$Matches[1]) "$scenario no later CLI calls" }
        if ($scenario -eq 'existing-report') {
            Assert-HostTest ($calls.Count -eq 5) 'existing report stops before build'
            Assert-HostTest ([IO.File]::ReadAllText((Join-Path $script:project 'vm-demo.md')) -ceq 'original') 'original report preserved'
        }
        if ($scenario -eq 'racing-report') { Assert-HostTest ([IO.File]::ReadAllText((Join-Path $script:project 'vm-demo.md')) -ceq 'original') 'racing report preserved' }
        if ($result.stage -in @('preflight', 'copy', 'validate')) { Assert-HostTest ($calls.Count -eq 0) "$scenario rejected before CLI" }
        if ($scenario -eq 'existing-run') {
            Assert-HostTest ([IO.File]::ReadAllText((Join-Path $existing 'keep.txt')) -ceq 'original') 'existing run preserved'
            Assert-HostTest (@(Get-ChildItem -LiteralPath $existing -Force).Count -eq 1) 'existing run receives no diagnostics'
        } elseif ($scenario -in @('diagnostic-failure', 'failure-diagnostic')) {
            Assert-HostTest ($result.diagnostic -eq 'failed') 'diagnostic write failure reported'
            if ($scenario -eq 'failure-diagnostic') {
                Assert-HostTest ($result.stage -eq 'artifact-2' -and $result.cli_exit -eq 2 -and $calls.Count -eq 4) 'original failure preserved when diagnostic also fails'
            } else {
                Assert-HostTest ($result.stage -eq 'diagnostic' -and (Test-Path -LiteralPath (Join-Path $script:project 'vm-demo.md'))) 'report retained after diagnostic failure'
            }
        } elseif ($result.run) {
            $runPath = Join-Path $area $result.run
            $diagnostic = [IO.File]::ReadAllText((Join-Path $runPath 'diagnostic.json'))
            Assert-HostTest (-not $diagnostic.Contains('PRIVATE-SENTINEL') -and -not $diagnostic.Contains($testRoot) -and
                -not $diagnostic.Contains('<Event') -and -not $diagnostic.Contains('11111111-2222')) "$scenario safe diagnostic"
            $record = $diagnostic | ConvertFrom-Json
            Assert-HostTest ($record.status -eq $result.status -and $record.stage -eq $result.stage) "$scenario diagnostic state"
            Assert-HostTest (Test-Path -LiteralPath (Join-Path $runPath 'collection')) "$scenario partial evidence retained"
        }
    }
    & {
        function Get-Item {
            [pscustomobject]@{ PSProvider = [pscustomobject]@{ Name = 'FileSystem' }; PSIsContainer = $true;
                Attributes = [IO.FileAttributes]::ReparsePoint; FullName = 'synthetic-link' }
        }
        $rejected = $false
        try { $null = Resolve-HostDemoPath 'synthetic-link' $true } catch { $rejected = $_.Exception.Message -eq 'LINK_NOT_ALLOWED' }
        Assert-HostTest $rejected 'reparse data path rejected without traversal'
    }
    $script:scenario = 'success'
    foreach ($parent in @($repo, $script:collection)) {
        $script:calls = @()
        $result = Invoke-SysmonHostDemo $script:collection $fakeExecutable $parent
        Assert-HostTest ($result.status -eq 'failed' -and $result.code -in @('OUTPUT_LOCATION_INVALID', 'LINK_NOT_ALLOWED') -and $calls.Count -eq 0) "unsafe output location rejected ($($result.code))"
    }
    $noReplace = Join-Path $testRoot 'no-replace.txt'
    Write-HostDemoNewText $noReplace 'original'
    $rejected = $false
    try { Write-HostDemoNewText $noReplace 'replacement' } catch { $rejected = $true }
    Assert-HostTest ($rejected -and [IO.File]::ReadAllText($noReplace) -ceq 'original') 'text outputs use no-replace creation'
    # Exercise the exact Windows PowerShell 5.1 native-process boundary. A
    # PowerShell function cannot model the global LASTEXITCODE behavior.
    $cmd = Join-Path $env:SystemRoot 'System32/cmd.exe'
    $global:LASTEXITCODE = 99
    $observed = & $script:realCli $cmd @('/d', '/c', 'echo synthetic-stdout')
    Assert-HostTest ($observed.Invoked -and $observed.ExitCode -eq 0) 'native success exit replaces stale code'
    Assert-HostTest ($observed.Lines.Count -eq 1 -and $observed.Lines[0].Trim() -ceq 'synthetic-stdout') 'native stdout captured'
    $global:LASTEXITCODE = 99
    $observed = & $script:realCli $cmd @('/d', '/c', 'exit 7')
    Assert-HostTest (-not $observed.Invoked -and $observed.ExitCode -eq 7 -and $observed.Lines.Count -eq 0) 'native nonzero exit captured'
    $global:LASTEXITCODE = 99
    $missingRejected = $false
    try { $null = & $script:realCli (Join-Path $testRoot 'missing-workbench.exe') @() }
    catch { $missingRejected = $true }
    Assert-HostTest ($missingRejected -and $null -eq $global:LASTEXITCODE) 'missing executable rejected without stale exit'

    # Read-only smoke test for the same installed native launcher used by the demo.
    $installedWorkbench = (Resolve-Path -LiteralPath (Join-Path $repo '.venv/Scripts/workbench.exe')).ProviderPath
    $observed = & $script:realCli $installedWorkbench @('--version')
    Assert-HostTest ($observed.Invoked -and $observed.ExitCode -eq 0) 'installed Workbench native smoke exit'
    Assert-HostTest ($observed.Lines.Count -eq 1 -and $observed.Lines[0] -match '^workbench [0-9]+\.[0-9]+\.[0-9]+$') 'installed Workbench version output'
    "Host demo synthetic/mocked/native checks: $script:checks PASS; no VM or Workbench Project execution."
} finally {
    $resolved = (Resolve-Path -LiteralPath $testRoot).ProviderPath
    $temp = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).ProviderPath.TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($resolved) -ne $temp -or [IO.Path]::GetFileName($resolved) -notlike 'host-demo-test-*') { throw 'UNSAFE_TEST_CLEANUP' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
