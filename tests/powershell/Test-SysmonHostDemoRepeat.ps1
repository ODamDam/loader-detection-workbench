#requires -Version 5.1
# Offline synthetic and mocked repeat-run checks. No VM or private collection is used.
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'scripts/Invoke-SysmonHostDemoRepeat.ps1') -CollectionDirectory 'unused'
$script:checks = 0
function Assert-RepeatTest {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw "FAILED: $Label" }
    $script:checks++
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('host-repeat-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
$fixtures = Join-Path $repo 'tests/fixtures/public/sysmon'
$installedWorkbench = (Resolve-Path -LiteralPath (Join-Path $repo '.venv/Scripts/workbench.exe')).ProviderPath

function New-RepeatTestCollection {
    param([string]$Directory)
    $null = New-Item -ItemType Directory -Path $Directory
    foreach ($name in @('process-create.xml', 'file-create.xml')) {
        [IO.File]::Copy((Join-Path $fixtures $name), (Join-Path $Directory $name))
    }
    $metadata = [ordered]@{
        collector = 'sysmon-demo'
        version = 1
        run_id = ('a' * 32)
        collection_started_at = '2026-10-06T01:02:00Z'
        collection_completed_at = '2026-10-06T01:02:10Z'
        events = @(
            [ordered]@{
                event_id = 1; record_id = 42; file = 'process-create.xml'
                sha256 = (Get-FileHash -LiteralPath (Join-Path $Directory 'process-create.xml')).Hash
            },
            [ordered]@{
                event_id = 11; record_id = 43; file = 'file-create.xml'
                sha256 = (Get-FileHash -LiteralPath (Join-Path $Directory 'file-create.xml')).Hash
            }
        )
    }
    Write-HostDemoNewText (Join-Path $Directory 'collection-metadata.json') ($metadata | ConvertTo-Json -Depth 4)
}

function Get-RepeatTestHashes {
    param([string]$Directory)
    return @(
        Get-ChildItem -LiteralPath $Directory -File | Sort-Object Name | ForEach-Object {
            $_.Name + ':' + $_.Length + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    )
}

try {
    # This is a real installed-CLI Host workflow over public synthetic XML. The
    # repeat runner launches exactly two independent powershell.exe children.
    $actualArea = Join-Path $testRoot 'actual synthetic space'
    $actualCollection = Join-Path $actualArea 'input'
    $null = New-Item -ItemType Directory -Path $actualArea
    New-RepeatTestCollection $actualCollection
    $before = Get-RepeatTestHashes $actualCollection
    $powerShellExecutable = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $global:LASTEXITCODE = $null
    $actualOutput = @(
        & $powerShellExecutable -NoProfile -NonInteractive -File `
            (Join-Path $repo 'scripts/Invoke-SysmonHostDemoRepeat.ps1') `
            -CollectionDirectory $actualCollection -OutputParent $actualArea `
            -Iterations 2 2>&1
    )
    $actualInvoked = $?
    $actualExit = $global:LASTEXITCODE
    Assert-RepeatTest ($actualInvoked -and $actualExit -eq 0) 'actual script entry point exits zero'
    Assert-RepeatTest ($actualOutput.Count -eq 1 -and $actualOutput[0] -is [string]) 'actual script stdout is one JSON string'
    $actual = $actualOutput[0] | ConvertFrom-Json -ErrorAction Stop
    if ($actual.status -ne 'success') {
        Write-Output ('Actual synthetic safe result: ' + ($actual | ConvertTo-Json -Compress))
    }
    Assert-RepeatTest ($actual.status -eq 'success' -and $actual.stage -eq 'complete' -and $actual.code -eq 'OK') 'actual synthetic repeat succeeds'
    Assert-RepeatTest ($actual.iterations_requested -eq 2 -and $actual.iterations_completed -eq 2 -and $null -eq $actual.failed_iteration) 'actual synthetic two iterations complete'
    Assert-RepeatTest ($actual.source_unchanged -and $actual.copies_match -and $actual.artifacts_valid -and
        $actual.projects_valid -and $actual.timelines_consistent -and $actual.reports_consistent) 'actual synthetic evidence checks pass'
    Assert-RepeatTest (@(Compare-Object $before (Get-RepeatTestHashes $actualCollection)).Count -eq 0) 'actual synthetic source unchanged'
    $actualBatch = Join-Path $actualArea $actual.batch
    $actualRuns = @(Get-ChildItem -LiteralPath $actualArea -Directory -Filter 'workbench-host-demo-*')
    Assert-RepeatTest ($actualRuns.Count -eq 2 -and $actualRuns[0].Name -cne $actualRuns[1].Name) 'actual synthetic independent run directories'
    foreach ($run in $actualRuns) {
        $diagnostic = Get-Content -LiteralPath (Join-Path $run.FullName 'diagnostic.json') -Raw | ConvertFrom-Json
        Assert-RepeatTest ($diagnostic.status -eq 'success' -and $diagnostic.stage -eq 'complete' -and $diagnostic.code -eq 'OK') 'actual child diagnostic success'
        Assert-RepeatTest (Test-Path -LiteralPath (Join-Path $run.FullName 'project/vm-demo.md') -PathType Leaf) 'actual child report retained'
        Assert-RepeatTest (Test-Path -LiteralPath (Join-Path $run.FullName 'timeline.txt') -PathType Leaf) 'actual child timeline retained'
    }
    $actualDiagnosticPath = Join-Path $actualBatch 'repeat-diagnostic.json'
    $actualDiagnosticText = [IO.File]::ReadAllText($actualDiagnosticPath)
    $actualDiagnostic = $actualDiagnosticText | ConvertFrom-Json
    Assert-RepeatTest ($actualDiagnostic.status -eq 'success' -and $actualDiagnostic.diagnostic -eq 'written') 'actual batch diagnostic written'
    Assert-RepeatTest (@($actualDiagnostic.runs).Count -eq 2 -and
        @($actualDiagnostic.runs | Select-Object -Unique).Count -eq 2) 'actual batch diagnostic identifies independent runs'
    Assert-RepeatTest (-not $actualDiagnosticText.Contains($testRoot) -and -not $actualDiagnosticText.Contains('<Event') -and
        -not $actualDiagnosticText.Contains('11111111-2222') -and -not $actualDiagnosticText.Contains('synthetic-demo')) 'actual batch diagnostic excludes sensitive values'

    $global:LASTEXITCODE = $null
    $failureOutput = @(
        & $powerShellExecutable -NoProfile -NonInteractive -File `
            (Join-Path $repo 'scripts/Invoke-SysmonHostDemoRepeat.ps1') `
            -CollectionDirectory ' ' -WorkbenchExecutable $installedWorkbench `
            -OutputParent $actualArea -Iterations 2 2>&1
    )
    $failureInvoked = $?
    $failureExit = $global:LASTEXITCODE
    Assert-RepeatTest ($failureInvoked -and $failureExit -eq 1 -and
        $failureOutput.Count -eq 1 -and $failureOutput[0] -is [string]) 'invalid path exits one with one JSON string'
    $failureResult = $failureOutput[0] | ConvertFrom-Json -ErrorAction Stop
    Assert-RepeatTest ($failureResult.status -eq 'failed' -and $failureResult.stage -eq 'preflight' -and
        $failureResult.code -eq 'PATH_ARGUMENT_INVALID' -and $failureResult.diagnostic -eq 'not_created') 'invalid path is safe structured failure'

    $script:realRepeatChild = ${function:Invoke-HostDemoRepeatChild}
    $script:realRepeatValidate = ${function:Test-HostDemoRepeatRun}
    $script:realRepeatName = ${function:New-HostDemoRepeatName}
    $script:scenario = ''
    $script:mockCalls = 0
    $script:mockCollection = $null

    function Invoke-HostDemoRepeatChild {
        param([string]$PowerShellExecutable, [string]$Collection, [string]$Executable, [string]$Parent)
        $script:mockCalls++
        if ($script:scenario -eq 'child-invalid' -and $script:mockCalls -eq 1) { throw 'CHILD_RESULT_INVALID' }
        if ($script:scenario -eq 'child-unsafe' -and $script:mockCalls -eq 1) {
            return [pscustomobject]@{
                Invoked = $false; ExitCode = 1
                Result = [pscustomobject]@{ status = 'failed'; stage = 'PRIVATE-SENTINEL path'; code = 'CLI_FAILED'; cli_exit = 2;
                    run = 'workbench-host-demo-' + ('c' * 32); diagnostic = 'written' }
            }
        }
        $runName = if ($script:scenario -eq 'duplicate-run') {
            'workbench-host-demo-' + ('b' * 32)
        } else {
            'workbench-host-demo-' + $script:mockCalls.ToString('x32')
        }
        if ($script:scenario -eq 'child-fail' -and $script:mockCalls -eq 2) {
            return [pscustomobject]@{
                Invoked = $false; ExitCode = 1
                Result = [pscustomobject]@{ status = 'failed'; stage = 'timeline'; code = 'CLI_FAILED'; cli_exit = 2;
                    run = $runName; diagnostic = 'written' }
            }
        }
        $runPath = Join-Path $Parent $runName
        if (-not (Test-Path -LiteralPath $runPath)) {
            $null = New-Item -ItemType Directory -Path $runPath
            [IO.File]::WriteAllText((Join-Path $runPath 'preserve.txt'), 'partial output')
        }
        return [pscustomobject]@{
            Invoked = $true; ExitCode = 0
            Result = [pscustomobject]@{ status = 'success'; stage = 'complete'; code = 'OK'; cli_exit = $null;
                run = $runName; diagnostic = 'written' }
        }
    }

    function Test-HostDemoRepeatRun {
        param([string]$RunDirectory, [string]$Executable, [hashtable]$SourceSnapshot)
        if ($script:scenario -eq 'copy-fail') { throw 'COPY_MISMATCH' }
        if ($script:scenario -eq 'source-change' -and $script:mockCalls -eq 1) {
            [IO.File]::SetLastWriteTimeUtc((Join-Path $script:mockCollection 'process-create.xml'), [DateTime]::UtcNow.AddHours(1))
        }
        return [pscustomobject]@{
            TimelineDigest = $(if ($script:scenario -eq 'timeline-diff' -and $script:mockCalls -eq 2) { 'timeline-b' } else { 'timeline-a' })
            ReportDigest = $(if ($script:scenario -eq 'report-diff' -and $script:mockCalls -eq 2) { 'report-b' } else { 'report-a' })
        }
    }

    function New-HostDemoRepeatName {
        if ($script:scenario -eq 'batch-collision') { return 'workbench-host-repeat-' + ('d' * 32) }
        return (& $script:realRepeatName)
    }

    $cases = @(
        [pscustomobject]@{ Name = 'child-fail'; Code = 'HOST_RUN_FAILED'; Calls = 2 },
        [pscustomobject]@{ Name = 'child-invalid'; Code = 'CHILD_RESULT_INVALID'; Calls = 1 },
        [pscustomobject]@{ Name = 'child-unsafe'; Code = 'CHILD_RESULT_INVALID'; Calls = 1 },
        [pscustomobject]@{ Name = 'copy-fail'; Code = 'COPY_MISMATCH'; Calls = 1 },
        [pscustomobject]@{ Name = 'duplicate-run'; Code = 'RUN_ID_INVALID'; Calls = 2 },
        [pscustomobject]@{ Name = 'timeline-diff'; Code = 'TIMELINE_SEMANTIC_MISMATCH'; Calls = 2 },
        [pscustomobject]@{ Name = 'report-diff'; Code = 'REPORT_SEMANTIC_MISMATCH'; Calls = 2 },
        [pscustomobject]@{ Name = 'source-change'; Code = 'INPUT_CHANGED'; Calls = 1 }
    )
    foreach ($case in $cases) {
        $script:scenario = $case.Name
        $script:mockCalls = 0
        $area = Join-Path $testRoot ('mock ' + $case.Name)
        $null = New-Item -ItemType Directory -Path $area
        $script:mockCollection = Join-Path $area 'input'
        New-RepeatTestCollection $script:mockCollection
        $original = Get-RepeatTestHashes $script:mockCollection
        $result = Invoke-SysmonHostDemoRepeat $script:mockCollection $installedWorkbench $area 3
        Assert-RepeatTest ($result.status -eq 'failed' -and $result.code -ceq $case.Code) "$($case.Name) safe failure code"
        Assert-RepeatTest ($script:mockCalls -eq $case.Calls) "$($case.Name) stops later iterations"
        Assert-RepeatTest ($result.diagnostic -eq 'written') "$($case.Name) batch diagnostic written"
        $batchPath = Join-Path $area $result.batch
        $diagnosticText = [IO.File]::ReadAllText((Join-Path $batchPath 'repeat-diagnostic.json'))
        Assert-RepeatTest (-not $diagnosticText.Contains($testRoot) -and -not $diagnosticText.Contains('<Event') -and
            -not $diagnosticText.Contains('11111111-2222') -and -not $diagnosticText.Contains('PRIVATE-SENTINEL')) "$($case.Name) safe diagnostic"
        if ($case.Name -eq 'source-change') {
            Assert-RepeatTest (-not $result.source_unchanged) 'source change reported'
        } else {
            Assert-RepeatTest (@(Compare-Object $original (Get-RepeatTestHashes $script:mockCollection)).Count -eq 0) "$($case.Name) source preserved"
        }
        $preserved = @(Get-ChildItem -LiteralPath $area -Recurse -File -Filter 'preserve.txt')
        if ($case.Name -notin @('child-invalid', 'child-unsafe', 'copy-fail')) {
            Assert-RepeatTest ($preserved.Count -ge 1) "$($case.Name) partial outputs preserved"
        }
    }

    foreach ($inputCase in @('missing-input', 'corrupt-input')) {
        $script:scenario = $inputCase
        $script:mockCalls = 0
        $area = Join-Path $testRoot $inputCase
        $null = New-Item -ItemType Directory -Path $area
        $collection = Join-Path $area 'input'
        New-RepeatTestCollection $collection
        if ($inputCase -eq 'missing-input') {
            Remove-Item -LiteralPath (Join-Path $collection 'file-create.xml')
        } else {
            [IO.File]::AppendAllText((Join-Path $collection 'file-create.xml'), 'synthetic corruption')
        }
        $result = Invoke-SysmonHostDemoRepeat $collection $installedWorkbench $area 2
        $expectedCode = if ($inputCase -eq 'missing-input') { 'COLLECTION_LAYOUT_INVALID' } else { 'HASH_MISMATCH' }
        Assert-RepeatTest ($result.status -eq 'failed' -and $result.code -eq $expectedCode) "$inputCase rejected"
        Assert-RepeatTest ($script:mockCalls -eq 0 -and $null -eq $result.batch -and $result.diagnostic -eq 'not_created') "$inputCase rejected before child and output"
    }

    $script:scenario = 'batch-collision'
    $script:mockCalls = 0
    $collisionArea = Join-Path $testRoot 'batch collision'
    $null = New-Item -ItemType Directory -Path $collisionArea
    $collisionCollection = Join-Path $collisionArea 'input'
    New-RepeatTestCollection $collisionCollection
    $collision = Join-Path $collisionArea ('workbench-host-repeat-' + ('d' * 32))
    $null = New-Item -ItemType Directory -Path $collision
    [IO.File]::WriteAllText((Join-Path $collision 'keep.txt'), 'original')
    $result = Invoke-SysmonHostDemoRepeat $collisionCollection $installedWorkbench $collisionArea 2
    Assert-RepeatTest ($result.status -eq 'failed' -and $result.code -eq 'OUTPUT_LOCATION_INVALID' -and
        $script:mockCalls -eq 0 -and $result.diagnostic -eq 'not_created') 'batch collision rejected before child'
    Assert-RepeatTest ([IO.File]::ReadAllText((Join-Path $collision 'keep.txt')) -ceq 'original' -and
        @(Get-ChildItem -LiteralPath $collision -Force).Count -eq 1) 'batch collision preserves existing output'

    $script:scenario = 'success'
    $invalidArea = Join-Path $testRoot 'invalid count'
    $null = New-Item -ItemType Directory -Path $invalidArea
    $invalidCollection = Join-Path $invalidArea 'input'
    New-RepeatTestCollection $invalidCollection
    $invalid = Invoke-SysmonHostDemoRepeat $invalidCollection $installedWorkbench $invalidArea 1
    Assert-RepeatTest ($invalid.status -eq 'failed' -and $invalid.code -eq 'ITERATION_COUNT_INVALID' -and $null -eq $invalid.batch) 'invalid iteration count rejected before output'

    "Host repeat checks: $script:checks PASS; actual synthetic CLI iterations: 2; no VM or private collection execution."
} finally {
    $resolved = (Resolve-Path -LiteralPath $testRoot).ProviderPath
    $temp = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).ProviderPath.TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($resolved) -ne $temp -or [IO.Path]::GetFileName($resolved) -notlike 'host-repeat-test-*') {
        throw 'UNSAFE_TEST_CLEANUP'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
