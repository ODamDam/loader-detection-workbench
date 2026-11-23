#requires -Version 5.1
# Dependency-free synthetic/mocked checks. Never launch a child or query host logs.
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'scripts/vm/Invoke-SysmonDemoCollection.ps1') -OutputDirectory 'unused'
$startChildImplementation = ${function:Start-DemoChild}
$script:checks = 0
function Assert-True { param([bool]$Value, [string]$Label) if (-not $Value) { throw "FAILED: $Label" }; $script:checks++ }
function Assert-Failure {
    param([scriptblock]$Action, [string]$Code)
    $failed = $false
    try { & $Action } catch { $failed = $true; Assert-True ($_.Exception.Message -like "*$Code*") $Code }
    Assert-True $failed "expected $Code"
}
function Start-Process { throw 'HOST_PROCESS_EXECUTION_FORBIDDEN' }
function New-Record {
    param([string]$Xml)
    $item = [pscustomobject]@{ Xml = $Xml; RecordId = 43 }
    $item | Add-Member ScriptMethod ToXml { $this.Xml }
    return $item
}
$processXml = Get-Content -LiteralPath (Join-Path $repo 'tests/fixtures/public/sysmon/process-create.xml') -Raw -Encoding UTF8
$fileXml = Get-Content -LiteralPath (Join-Path $repo 'tests/fixtures/public/sysmon/file-create.xml') -Raw -Encoding UTF8
function New-Pair {
    param([string]$RunId = 'synthetic-run', [string]$Target = 'synthetic-demo/output.txt')
    $p = $processXml.Replace('benign-demo.exe --message &quot;hello&quot;', "powershell.exe hello-workbench-$RunId")
    $f = $fileXml.Replace('synthetic-demo/output.txt', [Security.SecurityElement]::Escape($Target))
    @((ConvertTo-DemoEvent (New-Record $p)), (ConvertTo-DemoEvent (New-Record $f)))
}
$pair = @(New-Pair)
Assert-True ($pair.Count -eq 2) 'parse fixture pair'
$selected = @(Select-DemoPair -Events $pair -Baseline 41 -RunId 'synthetic-run' -Target 'synthetic-demo/output.txt' -ChildId 1234)
Assert-True ($selected.Count -eq 2) 'correlated pair'
Assert-True (@(Select-DemoPair -Events $pair -Baseline 42 -RunId 'synthetic-run' -Target 'synthetic-demo/output.txt' -ChildId 1234).Count -eq 0) 'old process excluded'
Assert-True (@(Select-DemoPair -Events $pair -Baseline 41 -RunId 'other-run' -Target 'synthetic-demo/output.txt' -ChildId 1234).Count -eq 0) 'other marker excluded'
Assert-True (@(Select-DemoPair -Events $pair -Baseline 41 -RunId 'synthetic-run' -Target 'synthetic-demo/output.txt' -ChildId 5678).Count -eq 0) 'other child excluded'
foreach ($field in @('ProcessGuid', 'ProcessId', 'TargetFilename')) {
    $bad = @(New-Pair)
    $bad[1].Data[$field] = 'mismatch'
    Assert-True (@(Select-DemoPair -Events $bad -Baseline 41 -RunId 'synthetic-run' -Target 'synthetic-demo/output.txt' -ChildId 1234).Count -eq 0) "mismatching $field excluded"
}
$bad = @(New-Pair); $bad[1].RecordId = 41
Assert-True (@(Select-DemoPair -Events $bad -Baseline 40 -RunId 'synthetic-run' -Target 'synthetic-demo/output.txt' -ChildId 1234).Count -eq 0) 'file must follow process'
Assert-Failure { Select-DemoPair -Events @($pair[0], $pair[0], $pair[1]) -Baseline 41 -RunId 'synthetic-run' -Target 'synthetic-demo/output.txt' -ChildId 1234 } 'AMBIGUOUS_PROCESS'
Assert-Failure { Select-DemoPair -Events @($pair[0], $pair[1], $pair[1]) -Baseline 41 -RunId 'synthetic-run' -Target 'synthetic-demo/output.txt' -ChildId 1234 } 'AMBIGUOUS_FILE'
Assert-Failure { ConvertTo-DemoEvent (New-Record '<!DOCTYPE Event><Event/>') } 'INVALID_EVENT_XML'
Assert-Failure { ConvertTo-DemoEvent (New-Record ($processXml.Replace('Name="CommandLine"', 'Name="Image"'))) } 'INVALID_EVENT_XML'

# Every OS telemetry/process boundary is mocked for main-flow tests.
$script:serviceRunning = $true
$script:logEnabled = $true
$script:coverage = $true
$script:queryFailure = $false
$script:pollMode = 'success'
$script:childCalls = 0
$script:runMarker = ''
$script:runTarget = ''
function Get-Service {
    param($Name, $ErrorAction)
    if ($script:serviceRunning) { [pscustomobject]@{ Status = 'Running' } }
}
function Get-WinEvent {
    param($ListLog, $LogName, $FilterXPath, $MaxEvents, $ErrorAction)
    if ($ListLog) { return [pscustomobject]@{ IsEnabled = $script:logEnabled } }
    if ($script:queryFailure) { throw 'injected private log error' }
    if ($FilterXPath -eq '*') { return [pscustomobject]@{ RecordId = 41 } }
    if ($FilterXPath -notlike '*EventRecordID*') {
        if ($script:coverage) { return New-Record $processXml }
        return
    }
    if ($script:pollMode -eq 'timeout') { return }
    $events = @(New-Pair -RunId $script:runMarker -Target $script:runTarget)
    foreach ($event in $events) { New-Record $event.Xml }
}
function Start-DemoChild {
    param([string]$Target, [string]$RunId)
    $script:childCalls++
    $script:runMarker = $RunId
    $script:runTarget = $Target
    $child = [pscustomobject]@{ Id = 1234; ExitCode = 0; HasExited = $true }
    $child | Add-Member ScriptMethod WaitForExit { param($milliseconds) return $true }
    $child | Add-Member ScriptMethod Dispose { }
    return $child
}
$runtime = Join-Path ([IO.Path]::GetTempPath()) ('workbench-helper-tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($runtime)
try {
    function Start-Process {
        param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru, $ErrorAction)
        $script:childArguments = $ArgumentList
        Assert-True ($WindowStyle -eq 'Hidden') 'hidden child window'
        [pscustomobject]@{ Handle = 1 }
    }
    $quotedTarget = Join-Path $runtime "quote ' and `$ literal/demo.txt"
    $null = & $startChildImplementation -Target $quotedTarget -RunId 'synthetic-run'
    $command = $script:childArguments[3]
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($command.Substring(1, $command.Length - 2), [ref]$tokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'child command parses without executing'
    $literals = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] }, $true)
    Assert-True (@($literals | Where-Object { $_.Value -eq $quotedTarget }).Count -eq 1) 'target remains one literal argument'
    function Start-Process { throw 'HOST_PROCESS_EXECUTION_FORBIDDEN' }
    $output = Join-Path $runtime 'collection'
    $root = Join-Path $runtime "quoted ' demo"
    $script:serviceRunning = $false
    Assert-Failure { Invoke-DemoCollection -Output $output -Root $root -Timeout 1 } 'SYSMON_NOT_RUNNING'
    $script:serviceRunning = $true; $script:logEnabled = $false
    Assert-Failure { Invoke-DemoCollection -Output $output -Root $root -Timeout 1 } 'SYSMON_LOG_DISABLED'
    $script:logEnabled = $true; $script:coverage = $false
    Assert-Failure { Invoke-DemoCollection -Output $output -Root $root -Timeout 1 } 'SYSMON_COVERAGE_UNVERIFIED'
    $script:coverage = $true; $script:queryFailure = $true
    Assert-Failure { Invoke-DemoCollection -Output $output -Root $root -Timeout 1 } 'SYSMON_LOG_UNREADABLE'
    $script:queryFailure = $false
    Assert-True ($script:childCalls -eq 0) 'readiness failures must not execute activity'
    $script:pollMode = 'timeout'
    Assert-Failure { Invoke-DemoCollection -Output $output -Root $root -Timeout 1 } 'COLLECTION_TIMEOUT'
    Assert-True (-not (Test-Path -LiteralPath $output)) 'timeout has no final output'
    $script:pollMode = 'success'
    $success = Invoke-DemoCollection -Output $output -Root $root -Timeout 2
    Assert-True ($success -eq 'collection: complete (2 events)') 'mocked main success'
    Assert-True (@(Get-ChildItem -LiteralPath $output).Count -eq 3) 'exact output file set'
    $metadata = Get-Content -LiteralPath (Join-Path $output 'collection-metadata.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($metadata.collector -eq 'sysmon-demo' -and $metadata.events.Count -eq 2) 'metadata contract'
    Assert-True (($metadata.PSObject.Properties.Name -join ',') -eq 'collector,version,run_id,collection_started_at,collection_completed_at,events') 'no environment metadata'
    foreach ($entry in $metadata.events) {
        $path = Join-Path $output $entry.file
        Assert-True ((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -eq $entry.sha256) 'XML hash'
        $bytes = [IO.File]::ReadAllBytes($path)
        Assert-True (-not ($bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) 'UTF8 no BOM'
        $parsed = ConvertTo-DemoEvent (New-Record ([IO.File]::ReadAllText($path)))
        Assert-True ($parsed.RecordId -eq $entry.record_id -and $parsed.EventId -eq $entry.event_id) 'XML identity'
    }
    $before = (Get-FileHash -LiteralPath (Join-Path $output 'process-create.xml')).Hash
    Assert-Failure { Invoke-DemoCollection -Output $output -Root $root -Timeout 1 } 'OUTPUT_EXISTS'
    Assert-True ((Get-FileHash -LiteralPath (Join-Path $output 'process-create.xml')).Hash -eq $before) 'no overwrite'
    $incomplete = Join-Path $runtime 'incomplete'
    Assert-Failure { Publish-DemoCollection -Output $incomplete -Pair @($pair[0]) -RunId 'synthetic-run' -StartedAt '2026-10-06T00:00:00Z' } 'INVALID_PAIR'
    Assert-True (-not (Test-Path -LiteralPath $incomplete)) 'no partial publication'
    Assert-True (@(Get-ChildItem -LiteralPath $runtime -Filter '.sysmon-demo-*.tmp').Count -eq 0) 'staging cleaned'
    function Get-FileHash { throw 'INJECTED_WRITE_VALIDATION_FAILURE' }
    Assert-Failure { Publish-DemoCollection -Output $incomplete -Pair $pair -RunId 'synthetic-run' -StartedAt '2026-10-06T00:00:00Z' } 'INJECTED_WRITE_VALIDATION_FAILURE'
    Remove-Item Function:\Get-FileHash
    Assert-True (-not (Test-Path -LiteralPath $incomplete)) 'write failure has no final output'
    Assert-True (@(Get-ChildItem -LiteralPath $runtime -Filter '.sysmon-demo-*.tmp').Count -eq 0) 'write failure cleans partial staging'
    Write-Output "PowerShell mocked checks: $script:checks PASS; no host process/log activity."
} finally {
    $resolved = (Resolve-Path -LiteralPath $runtime).ProviderPath
    $tempParent = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).ProviderPath.TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($resolved) -ne $tempParent -or
        [IO.Path]::GetFileName($resolved) -notlike 'workbench-helper-tests-*') { throw 'UNSAFE_TEST_CLEANUP' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
