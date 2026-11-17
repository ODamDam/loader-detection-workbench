#requires -Version 5.1
# Dependency-free mocked checks for the W4 guest runner. Never launches a real
# process, queries host logs or writes outside a temporary directory.
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'src/loader_detection_workbench/execution/guest/Invoke-WorkbenchGuestRun.ps1')
$script:checks = 0
function Assert-True { param([bool]$Value, [string]$Label) if (-not $Value) { throw "FAILED: $Label" }; $script:checks++ }
function Assert-Failure {
    param([scriptblock]$Action, [string]$Code)
    $failed = $false
    try { & $Action } catch { $failed = $true; Assert-True ($_.Exception.Message -like "$Code*") "$Code (got: $($_.Exception.Message))" }
    Assert-True $failed "expected $Code"
}

# Host safety: every process/OS boundary is mocked.
$script:started = @()
function Start-Process {
    param($FilePath, $WorkingDirectory, [switch]$PassThru, $WindowStyle, $ErrorAction, $ArgumentList)
    $script:started += , @{ FilePath = $FilePath; Arguments = $ArgumentList }
    $process = [pscustomobject]@{ Id = 4242; Exited = $script:exitEarly }
    $process | Add-Member ScriptMethod WaitForExit { param($ms) $this.Exited }
    $process | Add-Member ScriptMethod Dispose { }
    return $process
}
$script:stopped = @()
function Stop-Process { param($Id, [switch]$Force, $ErrorAction) $script:stopped += $Id }
function Start-Sleep { param($Seconds, $Milliseconds) }
function Get-CimInstance {
    param($ClassName, $ErrorAction)
    @(
        [pscustomobject]@{ ProcessId = 4242; ParentProcessId = 1 },
        [pscustomobject]@{ ProcessId = 5000; ParentProcessId = 4242 },
        [pscustomobject]@{ ProcessId = 5001; ParentProcessId = 5000 },
        [pscustomobject]@{ ProcessId = 6000; ParentProcessId = 1 }
    )
}
$script:serviceRunning = $true
function Get-Service { param($Name, $ErrorAction) if ($script:serviceRunning) { [pscustomobject]@{ Status = 'Running' } } }
$ns = 'http://schemas.microsoft.com/win/2004/08/events/event'
function New-Record {
    param([long]$Id, [int]$EventId)
    $xml = "<Event xmlns='$ns'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>$EventId</EventID><EventRecordID>$Id</EventRecordID></System><EventData><Data Name='Image'>C:\Windows\System32\notepad.exe</Data></EventData></Event>"
    $item = [pscustomobject]@{ RecordId = $Id; Xml = $xml }
    $item | Add-Member ScriptMethod ToXml { $this.Xml }
    return $item
}
$script:logEnabled = $true
$script:records = @()
$script:queries = @()
function Get-WinEvent {
    param($LogName, $FilterXPath, $MaxEvents, $ListLog, $ErrorAction)
    if ($ListLog) { return [pscustomobject]@{ IsEnabled = $script:logEnabled } }
    $script:queries += $FilterXPath
    if ($FilterXPath -eq '*') { return @(New-Record 100 1) }
    if ($FilterXPath -match 'EventRecordID > (\d+)') {
        $base = [long]$Matches[1]
        # Newest first, like Get-WinEvent.
        return @($script:records | Where-Object { $_.RecordId -gt $base } | Sort-Object RecordId -Descending)
    }
    throw 'unexpected query'
}

# wevtutil export: write UTF-16 like `wevtutil qe /e:Events /uni:true`, oldest first.
$script:exportFails = $false
$script:exportExtra = ''
function Invoke-WorkbenchLogExport {
    param([long]$Baseline, [string]$Path)
    if ($script:exportFails) { throw 'SYSMON_LOG_UNREADABLE: export tool failed' }
    $script:queries += "export>$Baseline"
    $body = @($script:records | Where-Object { $_.RecordId -gt $Baseline } | Sort-Object RecordId | ForEach-Object { $_.Xml })
    $text = "<Events>`r`n" + (($body + @($script:exportExtra)) -join "`r`n") + "`r`n</Events>`r`n"
    [IO.File]::WriteAllText($Path, $text, [Text.Encoding]::Unicode)
}

$sha = ('a' * 64)
# -- argument validation ------------------------------------------------------
Assert-WorkbenchArguments -Work 'C:\WorkbenchRun\VMR-0001' -Run 'VMR-0001' -RunMode Scenario -Name 'registry-probe' -Timeout 60 -Settle 5
Assert-WorkbenchArguments -Work 'C:\WorkbenchRun\VMR-0001' -Run 'VMR-0001' -RunMode Sample -File $sha -Sha $sha -Timeout 10 -Settle 0
$script:checks += 2
Assert-Failure { Assert-WorkbenchArguments -Work 'C:\Other\VMR-0001' -Run 'VMR-0001' -RunMode Scenario -Name 'registry-probe' -Timeout 60 -Settle 5 } 'INVALID_ARGUMENTS'
Assert-Failure { Assert-WorkbenchArguments -Work 'C:\WorkbenchRun\x' -Run 'x' -RunMode Scenario -Name 'registry-probe' -Timeout 60 -Settle 5 } 'INVALID_ARGUMENTS'
Assert-Failure { Assert-WorkbenchArguments -Work 'C:\WorkbenchRun\VMR-0001' -Run 'VMR-0001' -RunMode Scenario -Name 'calc' -Timeout 60 -Settle 5 } 'INVALID_ARGUMENTS'
Assert-Failure { Assert-WorkbenchArguments -Work 'C:\WorkbenchRun\VMR-0001' -Run 'VMR-0001' -RunMode Scenario -Name 'registry-probe' -Timeout 5 -Settle 5 } 'INVALID_ARGUMENTS'
Assert-Failure { Assert-WorkbenchArguments -Work 'C:\WorkbenchRun\VMR-0001' -Run 'VMR-0001' -RunMode Sample -File 'evil.exe' -Sha $sha -Timeout 60 -Settle 5 } 'INVALID_ARGUMENTS'
Assert-Failure { Assert-WorkbenchArguments -Work 'C:\WorkbenchRun\VMR-0001' -Run 'VMR-0001' -RunMode Sample -File $sha -Sha $sha -Name 'registry-probe' -Timeout 60 -Settle 5 } 'INVALID_ARGUMENTS'

# -- exit codes and helpers -----------------------------------------------------
Assert-True ((Get-WorkbenchExitCode 'SAMPLE_HASH_MISMATCH: x') -eq 13) 'hash exit code'
Assert-True ((Get-WorkbenchExitCode 'SYSMON_NOT_RUNNING: x') -eq 11) 'sysmon exit code'
Assert-True ((Get-WorkbenchExitCode 'something else') -eq 1) 'default exit code'
$tree = @(Get-WorkbenchDescendants -RootId 4242 -Processes (Get-CimInstance -ClassName Win32_Process))
Assert-True (($tree -join ',') -eq '5000,5001') 'descendants only'
$script:stopped = @(); Stop-WorkbenchProcessTree -RootId 4242
Assert-True (($script:stopped -join ',') -eq '5001,5000,4242') 'tree stopped leaves first, unrelated kept'
Assert-True ((Get-WorkbenchBaseline) -eq 100) 'baseline'
$script:serviceRunning = $false
Assert-Failure { Assert-WorkbenchSysmon } 'SYSMON_NOT_RUNNING'
$script:serviceRunning = $true; $script:logEnabled = $false
Assert-Failure { Assert-WorkbenchSysmon } 'SYSMON_LOG_UNREADABLE'
$script:logEnabled = $true

$temp = Join-Path ([IO.Path]::GetTempPath()) ('wb-guest-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    # -- sample start: hash verified before launch ------------------------------
    $bytes = [Text.Encoding]::ASCII.GetBytes('harmless synthetic bytes')
    $real = (New-Object Security.Cryptography.SHA256Managed).ComputeHash($bytes)
    $realSha = -join ($real | ForEach-Object { $_.ToString('x2') })
    [IO.File]::WriteAllBytes((Join-Path $temp $realSha), $bytes)
    $script:started = @()
    $process = Start-WorkbenchTarget -RunMode Sample -Work $temp -File $realSha -Sha $realSha
    Assert-True ($process.Id -eq 4242) 'sample started'
    Assert-True ($script:started[0].FilePath -like '*target-*.exe') 'sample renamed to exe'
    [IO.File]::WriteAllBytes((Join-Path $temp $sha), $bytes)
    $script:started = @()
    Assert-Failure { Start-WorkbenchTarget -RunMode Sample -Work $temp -File $sha -Sha $sha } 'SAMPLE_HASH_MISMATCH'
    Assert-True ($script:started.Count -eq 0) 'mismatching sample never started'
    Assert-Failure { Start-WorkbenchTarget -RunMode Sample -Work $temp -File ('b' * 64) -Sha ('b' * 64) } 'SAMPLE_HASH_MISMATCH'

    # -- sealed sample (ADR-030): unsealed in the guest, then verified --------------
    $keySha = (New-Object Security.Cryptography.SHA256Managed).ComputeHash((Get-WorkbenchSealKey))
    Assert-True ((-join ($keySha | ForEach-Object { $_.ToString('x2') })) -eq '13f1ba9c1b791556b3fe221c9b9343c0e2374e05f078c2feb7ba6859491d664a') 'keystream matches the host'
    $sealedHex = '4c44575345414c31984027f1dfc0768d458a3043da100cd501531558ac3341d2'
    $sealed = [byte[]]@(for ($i = 0; $i -lt $sealedHex.Length; $i += 2) { [Convert]::ToByte($sealedHex.Substring($i, 2), 16) })
    [IO.File]::WriteAllBytes((Join-Path $temp $realSha), $sealed)
    Remove-Item -LiteralPath (Join-Path $temp ('target-' + $realSha.Substring(0, 12) + '.exe')) -Force
    $script:started = @()
    [void](Start-WorkbenchTarget -RunMode Sample -Work $temp -File $realSha -Sha $realSha)
    $restored = [IO.File]::ReadAllBytes($script:started[0].FilePath)
    Assert-True ([Text.Encoding]::ASCII.GetString($restored) -eq 'harmless synthetic bytes') 'sealed sample restored'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $temp $realSha))) 'sealed transfer removed'
    $sealed[10] = $sealed[10] -bxor 1
    [IO.File]::WriteAllBytes((Join-Path $temp $sha), $sealed)
    $script:started = @()
    Assert-Failure { Start-WorkbenchTarget -RunMode Sample -Work $temp -File $sha -Sha $sha } 'SAMPLE_HASH_MISMATCH'
    Assert-True ($script:started.Count -eq 0) 'tampered sealed sample never started'

    # -- scenario start uses a fixed encoded command ------------------------------
    $script:started = @()
    [void](Start-WorkbenchTarget -RunMode Scenario -Work $temp -Name 'registry-probe')
    $encoded = $script:started[0].Arguments[3]
    $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
    Assert-True ($decoded -eq $script:WorkbenchScenarios['registry-probe']) 'scenario command fixed'

    # -- full flow with the work-directory rule relaxed to the temp directory ----
    function Assert-WorkbenchArguments { param($Work, $Run, $RunMode, $File, $Sha, $Name, $Timeout, $Settle) }
    $script:records = @((New-Record 99 1), (New-Record 101 1), (New-Record 103 11), (New-Record 102 13))
    $script:exitEarly = $true; $script:stopped = @()
    $work = Join-Path $temp 'run1'
    [void][IO.Directory]::CreateDirectory($work)
    $result = Invoke-WorkbenchGuestRun -Work $work -Run 'VMR-0001' -RunMode Scenario -Name 'file-write' -Timeout 10 -Settle 0
    Assert-True ($result -eq 'collection: complete (3 events)') 'flow output'
    Assert-True ($script:stopped -contains 4242) 'tree stopped after run'
    $manifest = Get-Content -LiteralPath (Join-Path $work 'out\run-manifest.json') -Raw | ConvertFrom-Json
    $events = [IO.File]::ReadAllBytes((Join-Path $work 'out\events.xml'))
    Assert-True ($events[0] -eq [byte][char]'<') 'events.xml has no BOM'
    $digest = -join ((New-Object Security.Cryptography.SHA256Managed).ComputeHash($events) | ForEach-Object { $_.ToString('x2') })
    Assert-True ($manifest.events_sha256 -eq $digest) 'manifest hash'
    Assert-True ($manifest.event_count -eq 3 -and $manifest.baseline_record_id -eq 100) 'manifest counts'
    Assert-True ($manifest.run_id -eq 'VMR-0001' -and $manifest.mode -eq 'Scenario' -and $manifest.scenario -eq 'file-write') 'manifest identity'
    Assert-True ($manifest.process_outcome -eq 'exited' -and $null -eq $manifest.target_sha256) 'manifest outcome'
    $text = [Text.Encoding]::UTF8.GetString($events)
    Assert-True ($text.IndexOf('>101<') -lt $text.IndexOf('>102<') -and $text.IndexOf('>102<') -lt $text.IndexOf('>103<')) 'record order'
    Assert-True ($text -notmatch '>99<') 'pre-run events excluded'
    Assert-Failure { Invoke-WorkbenchGuestRun -Work $work -Run 'VMR-0001' -RunMode Scenario -Name 'file-write' -Timeout 10 -Settle 0 } 'OUTPUT_EXISTS'

    $script:exitEarly = $false
    $work2 = Join-Path $temp 'run2'
    [void][IO.Directory]::CreateDirectory($work2)
    [void](Invoke-WorkbenchGuestRun -Work $work2 -Run 'VMR-0002' -RunMode Scenario -Name 'dns-invalid' -Timeout 10 -Settle 0)
    $manifest = Get-Content -LiteralPath (Join-Path $work2 'out\run-manifest.json') -Raw | ConvertFrom-Json
    Assert-True ($manifest.process_outcome -eq 'timeout_killed') 'timeout outcome'
    # -- export edge cases --------------------------------------------------------
    $script:exitEarly = $true
    $script:records = @((New-Record 101 1))
    $script:records[0].Xml = $script:records[0].Xml.Replace('notepad.exe', ([string][char]0xD55C) + '.exe')
    $work3 = Join-Path $temp 'run3'
    [void][IO.Directory]::CreateDirectory($work3)
    [void](Invoke-WorkbenchGuestRun -Work $work3 -Run 'VMR-0003' -RunMode Scenario -Name 'file-write' -Timeout 10 -Settle 0)
    $text3 = [IO.File]::ReadAllText((Join-Path $work3 'out\events.xml'), [Text.Encoding]::UTF8)
    Assert-True ($text3.Contains(([string][char]0xD55C) + '.exe')) 'non-ASCII text survives export'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $work3 'out\events.export.tmp'))) 'raw export removed'
    $script:records = @()
    $work4 = Join-Path $temp 'run4'
    [void][IO.Directory]::CreateDirectory($work4)
    $result4 = Invoke-WorkbenchGuestRun -Work $work4 -Run 'VMR-0004' -RunMode Scenario -Name 'file-write' -Timeout 10 -Settle 0
    Assert-True ($result4 -eq 'collection: complete (0 events)') 'empty export'
    $script:exportExtra = '<!DOCTYPE x>'
    $work5 = Join-Path $temp 'run5'
    [void][IO.Directory]::CreateDirectory($work5)
    Assert-Failure { Invoke-WorkbenchGuestRun -Work $work5 -Run 'VMR-0005' -RunMode Scenario -Name 'file-write' -Timeout 10 -Settle 0 } 'EXPORT_FAILED'
    $script:exportExtra = ''
    $script:exportFails = $true
    $work6 = Join-Path $temp 'run6'
    [void][IO.Directory]::CreateDirectory($work6)
    Assert-Failure { Invoke-WorkbenchGuestRun -Work $work6 -Run 'VMR-0006' -RunMode Scenario -Name 'file-write' -Timeout 10 -Settle 0 } 'SYSMON_LOG_UNREADABLE'
    $script:exportFails = $false
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
Write-Output "Test-WorkbenchGuestRun: $script:checks checks passed"
