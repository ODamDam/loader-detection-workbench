[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repositoryRoot '.demo\ui-readiness'
}
$outputPath = [IO.Path]::GetFullPath($OutputRoot)

if (Test-Path -LiteralPath $outputPath) {
    throw "Demo output already exists. Choose a new -OutputRoot or move the existing demo safely."
}

$projectPath = Join-Path $outputPath 'project'
$inputPath = Join-Path $outputPath 'inputs'
$pePath = Join-Path $inputPath 'benign-minimal.exe'
$notePath = Join-Path $inputPath 'analyst-note.txt'
$sysmonPath = Join-Path $repositoryRoot 'tests\fixtures\public\sysmon'

New-Item -ItemType Directory -Path $inputPath | Out-Null

# Header-only synthetic PE fixture. It is never executed.
[byte[]]$bytes = New-Object byte[] 516
$bytes[0] = 0x4d
$bytes[1] = 0x5a
[BitConverter]::GetBytes([uint32]0x80).CopyTo($bytes, 0x3c)
[byte[]](0x50, 0x45, 0, 0) | ForEach-Object -Begin { $index = 0x80 } -Process {
    $bytes[$index++] = $_
}
[BitConverter]::GetBytes([uint16]0x8664).CopyTo($bytes, 0x84)
[BitConverter]::GetBytes([uint16]1).CopyTo($bytes, 0x86)
[BitConverter]::GetBytes([uint16]0xf0).CopyTo($bytes, 0x94)
[BitConverter]::GetBytes([uint16]0x2022).CopyTo($bytes, 0x96)
[BitConverter]::GetBytes([uint16]0x20b).CopyTo($bytes, 0x98)
[Text.Encoding]::ASCII.GetBytes('.text').CopyTo($bytes, 0x188)
[BitConverter]::GetBytes([uint32]4).CopyTo($bytes, 0x190)
[BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, 0x194)
[BitConverter]::GetBytes([uint32]4).CopyTo($bytes, 0x198)
[BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes, 0x19c)
[BitConverter]::GetBytes([uint32]0x60000020).CopyTo($bytes, 0x1ac)
[Text.Encoding]::ASCII.GetBytes('SAFE').CopyTo($bytes, 0x200)
[IO.File]::WriteAllBytes($pePath, $bytes)
[IO.File]::WriteAllText(
    $notePath,
    'Sanitized analyst note for the local UI demonstration.',
    [Text.Encoding]::UTF8
)

function Invoke-Workbench {
    param([Parameter(Mandatory)][string[]]$CommandArguments)

    & uv run --project $repositoryRoot workbench @CommandArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Workbench command failed with exit code $LASTEXITCODE."
    }
}

Invoke-Workbench @('project', 'create', $projectPath, '--name', 'UI Demo Project')
Push-Location $projectPath
try {
    Invoke-Workbench @(
        'case', 'create', '--name', 'Benign relationship demo', '--kind', 'benign',
        '--description', 'Sanitized intermediate-report fixture'
    )
    Invoke-Workbench @(
        'case', 'create', '--name', 'Empty state demo', '--kind', 'benign',
        '--description', 'No Artifacts are attached to this Case'
    )
    Invoke-Workbench @(
        'case', 'artifact', 'add', 'CASE-0001', $pePath, '--kind', 'sample'
    )
    Invoke-Workbench @('case', 'static', 'analyze', 'CASE-0001', 'ART-000001')
    Invoke-Workbench @('case', 'collection', 'import', 'CASE-0001', $sysmonPath)
    Invoke-Workbench @(
        'report', 'build', 'CASE-0001', 'reports/CASE-0001.md'
    )
}
finally {
    Pop-Location
}

Write-Output ''
Write-Output 'Demo preparation complete.'
Write-Output "Project: $projectPath"
Write-Output "Upload during demo: $notePath"
Write-Output "Markdown report: $(Join-Path $projectPath 'reports\CASE-0001.md')"
Write-Output "Start UI: uv run workbench ui serve `"$projectPath`" --port 8080"
