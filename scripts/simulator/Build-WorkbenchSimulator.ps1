#requires -Version 5.1
<#
.SYNOPSIS
Build the benign Workbench simulator with the C# compiler that ships with
.NET Framework 4.x (ADR-028). Compiles only; never runs the result.
.DESCRIPTION
Output: build\simulator\workbench-simulator.exe (git-ignored). Prints the
SHA-256 so the binary can be matched with the sample Artifact registered from
it. The legacy compiler embeds a build timestamp, so every build has a new
hash; register exactly the file you built.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = ''
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'build\simulator' }
$source = Join-Path $repo 'tools\simulator\WorkbenchSimulator.cs'
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
    throw '.NET Framework 4.x C# compiler (csc.exe) was not found'
}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$output = Join-Path $OutputDirectory 'workbench-simulator.exe'
$arguments = @('/nologo', '/target:exe', '/platform:x64', '/optimize+', '/langversion:5',
    '/warnaserror+', "/out:$output", $source)
& $csc @arguments
if ($LASTEXITCODE -ne 0) { throw "csc.exe failed with exit code $LASTEXITCODE" }
$hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "built: $output"
Write-Output "sha256: $hash"
