param([string]$CandidatePath = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$build = Join-Path $PSScriptRoot 'build'
$target = Join-Path $build 'ssjack.exe'
if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
    $CandidatePath = Join-Path $build 'ui-next\ssjack.exe'
}
$CandidatePath = [IO.Path]::GetFullPath($CandidatePath)
if (-not [IO.File]::Exists($target)) { throw 'The development installation does not exist.' }
if ([string]::Equals($CandidatePath, [IO.Path]::GetFullPath($target), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Candidate and installed executable must differ.'
}
$expected = (Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
& (Join-Path $PSScriptRoot 'install.ps1') -CandidatePath $CandidatePath -SHA256 $expected -InstallDir $build -NoPathUpdate
