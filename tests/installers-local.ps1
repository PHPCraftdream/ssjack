param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$Fixture,
    [Parameter(Mandatory = $true)][string]$Directory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$localDirectory = Join-Path $Directory 'local-candidate'
& $Installer -CandidatePath $Fixture -SHA256 (Hash $Fixture) -InstallDir $localDirectory -NoPathUpdate
Assert ((Hash (Join-Path $localDirectory 'ssjack.exe')) -eq (Hash $Fixture)) 'Local installation failed.'
Remove-Item -LiteralPath $env:SSJACK_INSTALL_TEST_MARKER -Force -ErrorAction SilentlyContinue
$rejected = $false
try {
    & $Installer -CandidatePath $Fixture -SHA256 ('0' * 64) -InstallDir (Join-Path $Directory 'bad-local') -NoPathUpdate
} catch { $rejected = $true }
Assert $rejected 'Local candidate checksum mismatch was accepted.'
Assert (-not (Test-Path -LiteralPath $env:SSJACK_INSTALL_TEST_MARKER)) 'Unverified local candidate was executed.'

$lockedBackup = Join-Path $localDirectory 'ssjack.previous-20260101T010203004Z-0123456789abcdef0123456789abcdef.exe'
[IO.File]::WriteAllText($lockedBackup, 'locked previous fixture')
$foreign = Join-Path $localDirectory 'ssjack.previous-user-owned.exe'
[IO.File]::WriteAllText($foreign, 'not owned by installer')
$busy = [IO.File]::Open($lockedBackup, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    & $Installer -CandidatePath $Fixture -SHA256 (Hash $Fixture) -InstallDir $localDirectory -NoPathUpdate
    Assert ([IO.File]::Exists($lockedBackup)) 'Locked previous file was removed.'
} finally { $busy.Dispose() }
& $Installer -CandidatePath $Fixture -SHA256 (Hash $Fixture) -InstallDir $localDirectory -NoPathUpdate
Assert (-not [IO.File]::Exists($lockedBackup)) 'Unlocked previous file was not cleaned on repeat install.'
Assert ([IO.File]::Exists($foreign)) 'Foreign backup-like file was removed.'

$activeDirectory = Join-Path $Directory 'active-executable'
[IO.Directory]::CreateDirectory($activeDirectory) | Out-Null
$activeTarget = Join-Path $activeDirectory 'ssjack.exe'
[IO.File]::Copy($Fixture, $activeTarget)
[IO.File]::AppendAllText($activeTarget, 'previous fixture overlay')
$activeHash = Hash $activeTarget
$held = [Diagnostics.Process]::new()
$held.StartInfo.FileName = $activeTarget
$held.StartInfo.Arguments = '--hold'
$held.StartInfo.UseShellExecute = $false
$held.StartInfo.RedirectStandardInput = $true
$held.StartInfo.RedirectStandardOutput = $true
$started = $false
try {
    $started = $held.Start()
    Assert $started 'Could not start active executable fixture.'
    $ready = $held.StandardOutput.ReadLineAsync()
    Assert ($ready.Wait(10000)) 'Active fixture did not become ready.'
    Assert ($ready.Result -eq 'ready') 'Unexpected active fixture readiness.'
    & $Installer -CandidatePath $Fixture -SHA256 (Hash $Fixture) -InstallDir $activeDirectory -NoPathUpdate
    Assert (-not $held.HasExited) 'Installer stopped a running executable.'
    $backups = @(Get-ChildItem -LiteralPath $activeDirectory -Filter 'ssjack.previous-*.exe')
    Assert ($backups.Count -eq 1) 'Running previous image was not retained.'
    Assert ((Hash $backups[0].FullName) -eq $activeHash) 'Running image bytes changed.'
} finally {
    if ($started) {
        $held.StandardInput.Close()
        if (-not $held.WaitForExit(10000)) {
            $held.Kill()
            $held.WaitForExit()
        }
    }
    $held.Dispose()
}
& $Installer -CandidatePath $Fixture -SHA256 (Hash $Fixture) -InstallDir $activeDirectory -NoPathUpdate
Assert (@(Get-ChildItem -LiteralPath $activeDirectory -Filter 'ssjack.previous-*.exe').Count -eq 0) 'Exited previous image was not cleaned.'
