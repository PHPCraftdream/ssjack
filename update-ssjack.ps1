param([string]$CandidatePath = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ExeHash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular file: $Path"
    }
}

function Assert-Ssjack([string]$Path) {
    $savedPreference = $ErrorActionPreference
    try {
        # Windows PowerShell treats native stderr as ErrorRecord objects.
        $ErrorActionPreference = 'Continue'
        $help = @(& $Path --help 2>&1)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    $text = ($help | ForEach-Object { $_.ToString() }) -join "`n"
    if ($code -ne 0 -or $text -notlike '*Usage: ssjack *') {
        throw 'Candidate failed the ssjack --help check.'
    }
}

$build = Join-Path $PSScriptRoot 'build'
$target = Join-Path $build 'ssjack.exe'
if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
    $CandidatePath = Join-Path $build 'ui-next\ssjack.exe'
}
$stage = $null
$backup = $null
$lock = $null
$oldMoved = $false
$newInstalled = $false
$committed = $false

try {
    $CandidatePath = [IO.Path]::GetFullPath($CandidatePath)
    $target = [IO.Path]::GetFullPath($target)
    if ([string]::Equals($CandidatePath, $target, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Candidate and installed executable must be different files.'
    }
    Assert-RegularFile $CandidatePath
    Assert-RegularFile $target
    $buildInfo = Get-Item -LiteralPath $build -Force
    if (($buildInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The build directory must not be a reparse point.'
    }
    $lock = [IO.File]::Open((Join-Path $build '.ssjack-update.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $expectedHash = Get-ExeHash $CandidatePath
    $oldHash = Get-ExeHash $target
    if ($expectedHash -eq $oldHash) {
        Write-Host "Already up to date: $target"
        Write-Host "SHA256: $expectedHash"
        exit 0
    }

    $tag = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N')
    $stage = Join-Path $build ('.ssjack-update-' + $tag + '.exe')
    $backup = Join-Path $build ('ssjack.previous-' + $tag + '.exe')
    [IO.File]::Copy($CandidatePath, $stage, $false)
    if ((Get-ExeHash $stage) -ne $expectedHash) { throw 'Staged executable hash mismatch.' }
    Assert-Ssjack $stage
    if ((Get-ExeHash $stage) -ne $expectedHash) { throw 'Staged executable changed during verification.' }

    # Renaming preserves the image used by an already running process.
    [IO.File]::Move($target, $backup)
    $oldMoved = $true
    [IO.File]::Move($stage, $target)
    $newInstalled = $true
    if ((Get-ExeHash $target) -ne $expectedHash) { throw 'Installed executable hash mismatch.' }
    Assert-Ssjack $target
    $committed = $true

    Write-Host "Updated: $target"
    Write-Host "Previous executable: $backup"
    Write-Host "Previous SHA256: $oldHash"
    Write-Host "Installed SHA256: $expectedHash"
    Write-Host 'No process was stopped. Restart ssjack to use the installed version.'
    exit 0
} catch {
    $failure = $_.Exception.Message
    if ($oldMoved -and -not $committed) {
        try {
            if ($newInstalled -and [IO.File]::Exists($target)) {
                $failed = $target + '.failed-' + [Guid]::NewGuid().ToString('N') + '.exe'
                [IO.File]::Move($target, $failed)
                [Console]::Error.WriteLine("Failed candidate preserved: $failed")
            }
            if ([IO.File]::Exists($target)) { throw 'The original target path is occupied; refusing to overwrite it.' }
            [IO.File]::Move($backup, $target)
            [Console]::Error.WriteLine('Previous executable restored.')
        } catch {
            [Console]::Error.WriteLine("Rollback failed: $($_.Exception.Message)")
            [Console]::Error.WriteLine("Previous executable remains at: $backup")
        }
    }
    [Console]::Error.WriteLine("Update failed: $failure")
    exit 1
} finally {
    if ($stage -and [IO.File]::Exists($stage)) {
        Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $lock) { $lock.Dispose() }
}
