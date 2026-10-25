param(
    [string]$Version = '',
    [string]$InstallDir = '',
    [switch]$NoPathUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = 'PHPCraftdream/ssjack'

function Assert-RegularFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Expected a regular file: $Path"
    }
}

function Get-Hash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ReleaseFile([string]$Uri, [string]$OutFile = '') {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    if ($handler.PSObject.Properties['SslProtocols']) {
        $handler.SslProtocols = [Security.Authentication.SslProtocols]::Tls12
    }
    $client = $null
    $timeout = [Threading.CancellationTokenSource]::new()
    $timeout.CancelAfter(180000)
    try {
        $client = New-Object -TypeName 'System.Net.Http.HttpClient' -ArgumentList $handler
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('ssjack-installer')
        $limit = 134217728
        if ($OutFile -eq '' -or [IO.Path]::GetFileName($OutFile) -eq 'SHA256SUMS') { $limit = 65536 }
        for ($redirect = 0; $redirect -le 5; $redirect++) {
            $address = [uri]$Uri
            if (-not $address.IsAbsoluteUri -or $address.Scheme -cne 'https') {
                throw 'Only HTTPS downloads and redirects are allowed.'
            }
            $reply = $client.GetAsync($address, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $timeout.Token).GetAwaiter().GetResult()
            try {
                if ([int]$reply.StatusCode -in @(301, 302, 303, 307, 308)) {
                    if (-not $reply.Headers.Location) { throw 'Redirect response has no location.' }
                    $Uri = [uri]::new($address, $reply.Headers.Location).AbsoluteUri
                    continue
                }
                $reply.EnsureSuccessStatusCode() | Out-Null
                $length = $reply.Content.Headers.ContentLength
                if ($null -ne $length -and $length -gt $limit) { throw 'Release response is too large.' }
                $inputStream = $reply.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $outputStream = $null
                try {
                    if ($OutFile -eq '') { $outputStream = [IO.MemoryStream]::new() }
                    else { $outputStream = [IO.File]::Create($OutFile) }
                    $buffer = [byte[]]::new(65536)
                    $total = 0L
                    while ($true) {
                        $count = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $timeout.Token).GetAwaiter().GetResult()
                        if ($count -eq 0) { break }
                        $total += $count
                        if ($total -gt $limit) { throw 'Release response is too large.' }
                        $outputStream.Write($buffer, 0, $count)
                    }
                    if ($OutFile -eq '') {
                        return [pscustomobject]@{ Content = [Text.Encoding]::UTF8.GetString($outputStream.ToArray()) }
                    }
                    $outputStream.Flush()
                    return
                } finally {
                    if ($outputStream) { $outputStream.Dispose() }
                    $inputStream.Dispose()
                }
            } finally {
                $reply.Dispose()
            }
        }
        throw 'Too many release download redirects.'
    } finally {
        if ($client) { $client.Dispose() }
        $handler.Dispose()
        $timeout.Dispose()
    }
}

function Assert-Ssjack([string]$Path) {
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $help = @(& $Path --help 2>&1)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    $text = ($help | ForEach-Object { $_.ToString() }) -join "`n"
    if ($code -ne 0 -or $text -notlike '*Usage: ssjack *') {
        throw 'The verified binary failed the ssjack --help check.'
    }
}

function Add-UserPath([string]$Directory) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) { $entries = @($userPath -split ';') }
    $found = $false
    foreach ($entry in $entries) {
        if ([string]::Equals($entry.TrimEnd('\', '/'), $Directory.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
            $found = $true
        }
    }
    if (-not $found) {
        $updated = $Directory
        if ($userPath) { $updated = $userPath.TrimEnd(';') + ';' + $Directory }
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    }
    $current = @($env:Path -split ';')
    if (-not ($current | Where-Object { [string]::Equals($_.TrimEnd('\', '/'), $Directory.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase) })) {
        $env:Path = $Directory + ';' + $env:Path
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'install.ps1 supports Windows; use install.sh on Linux or macOS.' }
$architecture = $env:PROCESSOR_ARCHITEW6432
if (-not $architecture) { $architecture = $env:PROCESSOR_ARCHITECTURE }
switch ($architecture.ToUpperInvariant()) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw 'Unsupported CPU architecture; expected AMD64 or ARM64.' }
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is required for the default installation directory.' }
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\ssjack\bin'
}
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
if ($InstallDir.IndexOfAny([char[]]";`r`n") -ge 0) { throw 'The installation directory cannot contain semicolons or line breaks.' }
$target = Join-Path $InstallDir 'ssjack.exe'
$lock = $null
$stage = $null
$candidate = $null
$manifest = $null
$backup = $null
$failed = $null
$oldMoved = $false
$newInstalled = $false
$committed = $false
$oldProtocol = [Net.ServicePointManager]::SecurityProtocol

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $response = Get-ReleaseFile "https://api.github.com/repos/$repository/releases/latest"
        if ($response.Content.Length -gt 65536) { throw 'Release metadata is too large.' }
        $Version = [string](($response.Content | ConvertFrom-Json).tag_name)
    }
    if ($Version -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?$') {
        throw 'Invalid version tag.'
    }
    if (Test-Path -LiteralPath $InstallDir) {
        $directory = Get-Item -LiteralPath $InstallDir -Force
        if (-not $directory.PSIsContainer -or (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'The installation directory must be a regular directory, not a reparse point.'
        }
    } else {
        [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    }
    if (Test-Path -LiteralPath $target) { Assert-RegularFile $target }
    $lockPath = Join-Path $InstallDir '.ssjack-install.lock'
    if (Test-Path -LiteralPath $lockPath) { Assert-RegularFile $lockPath }
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $tag = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N')
    $stage = Join-Path $InstallDir ('.ssjack-install-' + $tag)
    if (Test-Path -LiteralPath $stage) { throw 'Staging directory already exists.' }
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $candidate = Join-Path $stage 'ssjack.exe'
    $manifest = Join-Path $stage 'SHA256SUMS'
    $asset = "ssjack_windows_$arch.exe"
    $base = "https://github.com/$repository/releases/download/$Version"
    Get-ReleaseFile "$base/$asset" $candidate | Out-Null
    Get-ReleaseFile "$base/SHA256SUMS" $manifest | Out-Null
    Assert-RegularFile $candidate
    Assert-RegularFile $manifest
    if ((Get-Item -LiteralPath $candidate).Length -gt 134217728 -or (Get-Item -LiteralPath $manifest).Length -gt 65536) {
        throw 'Downloaded binary or checksum manifest is too large.'
    }
    $checksums = @()
    foreach ($line in [IO.File]::ReadAllLines($manifest)) {
        $parts = @($line.Trim() -split '\s+')
        if ($parts.Length -eq 2 -and ($parts[1] -replace '^\*', '') -ceq $asset) {
            $checksums += $parts[0]
        }
    }
    if ($checksums.Count -ne 1 -or $checksums[0] -cnotmatch '^[0-9A-Fa-f]{64}$') {
        throw 'The checksum manifest must contain exactly one valid entry for this binary.'
    }
    $expected = $checksums[0].ToLowerInvariant()
    if ((Get-Hash $candidate) -ne $expected) { throw 'SHA-256 mismatch; refusing to execute or install the download.' }
    Assert-Ssjack $candidate
    if ((Get-Hash $candidate) -ne $expected) { throw 'Candidate changed during verification.' }
    if ([IO.File]::Exists($target) -and (Get-Hash $target) -eq $expected) {
        $committed = $true
        Write-Host "Already installed: $target ($Version)"
    } else {
        $backup = Join-Path $InstallDir ('ssjack.previous-' + $tag + '.exe')
        $failed = Join-Path $InstallDir ('ssjack.failed-' + $tag + '.exe')
        if ([IO.File]::Exists($target)) {
            [IO.File]::Move($target, $backup)
            $oldMoved = $true
        }
        [IO.File]::Move($candidate, $target)
        $newInstalled = $true
        if ((Get-Hash $target) -ne $expected) { throw 'Installed executable hash mismatch.' }
        Assert-Ssjack $target
        $committed = $true
        Write-Host "Installed: $target"
        Write-Host "Version: $Version"
        Write-Host "SHA256: $expected"
        if ($oldMoved) { Write-Host "Previous executable retained: $backup" }
    }
    if (-not $NoPathUpdate) { Add-UserPath $InstallDir }
    Write-Host 'No process was stopped. Restart ssjack to use the installed executable.'
} catch {
    $failure = $_.Exception.Message
    if (-not $committed) {
        try {
            if ($newInstalled -and [IO.File]::Exists($target)) {
                [IO.File]::Move($target, $failed)
                [Console]::Error.WriteLine("Failed candidate retained: $failed")
            }
            if ($oldMoved) {
                if (Test-Path -LiteralPath $target) { throw 'The original path is occupied; refusing to overwrite it.' }
                [IO.File]::Move($backup, $target)
                [Console]::Error.WriteLine('Previous executable restored.')
            }
        } catch {
            [Console]::Error.WriteLine("Rollback failed: $($_.Exception.Message)")
            [Console]::Error.WriteLine("Previous executable remains at: $backup")
        }
    } else {
        [Console]::Error.WriteLine('The executable is installed, but finalization failed.')
    }
    throw $failure
} finally {
    [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
    if ($lock) { $lock.Dispose() }
    if ($stage) {
        foreach ($file in @($candidate, $manifest)) {
            if ($file -and [IO.File]::Exists($file)) {
                Remove-Item -LiteralPath $file -Force -ErrorAction Continue
            }
        }
        if ([IO.Directory]::Exists($stage)) {
            try { [IO.Directory]::Delete($stage, $false) } catch { [Console]::Error.WriteLine("Staging directory retained: $stage") }
        }
    }
}
