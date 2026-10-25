param([Parameter(Mandatory = $true)][string]$Fixture)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installer = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\install.ps1'))
$Fixture = [IO.Path]::GetFullPath($Fixture)
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('ssjack-installer-test-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporary) | Out-Null
$script:FixtureMode = 'good'
$script:Requests = 0
$env:SSJACK_INSTALL_TEST_MARKER = Join-Path $temporary 'executed'
$originalUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Hash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-FixtureResponse([uri]$Uri) {
    $script:Requests++
    if ($script:FixtureMode -eq 'download-error') { throw 'intentional download failure' }
    $reply = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
    if ($script:FixtureMode -eq 'redirect-http' -or ($script:FixtureMode -eq 'redirect-good' -and $Uri.Host -ne 'fixture.invalid')) {
        $reply.StatusCode = [Net.HttpStatusCode]::Found
        $scheme = 'https'
        if ($script:FixtureMode -eq 'redirect-http') { $scheme = 'http' }
        $reply.Headers.Location = [uri]("${scheme}://fixture.invalid/" + [IO.Path]::GetFileName($Uri.AbsolutePath))
        return $reply
    }
    if ($Uri.AbsolutePath -like '*/releases/latest') {
        $data = [Text.Encoding]::UTF8.GetBytes('{"tag_name":"v0.0.0-test"}')
    } elseif ($Uri.AbsolutePath -like '*/SHA256SUMS') {
        $architecture = $env:PROCESSOR_ARCHITEW6432
        if (-not $architecture) { $architecture = $env:PROCESSOR_ARCHITECTURE }
        switch ($architecture.ToUpperInvariant()) {
            'AMD64' { $arch = 'amd64' }
            'ARM64' { $arch = 'arm64' }
            default { throw 'unsupported test CPU' }
        }
        $value = Hash $Fixture
        if ($script:FixtureMode -eq 'badsum') { $value = '0' * 64 }
        $name = "ssjack_windows_$arch.exe"
        if ($script:FixtureMode -eq 'missing') { $name = 'other-file' }
        $line = "$value  $name`n"
        if ($script:FixtureMode -eq 'duplicate') { $line += $line }
        $data = [Text.Encoding]::ASCII.GetBytes($line)
    } else {
        $data = [IO.File]::ReadAllBytes($Fixture)
    }
    $reply.Content = [Net.Http.ByteArrayContent]::new([byte[]]$data)
    return $reply
}

function New-Object {
    [CmdletBinding()]
    param([string]$TypeName, [object[]]$ArgumentList)
    if ($TypeName -cne 'System.Net.Http.HttpClient') {
        return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
    }
    $headers = [Net.Http.HttpRequestMessage]::new().Headers
    $mock = [pscustomobject]@{ DefaultRequestHeaders = $headers }
    $mock | Add-Member ScriptMethod GetAsync {
        param($Uri, $Completion, $Token)
        $result = Get-FixtureResponse $Uri
        $task = [Threading.Tasks.TaskCompletionSource[Net.Http.HttpResponseMessage]]::new()
        $task.SetResult($result)
        return $task.Task
    }
    $mock | Add-Member ScriptMethod Dispose { }
    return $mock
}

function Install([string]$Directory, [switch]$Latest) {
    if ($Latest) {
        & $installer -InstallDir $Directory -NoPathUpdate
    } else {
        & $installer -Version 'v0.0.0-test' -InstallDir $Directory -NoPathUpdate
    }
}

try {
    $fresh = Join-Path $temporary 'fresh install'
    Install $fresh
    $target = Join-Path $fresh 'ssjack.exe'
    Assert ((Hash $target) -eq (Hash $Fixture)) 'Fresh installation hash mismatch.'
    Install $fresh
    Assert (@(Get-ChildItem -LiteralPath $fresh -Filter 'ssjack.previous-*.exe').Count -eq 0) 'Repeat installation created a backup.'

    $update = Join-Path $temporary 'update'
    [IO.Directory]::CreateDirectory($update) | Out-Null
    $target = Join-Path $update 'ssjack.exe'
    [IO.File]::WriteAllText($target, 'previous executable')
    $before = Hash $target
    Install $update
    $backups = @(Get-ChildItem -LiteralPath $update -Filter 'ssjack.previous-*.exe')
    Assert ($backups.Count -eq 1) 'Update did not retain exactly one backup.'
    Assert ((Hash $backups[0].FullName) -eq $before) 'Backup bytes changed.'

    foreach ($mode in @('badsum', 'duplicate', 'missing', 'download-error', 'redirect-http')) {
        $destination = Join-Path $temporary $mode
        [IO.Directory]::CreateDirectory($destination) | Out-Null
        $target = Join-Path $destination 'ssjack.exe'
        [IO.File]::WriteAllText($target, 'previous executable')
        $before = Hash $target
        Remove-Item -LiteralPath $env:SSJACK_INSTALL_TEST_MARKER -Force -ErrorAction SilentlyContinue
        $script:FixtureMode = $mode
        $rejected = $false
        try { Install $destination } catch { $rejected = $true }
        Assert $rejected "Expected failure: $mode"
        Assert ((Hash $target) -eq $before) 'Failed download changed the old executable.'
        Assert (-not (Test-Path -LiteralPath $env:SSJACK_INSTALL_TEST_MARKER)) 'Unverified candidate was executed.'
    }
    $script:FixtureMode = 'good'
    $rollback = Join-Path $temporary 'rollback'
    [IO.Directory]::CreateDirectory($rollback) | Out-Null
    $target = Join-Path $rollback 'ssjack.exe'
    [IO.File]::WriteAllText($target, 'previous executable')
    $before = Hash $target
    $env:SSJACK_INSTALL_TEST_FAIL_INSTALLED = '1'
    $rejected = $false
    try { Install $rollback } catch { $rejected = $true }
    $env:SSJACK_INSTALL_TEST_FAIL_INSTALLED = $null
    Assert $rejected 'Expected installed-path probe failure.'
    Assert ((Hash $target) -eq $before) 'Rollback did not restore the previous executable.'
    Assert (@(Get-ChildItem -LiteralPath $rollback -Filter 'ssjack.failed-*.exe').Count -eq 1) 'Failed candidate was not retained.'

    $script:FixtureMode = 'redirect-good'
    Install (Join-Path $temporary 'https-redirect')
    $script:FixtureMode = 'good'
    $latest = Join-Path $temporary 'latest'
    Install $latest -Latest
    Assert ((Hash (Join-Path $latest 'ssjack.exe')) -eq (Hash $Fixture)) 'Latest release fixture was not installed.'

    $beforeRequests = $script:Requests
    $originalArch = $env:PROCESSOR_ARCHITECTURE
    $originalWowArch = $env:PROCESSOR_ARCHITEW6432
    try {
        $env:PROCESSOR_ARCHITECTURE = 'unsupported-test-cpu'
        $env:PROCESSOR_ARCHITEW6432 = $null
        $rejected = $false
        try { Install (Join-Path $temporary 'unsupported') } catch { $rejected = $true }
        Assert $rejected 'Unsupported CPU was accepted.'
        Assert ($script:Requests -eq $beforeRequests) 'Unsupported CPU triggered a download.'
    } finally {
        $env:PROCESSOR_ARCHITECTURE = $originalArch
        $env:PROCESSOR_ARCHITEW6432 = $originalWowArch
    }
    Assert ([Environment]::GetEnvironmentVariable('Path', 'User') -ceq $originalUserPath) 'Tests changed the persistent user PATH.'
    Write-Host 'Installer tests passed without live downloads or global installation.'
} finally {
    $env:SSJACK_INSTALL_TEST_FAIL_INSTALLED = $null
    $env:SSJACK_INSTALL_TEST_MARKER = $null
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
