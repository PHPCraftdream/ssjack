param(
    [string]$InstallDir = '',
    [switch]$NoPathUpdate,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Help) {
    Write-Output 'Usage: .\build.ps1 [-InstallDir ABSOLUTE_DIRECTORY] [-NoPathUpdate]'
    Write-Output 'Build this checkout for native Windows and install on the user PATH.'
    Write-Output 'Default: LOCALAPPDATA\Programs\ssjack\bin. Requires Git and Go from go.mod.'
    Write-Output 'Never elevates, stops running processes or migrates credentials.'
    return
}
if ($env:OS -ne 'Windows_NT') { throw 'build.ps1 supports Windows; use build.sh on Linux/macOS.' }
if ($args.Count -ne 0) { throw 'Unknown build arguments. Use -Help.' }
if ($InstallDir -ne '' -and (-not [IO.Path]::IsPathRooted($InstallDir) -or
    [IO.Path]::GetPathRoot($InstallDir).Length -lt 3)) {
    throw 'The installation directory must be absolute, not drive-relative.'
}
$architecture = $env:PROCESSOR_ARCHITEW6432
if (-not $architecture) { $architecture = $env:PROCESSOR_ARCHITECTURE }
switch ($architecture.ToUpperInvariant()) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw 'Unsupported CPU architecture; expected AMD64 or ARM64.' }
}
$root = $PSScriptRoot
$installer = Join-Path $root 'install.ps1'
if (!(Test-Path -LiteralPath (Join-Path $root 'go.mod') -PathType Leaf) -or
    !(Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw 'Run the script from a complete ssjack source checkout.'
}
$git = (Get-Command git -CommandType Application -ErrorAction Stop).Source
$go = (Get-Command go -CommandType Application -ErrorAction Stop).Source
$revision = (& $git -C $root rev-parse --verify HEAD) -join ''
if ($LASTEXITCODE -ne 0 -or $revision -cnotmatch '^[0-9a-f]{40}$') {
    throw 'Cannot identify the checkout commit.'
}
$changes = @(& $git -C $root status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect source status.' }
if ($changes.Count -ne 0) { $revision += '-dirty' }
$stage = Join-Path ([IO.Path]::GetTempPath()) ('ssjack-source-build-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stage) | Out-Null
$candidate = Join-Path $stage 'ssjack.exe'
$names = @('GOOS', 'GOARCH', 'CGO_ENABLED', 'GOTOOLCHAIN', 'GOWORK', 'GOFLAGS')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:GOOS = 'windows'
    $env:GOARCH = $arch
    $env:CGO_ENABLED = '0'
    $env:GOTOOLCHAIN = 'local'
    $env:GOWORK = 'off'
    $env:GOFLAGS = ''
    Push-Location -LiteralPath $root
    try {
        Write-Host "Building ssjack for windows/$arch from $revision"
        & $go build -mod=readonly -trimpath -buildvcs=true `
            -ldflags "-X github.com/PHPCraftdream/ssjack/internal/buildinfo.Commit=$revision" `
            -o $candidate ./cmd/ssjack
        if ($LASTEXITCODE -ne 0) { throw 'Build failed; installation was not started.' }
    } finally {
        Pop-Location
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    }
    $digest = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    & $installer -CandidatePath $candidate -SHA256 $digest -InstallDir $InstallDir -NoPathUpdate:$NoPathUpdate
    Write-Host "Built and installed checkout $revision. No process was stopped; no database was changed."
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { [IO.File]::Delete($candidate) }
    [IO.Directory]::Delete($stage, $false)
}
