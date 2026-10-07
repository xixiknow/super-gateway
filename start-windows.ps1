#requires -Version 5.1
<#
Start the local Windows gateway, including its private PostgreSQL cluster.
  .\start-windows.cmd             Build the latest UI/backend, then start.
  .\start-windows.cmd -SkipBuild  Start the previously built executable.
  .\start-windows.cmd -Check      Check prerequisites only.
  .\start-windows.cmd -ProxyUrl http://127.0.0.1:7890  Use an explicit proxy.
Without -ProxyUrl, use GATEWAY_PUBLIC_HTTP_PROXY, HTTPS_PROXY, ALL_PROXY,
or HTTP_PROXY (in that order). A proxy is required for this local launcher.
PostgreSQL 16+ is required. Builds also require Rust MSVC, Visual Studio C++
Build Tools, CMake, LLVM/libclang, and Node.js 20.19+ or 22.12+.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$Check,
    [string]$ProxyUrl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Push-Location -LiteralPath $PSScriptRoot
try {
    $env:CARGO_TARGET_DIR = Join-Path $PSScriptRoot 'target'
    $env:GATEWAY_LOCAL_STATE_DIR = Join-Path $PSScriptRoot '.super-gateway-local'
    $binary = Join-Path $env:CARGO_TARGET_DIR 'debug\super-gatewayd.exe'

    # Public model discovery uses the same proxy as local command-line tools.
    if (-not $ProxyUrl) {
        foreach ($name in @('GATEWAY_PUBLIC_HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'HTTP_PROXY')) {
            $candidate = [Environment]::GetEnvironmentVariable($name)
            if ($candidate) { $ProxyUrl = $candidate; break }
        }
    }
    if (-not $ProxyUrl) {
        throw 'Set HTTPS_PROXY or pass -ProxyUrl http://HOST:PORT for public model discovery.'
    }
    $proxyUri = $null
    if (-not [Uri]::TryCreate($ProxyUrl, [UriKind]::Absolute, [ref]$proxyUri) -or
        $proxyUri.Scheme -notin @('http', 'socks5', 'socks5h') -or
        -not $proxyUri.Host -or $proxyUri.UserInfo -or $proxyUri.Query -or $proxyUri.Fragment -or
        $proxyUri.AbsolutePath -notin @('', '/')) {
        throw 'ProxyUrl must be an http://HOST:PORT, socks5://HOST:PORT or socks5h://HOST:PORT URL without credentials.'
    }
    $env:GATEWAY_PUBLIC_HTTP_PROXY = $ProxyUrl
    Write-Host ('Public model discovery proxy: ' + $proxyUri.Scheme + '://' + $proxyUri.Authority)

    if ($env:GATEWAY_LOCAL_POSTGRES_BIN) {
        foreach ($tool in @('initdb.exe', 'pg_ctl.exe', 'psql.exe')) {
            if (-not (Test-Path -LiteralPath (Join-Path $env:GATEWAY_LOCAL_POSTGRES_BIN $tool))) {
                throw "PostgreSQL tool missing: $tool. Check GATEWAY_LOCAL_POSTGRES_BIN."
            }
        }
    } else {
        $postgresRoot = Join-Path $env:ProgramFiles 'PostgreSQL'
        $installed = @(Get-ChildItem -LiteralPath $postgresRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+$' -and [int]$_.Name -ge 16 -and
                (Test-Path -LiteralPath (Join-Path $_.FullName 'bin\pg_ctl.exe')) })
        if ($installed.Count -eq 0) {
            throw 'Install PostgreSQL 16+ or set GATEWAY_LOCAL_POSTGRES_BIN to its bin directory.'
        }
        # The application chooses a version compatible with the existing local cluster.
    }

    if ($SkipBuild) {
        if (-not (Test-Path -LiteralPath $binary)) {
            throw 'No local executable found. Run start-windows.cmd without -SkipBuild first.'
        }
    } else {
        foreach ($tool in @('cargo', 'node', 'npm.cmd', 'cmake')) {
            if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
                throw "Missing build tool: $tool. Install it and open a new terminal."
            }
        }
    }

    if ($Check) {
        Write-Host 'Prerequisite paths OK. No build, database migration or server startup performed.'
        exit 0
    }

    # Keep temporary compiler files and npm cache inside this checkout too.
    $tempDir = Join-Path $env:CARGO_TARGET_DIR 'windows-tmp'
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    $env:TEMP = $tempDir
    $env:TMP = $tempDir
    $env:npm_config_cache = Join-Path $env:CARGO_TARGET_DIR 'npm-cache'

    if (-not $SkipBuild) {
        # NASM does not support non-ASCII intermediate paths. This applies only to
        # this local build and keeps every artifact in the repository.
        if ($PSScriptRoot -match '[^\x00-\x7F]' -and -not $env:CMAKE_TOOLCHAIN_FILE) {
            $toolchain = Join-Path $env:CARGO_TARGET_DIR 'windows-local-toolchain.cmake'
            'set(OPENSSL_NO_ASM ON CACHE BOOL "Local Windows path compatibility" FORCE)' |
                Set-Content -LiteralPath $toolchain -Encoding ASCII
            $env:CMAKE_TOOLCHAIN_FILE = $toolchain
        }

        Write-Host '[1/3] Building the management console...'
        Push-Location -LiteralPath (Join-Path $PSScriptRoot 'web\admin-console')
        try {
            if (-not (Test-Path -LiteralPath 'node_modules\.bin\vite.cmd')) {
                & npm.cmd ci --no-audit --no-fund
                if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
            }
            & npm.cmd run build
            if ($LASTEXITCODE -ne 0) { throw 'Management console build failed.' }
        } finally {
            Pop-Location
        }

        Write-Host '[2/3] Building the gateway...'
        & cargo build --locked -p super-gatewayd
        if ($LASTEXITCODE -ne 0) { throw 'Gateway build failed; startup cancelled.' }
    }

    Write-Host '[3/3] Starting Super Gateway (local mode)...'
    Write-Host 'Admin console: http://127.0.0.1:8081/admin/'
    Write-Host 'API base URL:  http://127.0.0.1:8080/v1'
    Write-Host 'Initial username: admin'
    Write-Host ('Initial password file: ' + (Join-Path $env:GATEWAY_LOCAL_STATE_DIR 'admin-password'))
    Write-Host 'Wait for the ready message. Press Ctrl+C to stop gracefully.'
    & $binary local
    if ($LASTEXITCODE -ne 0) { throw "Gateway exited with code $LASTEXITCODE." }
} catch {
    Write-Host ('Startup failed: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}
