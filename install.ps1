# install.ps1 - build cube.exe and install on Windows.
#
# Requirements:
#   - MSYS2 or MinGW-w64 in PATH (for gcc, make, ar, pkg-config)
#   - libsodium (optional, only if crypto uses it)
#   - OpenSSL (optional, only if crypto uses it)
#
# Usage:
#   .\install.ps1                                    # build + install to Program Files\cube
#   .\install.ps1 -Prefix C:\opt\cube
#   .\install.ps1 -NoBuild                           # install existing cube.exe
#   .\install.ps1 -SkipMissing                       # continue if libsodium/openssl missing
#
# What it does:
#   1. Verifies cc/make are available
#   2. Builds all libraries via the same Makefile used on POSIX
#   3. Links cube.exe
#   4. Installs cube.exe, headers, and .a files

param(
    [string]$Prefix = "$env:ProgramFiles\cube",
    [switch]$NoBuild,
    [switch]$SkipMissing
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $Root

function Find-Tool($name) {
    $t = Get-Command $name -ErrorAction SilentlyContinue
    if ($t) { return $t.Source }
    foreach ($dir in @(
        "C:\msys64\usr\bin",
        "C:\msys64\mingw64\bin",
        "C:\msys64\ucrt64\bin",
        "C:\MinGW\bin",
        "$env:USERPROFILE\scoop\shims",
        "$env:USERPROFILE\scoop\apps\gcc\current\bin"
    )) {
        $p = Join-Path $dir "$name.exe"
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Require-Tool($name, $hint) {
    $t = Find-Tool $name
    if (-not $t) {
        Write-Host "ERROR: '$name' not found." -ForegroundColor Red
        Write-Host "  $hint" -ForegroundColor Yellow
        if ($SkipMissing) { Write-Host "  (-SkipMissing set, continuing)" -ForegroundColor Yellow; return $null }
        throw "missing tool: $name"
    }
    return $t
}

try {
    if (-not $NoBuild) {
        $cc   = Require-Tool "cc"    "Install MSYS2 + mingw-w64: https://www.msys2.org/"
        $make = Require-Tool "make"  "Install MSYS2 + make: https://www.msys2.org/"
        $ar   = Find-Tool "ar"
        if (-not $ar) { $ar = Find-Tool "llvm-ar" }
        if (-not $ar) {
            Write-Host "ERROR: 'ar' or 'llvm-ar' not found." -ForegroundColor Red
            throw "missing archiver"
        }

        Write-Host "building cube with $cc" -ForegroundColor Cyan
        Write-Host "  archiver: $ar"

        # Build libraries first (POSIX build, works with MinGW make)
        $libs = @(
            "utils",
            "flywheel/url", "flywheel/json", "flywheel/html", "flywheel/dom", "flywheel/css",
            "net/tcp", "net/dns", "net/crisptls", "net/http_client", "net/quic"
        )
        foreach ($d in $libs) {
            $mk = Join-Path $d "Makefile"
            if (Test-Path $mk) {
                Write-Host "  building $d" -ForegroundColor Gray
                Push-Location $d
                try {
                    & make 2>&1 | Select-Object -Last 2 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
                    if ($LASTEXITCODE -ne 0) { throw "make failed in $d" }
                } finally { Pop-Location }
            }
        }

        # Build cube.exe
        Write-Host "  linking cube.exe" -ForegroundColor Gray
        $ccArgs = @(
            "-O2", "-I.", "-Iutils", "-Wall", "-Wextra",
            "-Inet/crisptls/include", "-Inet/dns/include", "-Inet/tcp/include",
            "-Inet/http_client/include", "-Iflywheel/url/include", "-Iflywheel/json/include",
            "-Iflywheel/html/include", "-Iflywheel/dom/include", "-Iflywheel/css/include",
            "src/cube.c",
            "net/http_client/build/libhttp_client.a",
            "net/crisptls/build/libcrisptls.a",
            "net/dns/build/libdns.a",
            "net/tcp/build/libtcp.a",
            "flywheel/url/build/liburl.a",
            "flywheel/html/build/libhtml.a",
            "flywheel/dom/build/libdom.a",
            "flywheel/css/build/libcss.a",
            "flywheel/json/build/libjson.a",
            "utils/build/libutils.a",
            "-lws2_32", "-lcrypto", "-lsodium", "-lssl",
            "-o", "cube.exe"
        )
        & $cc @ccArgs 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        if ($LASTEXITCODE -ne 0) { throw "link failed" }
    }

    if (-not (Test-Path "cube.exe")) {
        throw "cube.exe not found after build"
    }

    $binDir = Join-Path $Prefix "bin"
    $incDir = Join-Path $Prefix "include\cube"
    $libDir = Join-Path $Prefix "lib"
    Write-Host "installing to $Prefix" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $binDir, $incDir, $libDir | Out-Null

    Copy-Item "cube.exe" (Join-Path $binDir "cube.exe") -Force

    $headers = @(
        "flywheel/url", "flywheel/json", "flywheel/html", "flywheel/dom", "flywheel/css",
        "net/crisptls", "net/dns", "net/tcp", "net/http_client", "net/quic",
        "utils"
    )
    foreach ($d in $headers) {
        $inc = Join-Path $d "include"
        if (Test-Path $inc) {
            $target = Join-Path $incDir (Split-Path $d -Leaf)
            New-Item -ItemType Directory -Force -Path $target | Out-Null
            Get-ChildItem -Path $inc -Filter "*.h" -ErrorAction SilentlyContinue |
                Copy-Item -Destination $target -Force
        }
    }

    Get-ChildItem -Path . -Recurse -Filter "*.a" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\build\\" } |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $libDir $_.Name) -Force }

    Write-Host "installed:" -ForegroundColor Green
    Write-Host "  binary:  $binDir\cube.exe"
    Write-Host "  headers: $incDir\"
    Write-Host "  libs:    $libDir\"
    Write-Host ""
    Write-Host "to run: `"$binDir\cube.exe`" https://example.com"
    Write-Host "to add to PATH for this session:"
    Write-Host "  `$env:Path = `"$binDir;`$env:Path`""
}
catch {
    Write-Host "install failed: $_" -ForegroundColor Red
    exit 1
}
finally {
    Pop-Location
}
