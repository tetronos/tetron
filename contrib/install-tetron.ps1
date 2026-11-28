# Installs tetron on Windows 10 or 11 (x86_64).
#
# Run from an elevated PowerShell ("Run as administrator"):
#   irm https://tetronos.github.io/tetron/install.ps1 | iex
# or, to pin a release, download this file and run:
#   .\install.ps1 -Version vX.Y.Z
# -BaseUrl downloads the executable and its .sha256 from another location (a
# mirror) instead of the GitHub release.
#
# What it does, in order:
#   1. Downloads tetron-x86_64-windows.exe (tetron with the Wintun driver DLL
#      built in) and its .sha256 from the tetron GitHub releases (the latest
#      release, or the tag given with -Version).
#   2. Stops unless the file's SHA-256 matches the published .sha256.
#   3. Runs `tetron-x86_64-windows.exe install` from a new temporary folder.
#      That copies itself to %ProgramFiles%\tetron\tetron.exe, writes
#      wintun.dll beside it, registers and starts the `tetron` Windows
#      service (LocalSystem, automatic start), puts %ProgramFiles%\tetron on
#      the machine PATH so `tetron` works in new terminals, and activates the
#      VPN.
#   4. Deletes the temporary folder.
#
# Nothing else on the system is changed. `tetron uninstall` removes the
# service and the program files and keeps %ProgramData%\tetron (the node's
# identity and networks).

param(
    [string]$Version = "latest",
    [string]$BaseUrl = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "tetronos/tetron"
$Asset = "tetron-x86_64-windows.exe"

# The service install needs an elevated (Administrator) session.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated PowerShell (right-click, Run as administrator)."
}

if ([Environment]::Is64BitOperatingSystem -eq $false) {
    throw "tetron for Windows needs a 64-bit (x86_64) Windows."
}

if ($BaseUrl -ne "") {
    $base = $BaseUrl.TrimEnd("/")
} elseif ($Version -eq "latest") {
    $base = "https://github.com/$Repo/releases/latest/download"
} else {
    $base = "https://github.com/$Repo/releases/download/$Version"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("tetron-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # 1. Download the executable and its checksum.
    $exe = Join-Path $work $Asset
    $sum = "$exe.sha256"
    Write-Host "downloading $base/$Asset"
    Invoke-WebRequest -Uri "$base/$Asset" -OutFile $exe -UseBasicParsing
    Invoke-WebRequest -Uri "$base/$Asset.sha256" -OutFile $sum -UseBasicParsing

    # 2. Verify. The .sha256 file is "<hash>  <file name>".
    $expected = ((Get-Content $sum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "checksum mismatch for $Asset (expected $expected, got $actual); nothing was installed"
    }
    Write-Host "checksum ok ($actual)"

    # 3. Let tetron install itself as a service.
    & $exe install
    if ($LASTEXITCODE -ne 0) { throw "tetron install failed (exit code $LASTEXITCODE)" }

    Write-Host "tetron is installed. Next: tetron create, or tetron join <invite key>."
}
finally {
    # 4. Clean up the download.
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
