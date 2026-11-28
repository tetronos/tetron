# Builds the Windows release assets (WIN-080, WIN-081, WIN-085):
#   tetron-x86_64-windows.exe   self-installing tetron.exe with wintun.dll embedded
#   tetron-x86_64-windows.zip   tetron.exe, wintun.dll, tetron's LICENSE, Wintun's license
# plus a .sha256 beside each.
#
# Usage, from the repository root on Windows:
#   pwsh contrib/package-windows.ps1 [-Features tor,veilid] [-Target x86_64-pc-windows-msvc]

param(
    [string]$Features = "",
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$OutName = "tetron-x86_64-windows"
)

$ErrorActionPreference = "Stop"

# Wintun is redistributed as the official prebuilt, signed DLL, never built
# from source. One version is pinned, and the download must match this hash
# exactly or packaging stops.
$WintunVersion = "0.14.1"
$WintunSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$WintunUrl = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"

# A per-run folder under target/, so the build can embed the DLL by absolute
# path and nothing outside the build tree is touched.
New-Item -ItemType Directory -Force -Path "target" | Out-Null
$work = Join-Path (Resolve-Path "target").Path ("package-windows-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # 1. Fetch and verify Wintun.
    $wintunZip = Join-Path $work "wintun.zip"
    Invoke-WebRequest -Uri $WintunUrl -OutFile $wintunZip -UseBasicParsing
    $actual = (Get-FileHash -Algorithm SHA256 $wintunZip).Hash.ToLowerInvariant()
    if ($actual -ne $WintunSha256) {
        throw "wintun-$WintunVersion.zip hash $actual does not match the pinned $WintunSha256"
    }
    Expand-Archive -Path $wintunZip -DestinationPath (Join-Path $work "wintun-src")
    $dll = Join-Path $work "wintun-src\wintun\bin\amd64\wintun.dll"
    $wintunLicense = Join-Path $work "wintun-src\wintun\LICENSE.txt"

    # 2. Build with the verified DLL embedded (build.rs reads TETRON_WINTUN_DLL).
    $env:TETRON_WINTUN_DLL = $dll
    $cargoArgs = @("build", "--release", "--locked", "--target", $Target)
    if ($Features -ne "") { $cargoArgs += @("--features", $Features) }
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    $binary = "target\$Target\release\tetron.exe"

    # The built binary must start.
    $version = & $binary --version
    if ($LASTEXITCODE -ne 0) { throw "tetron.exe --version failed" }
    Write-Host "built $version with wintun $WintunVersion embedded"

    # 3a. The self-installing executable.
    $exe = "$OutName.exe"
    Copy-Item $binary $exe -Force

    # 3b. The zip, for installs that want the DLL as a separate file.
    $stage = Join-Path $work $OutName
    New-Item -ItemType Directory -Path $stage | Out-Null
    Copy-Item $binary (Join-Path $stage "tetron.exe")
    Copy-Item $dll $stage
    Copy-Item "LICENSE" (Join-Path $stage "LICENSE")
    Copy-Item $wintunLicense (Join-Path $stage "WINTUN-LICENSE.txt")
    $zip = "$OutName.zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip

    # Wintun's license is also published on its own, beside the executable
    # that embeds the DLL.
    Copy-Item $wintunLicense "WINTUN-LICENSE.txt" -Force

    # Checksums, in the same "<hash>  <name>" form as the other release assets.
    foreach ($f in @($exe, $zip)) {
        $hash = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLowerInvariant()
        Set-Content -Path "$f.sha256" -Value "$hash  $f" -NoNewline -Encoding ascii
        Write-Host "wrote $f ($hash)"
    }
}
finally {
    Remove-Item Env:\TETRON_WINTUN_DLL -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
