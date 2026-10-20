param(
    [Parameter(Mandatory)][string]$Binaries,
    [string]$Output = "$PSScriptRoot/../artifacts/distribution"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Run in a VS developer shell so dumpbin is available. Build with
# RUSTFLAGS='-C target-feature=+crt-static' and an explicit MSVC target.
$null = Get-Command dumpbin -ErrorAction Stop
$version = (Get-Content "$PSScriptRoot/../Cargo.toml" |
    Select-String '^version = "([0-9.]+)"$' | Select-Object -First 1).Matches.Groups[1].Value
if (!$version) { throw 'Missing package version' }
$name = "gulikit-updater-$version-windows-x86_64"
$null = New-Item -ItemType Directory -Force $Output
$Output = (Resolve-Path $Output).Path
$archive = Join-Path $Output "$name.zip"
if (Test-Path $archive) { throw "Refusing to replace $archive" }
$temporary = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$package = Join-Path $temporary $name
$null = New-Item -ItemType Directory -Force $package
try {
    foreach ($exe in @('gulikit-ui.exe', 'gulikit-updater.exe')) {
        $source = Join-Path $Binaries $exe
        if ((Get-AuthenticodeSignature $source).Status -ne 'NotSigned') {
            throw "Expected an unsigned executable: $source"
        }
        $headers = & dumpbin /headers $source
        if ($LASTEXITCODE -ne 0 -or !($headers -match '8664 machine')) {
            throw "Expected a Windows x64 PE executable: $source"
        }
        $imports = & dumpbin /dependents $source
        if ($LASTEXITCODE -ne 0) { throw "Cannot inspect imports: $source" }
        $dlls = @($imports | Where-Object { $_ -match '^\s+[\w.-]+\.dll\s*$' } |
            ForEach-Object { $_.Trim() })
        if ($dlls.Count -eq 0) { throw "No PE dependencies found: $source" }
        foreach ($dll in $dlls) {
            # Reject redistributable CRTs even though the CI host has them.
            # API sets and ucrtbase ship with Windows 10/11 itself.
            if ($dll -match '^(vcruntime|msvcp|concrt|msvcr)\d' -or
                ($dll -notmatch '^(api-ms-win-|ext-ms-win-)' -and
                 !(Test-Path (Join-Path "$env:WINDIR/System32" $dll)))) {
                throw "Non-system DLL dependency in ${exe}: $dll"
            }
        }
        Copy-Item $source $package
    }
    @'
GuliKit Updater for Windows x64 (unsigned)

Extract the complete ZIP to a local folder and open gulikit-ui.exe.
gulikit-updater.exe is the command-line client.

SmartScreen may show "Windows protected your PC" / Unknown publisher.
On machines that permit it, More info > Run anyway continues to the app.
Smart App Control or organization policies can block unsigned applications.
This package cannot override those policies.

Native controller access on Windows is not implemented yet. Offline package
inspection and the --demo UI are available. See the project's desktop README.
'@ | Set-Content (Join-Path $package 'README.txt')
    $candidate = Join-Path $temporary "$name.zip"
    Compress-Archive -Path $package -DestinationPath $candidate
    $extracted = Join-Path $temporary 'extracted'
    Expand-Archive $candidate $extracted
    $consumer = Join-Path $extracted $name
    # Exclude development tools and runtime directories from the consumer PATH.
    $savedPath = $env:PATH
    try {
        $env:PATH = "$env:WINDIR/System32;$env:WINDIR"
        foreach ($exe in @('gulikit-ui.exe', 'gulikit-updater.exe')) {
            $stdout = Join-Path $temporary "$exe.stdout"
            $stderr = Join-Path $temporary "$exe.stderr"
            $process = Start-Process (Join-Path $consumer $exe) -ArgumentList '--help' `
                -WorkingDirectory $consumer -RedirectStandardOutput $stdout `
                -RedirectStandardError $stderr -PassThru
            if (!$process.WaitForExit(30000)) {
                $process.Kill()
                $null = $process.WaitForExit(5000)
                throw "Help command timed out: $exe"
            }
            if ($process.ExitCode -ne 0 -or !(Select-String -Path $stdout -Pattern 'Usage:')) {
                throw "Packaged help failed: $exe (exit $($process.ExitCode)): $(Get-Content $stderr -Raw)"
            }
        }
        $demoStdout = Join-Path $temporary 'demo.stdout'
        $demoStderr = Join-Path $temporary 'demo.stderr'
        $demo = Start-Process (Join-Path $consumer 'gulikit-ui.exe') `
            -ArgumentList '--demo' -WorkingDirectory $consumer `
            -RedirectStandardOutput $demoStdout -RedirectStandardError $demoStderr -PassThru
        try {
            $null = $demo.Handle
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            while (!$demo.HasExited -and $demo.MainWindowHandle -eq 0 -and [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 500
                $demo.Refresh()
            }
            if ($demo.HasExited -or $demo.MainWindowHandle -eq 0) {
                throw "Packaged demo did not open a window: $(Get-Content $demoStderr -Raw)"
            }
            # A window handle can appear before the UI message loop is ready.
            if (!$demo.WaitForInputIdle(30000)) {
                throw 'Packaged demo did not become ready for window input'
            }
            $demo.Refresh()
            if (!$demo.CloseMainWindow()) {
                throw "Packaged demo rejected the close request (window $($demo.MainWindowHandle))"
            }
            if (!$demo.WaitForExit(30000)) {
                $demo.Refresh()
                throw "Packaged demo close timed out (window $($demo.MainWindowHandle), responding $($demo.Responding)): $(Get-Content $demoStderr -Raw)"
            }
            if ($demo.ExitCode -ne 0) {
                throw "Packaged demo exited with code $($demo.ExitCode): $(Get-Content $demoStderr -Raw)"
            }
        } finally {
            if (!$demo.HasExited) {
                $demo.Kill()
                $null = $demo.WaitForExit(5000)
            }
        }
    } finally {
        $env:PATH = $savedPath
    }
    Copy-Item $candidate $archive
    $hash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    "$hash  $name.zip" | Set-Content -Encoding ascii "$archive.sha256"
    Write-Output "Unsigned Windows package passed import and extracted launch checks: $archive"
} finally {
    Remove-Item -Recurse -Force $temporary
}
