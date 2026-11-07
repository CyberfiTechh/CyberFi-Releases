param([switch]$SelfCheck, [string]$UpstreamPath, [switch]$Upgrade115, [switch]$Mcp115)
$ErrorActionPreference = 'Stop'
$repo = 'CyberfiTechh/CyberFi-Releases'
$certificateThumbprint = '2470547AF0CF456E06BF7065399591BBD7EC79ED'
$expected = @{
    '0.0.113' = 'c1f4e1f2e0b779e5fa808f288255e39b15d01a84cf3e84835e71960333e47deb'
    '0.0.114' = '3bcbe22f5f338cf0d8cb4d6747c69bd11ca347b649b4bc1c8bb48c4fe9ecdae2'
    '0.0.115' = '5d6334d1d7f516cd13c893ffd7a18d1a6bb2511292ff6946c8ffb9c37608ea5a'
}
function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Receive-PublishedAsset([string]$Url, [string]$Destination) {
    Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Downloading $([IO.Path]::GetFileName($Destination))"
    & curl.exe --fail --location --retry 2 --connect-timeout 20 --max-time 300 --output $Destination $Url
    Assert-True ($LASTEXITCODE -eq 0) "Bounded release download failed: $([IO.Path]::GetFileName($Destination)) (curl exit $LASTEXITCODE)"
    Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Downloaded $((Get-Item -LiteralPath $Destination).Length) bytes"
}
function Assert-Owned([string]$Path, [string]$Root) {
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    Assert-True ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) "Path is outside the owned root: $full"
    $full
}
if ($SelfCheck) {
    Assert-True ($expected.Count -eq 3) 'Exactly three immutable versions required'
    foreach ($entry in $expected.GetEnumerator()) {
        Assert-True ($entry.Value -cmatch '^[a-f0-9]{64}$') 'Invalid pinned digest'
        Assert-True ($entry.Key -in @('0.0.113', '0.0.114', '0.0.115')) 'Unexpected version'
    }
    Assert-True ($certificateThumbprint -cmatch '^[A-F0-9]{40}$') 'Invalid certificate pin'
    $null = Assert-Owned (Join-Path ([IO.Path]::GetTempPath()) 'owned/item') ([IO.Path]::GetTempPath())
    try { $null = Assert-Owned ([IO.Path]::GetTempPath()) (Join-Path ([IO.Path]::GetTempPath()) 'owned'); throw 'Guard accepted parent' }
    catch { Assert-True ($_.Exception.Message -like 'Path is outside*') 'Ownership guard failed' }
    'Acceptance harness self-check passed; no installers or network used.'
    return
}
Assert-True ($IsWindows -and $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted' -and
    $env:GITHUB_REPOSITORY -ceq $repo -and $env:GITHUB_REF -eq 'refs/heads/main') 'Only the disposable public Windows runner may install'
$fromVersion = $(if ($Upgrade115) { '0.0.114' } else { '0.0.113' })
$toVersion = $(if ($Upgrade115) { '0.0.115' } else { '0.0.114' })
$versions = $(if ($Mcp115) { @('0.0.115') } else { @($fromVersion, $toVersion) })
$rootName = $(if ($Mcp115) { 'cyberfi-windows-mcp-115' } elseif ($Upgrade115) { 'cyberfi-windows-upgrade-115' } else { 'cyberfi-windows-acceptance' })
$root = Assert-Owned (Join-Path $env:RUNNER_TEMP $rootName) $env:RUNNER_TEMP
Assert-True (-not (Test-Path -LiteralPath $root)) 'Acceptance root must start empty'
$evidence = Join-Path $root 'evidence'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\f8156223-0df4-5c6f-b223-7004db2f68a2'
Assert-True (-not (Test-Path -LiteralPath $uninstallKey)) 'Existing CyberFi installation must never be replaced'
$installation = Assert-Owned (Join-Path $root 'installed') $root
$exe = Join-Path $installation 'CyberFi.exe'
$ownedHome = Assert-Owned (Join-Path $root 'home') $root
# NSIS relaunch has no user-data-dir argument; use its real default on the disposable runner.
$userData = $(if ($Mcp115) { Assert-Owned (Join-Path $root 'user-data') $root } else { Assert-Owned (Join-Path $env:APPDATA 'CyberFi') $env:APPDATA })
Assert-True (-not (Test-Path -LiteralPath $userData)) 'Runner CyberFi profile must start empty'
$happy = Join-Path $ownedHome '.happy'
New-Item -ItemType Directory -Path $ownedHome, $userData -Force | Out-Null
if (-not $Mcp115) { New-Item -ItemType Directory -Path $happy -Force | Out-Null }

function Invoke-BoundedCertificateStep([string]$Stage, [scriptblock]$Action, [object[]]$Arguments) {
    Write-Host "[$([DateTime]::UtcNow.ToString('o'))] $Stage"
    $job = Start-Job -ScriptBlock $Action -ArgumentList $Arguments
    try {
        Assert-True ($null -ne (Wait-Job -Job $job -Timeout 60)) "$Stage exceeded 60 seconds"
        $value = Receive-Job -Job $job -ErrorAction Stop
        Assert-True ($job.State -eq 'Completed') "$Stage failed"
        Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Completed: $Stage"
        $value
    } finally {
        if ($job.State -eq 'Running') { Stop-Job -Job $job }
        Remove-Job -Job $job -Force
    }
}
function Read-BoundedSignature([string]$Path) {
    $value = Invoke-BoundedCertificateStep "Validate trusted Authenticode: $([IO.Path]::GetFileName($Path))" {
        param($Candidate)
        $signature = Get-AuthenticodeSignature -LiteralPath $Candidate
        [pscustomobject]@{ Status = [string]$signature.Status
            Certificate = $(if ($signature.SignerCertificate) { [Convert]::ToBase64String($signature.SignerCertificate.RawData) } else { $null }) }
    } @($Path)
    $signature = [pscustomobject]@{ Status = $value.Status
        SignerCertificate = $(if ($value.Certificate) { [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($value.Certificate)) } else { $null }) }
    $signature
}
function Assert-Signature([string]$Path) {
    $signature = Read-BoundedSignature $Path
    Assert-True ($signature.SignerCertificate.Thumbprint -ceq $certificateThumbprint -and
        $signature.Status -eq 'Valid') "Unexpected or invalid signature on $Path ($($signature.Status))"
    $signature
}
$payloadHashes = @{}
$payloadDirectories = @{}
function Read-VerifiedPayloadHash([string]$Installer, [string]$Version) {
    Assert-True ($expected.ContainsKey($Version)) 'Only the pinned releases may be extracted'
    $extractor = Join-Path $env:ProgramFiles '7-Zip/7z.exe'
    Assert-True (Test-Path -LiteralPath $extractor) 'Independent NSIS extractor unavailable'
    $destination = Assert-Owned (Join-Path $root "payload-$Version") $root
    New-Item -ItemType Directory -Path $destination | Out-Null
    function Expand-OwnedArchive([string]$Archive, [string]$Output, [string]$Label, [string]$Member = '*') {
        Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Independently extracting $Label"
        $log = Join-Path $evidence "extract-$Version-$Label.log"
        $process = Start-Process -FilePath $extractor -ArgumentList @('x', '-y', $Archive, "-o$Output", $Member) `
            -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru
        if (-not $process.WaitForExit(60000)) { $process.Kill($true); throw "Independent $Label extraction timed out" }
        Assert-True ($process.ExitCode -eq 0) "Independent $Label extraction failed"
    }
    Expand-OwnedArchive $Installer $destination 'NSIS'
    $archive = @(Get-ChildItem -LiteralPath $destination -Recurse -File -Filter app-64.7z)
    Assert-True ($archive.Count -eq 1) 'Expected exactly one embedded x64 application archive'
    $inner = Assert-Owned (Join-Path $destination 'inner') $root
    $member = $(if ($Mcp115) { '*' } else { 'CyberFi.exe' })
    Expand-OwnedArchive $archive[0].FullName $inner 'inner' $member
    $payloadDirectories[$Version] = $inner
    $digest = (Get-FileHash -LiteralPath (Join-Path $inner 'CyberFi.exe') -Algorithm SHA256).Hash
    [ordered]@{ version = $Version; trustedInstallerSHA256 = $expected[$Version]; independentInnerSHA256 = $digest;
        method = '7-Zip extracts NSIS then embedded app-64.7z; NSIS installer is not executed for this reference.'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence "payload-$Version.json") -Encoding utf8
    $digest
}
function Assert-Installed([string]$Version) {
    Assert-True (Test-Path -LiteralPath $exe) 'Installed executable missing'
    Assert-True ((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -eq "$Version.0") 'Installed PE version mismatch'
    $digest = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    if ($Version -in @('0.0.113', '0.0.114')) {
        Assert-True ($payloadHashes[$Version] -and $digest -ceq $payloadHashes[$Version]) 'Legacy installed EXE differs from independently extracted trusted installer payload'
        $signature = Read-BoundedSignature $exe
        Assert-True ($signature.Status -eq 'NotSigned') 'Unexpected legacy inner signature state'
    } else {
        $signature = Assert-Signature $exe
    }
    $registry = Get-ItemProperty -LiteralPath $uninstallKey
    Assert-True ($registry.DisplayVersion -eq $Version -and $registry.UninstallString.Contains($installation)) 'Installer registry points elsewhere'
    [ordered]@{ version = $Version; executable = $exe; sha256 = $digest; registryVersion = $registry.DisplayVersion;
        innerSignature = $signature.Status; integrity = $(if ($Version -in @('0.0.113', '0.0.114')) { 'Matches independent extraction of exact pinned, RSA-verified, Valid-signed installer; legacy inner EXE is unsigned.' } else { 'Valid pinned inner Authenticode signature' }) }
}
function Assert-Smoke([string]$Path) {
    Assert-True (Test-Path -LiteralPath $Path) "Packaged app did not write $Path"
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    Assert-True ($report.packaged -and $report.platform -eq 'win32' -and $report.arch -eq 'x64' -and
        $report.welcomeVisible -and $report.windowTitle -eq 'CyberFi' -and $report.screenshotWritten -and
        $report.hiddenMode -and -not $report.focusedWindow -and
        @($report.windows | Where-Object { $_.visible -or $_.focused }).Count -eq 0) 'Packaged hidden smoke failed'
}

$installers = @{}
foreach ($version in $versions) {
    $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/tags/v$version" -Headers @{ Accept = 'application/vnd.github+json' } -TimeoutSec 30
    Assert-True (-not $release.draft -and $release.tag_name -ceq "v$version") 'Expected an actual published release'
    $release | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $evidence "release-$version.json") -Encoding utf8
    $name = "CyberFi-$version-x64.exe"
    $asset = @($release.assets | Where-Object { $_.name -ceq $name })
    Assert-True ($asset.Count -eq 1 -and $asset[0].state -eq 'uploaded' -and
        $asset[0].digest -ceq "sha256:$($expected[$version])") 'Immutable installer asset mismatch'
    $path = Join-Path $root $name
    Receive-PublishedAsset "https://github.com/$repo/releases/download/v$version/$name" $path
    Assert-True ((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $expected[$version]) 'Downloaded installer digest mismatch'
    foreach ($suffix in @('.sha256', '.update.json')) {
        $metadata = @($release.assets | Where-Object { $_.name -ceq "$name$suffix" })
        Assert-True ($metadata.Count -eq 1 -and $metadata[0].state -eq 'uploaded') 'Missing release verification asset'
        $sidecar = "$path$suffix"
        Receive-PublishedAsset "https://github.com/$repo/releases/download/v$version/$name$suffix" $sidecar
        Assert-True ("sha256:$((Get-FileHash $sidecar -Algorithm SHA256).Hash.ToLowerInvariant())" -ceq $metadata[0].digest) 'Verification asset digest mismatch'
    }
    Assert-True ((Get-Content "$path.sha256" -Raw).Split()[0] -ceq $expected[$version]) 'Published SHA256 sidecar mismatch'
    $manifest = Get-Content "$path.update.json" -Raw | ConvertFrom-Json
    Assert-True ($manifest.sha256 -ceq $expected[$version] -and $manifest.size -eq (Get-Item $path).Length) 'Manifest digest/size mismatch'
    # Parse the embedded signer offline before any WinVerifyTrust/AIA chain lookup.
    # Integrity and signer identity are still independently pinned, then trust must be Valid.
    Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Extracting pinned embedded signer for $version"
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($path))
    Assert-True ($certificate.Thumbprint -ceq $certificateThumbprint) 'Embedded signer pin mismatch'
    $signature = [pscustomobject]@{ SignerCertificate = $certificate }
    Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Verifying RSA update manifest for $version"
    $publicKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($signature.SignerCertificate)
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes("$version`n$name`n$($manifest.sha256)`n$($manifest.size)`n")
        Assert-True ($publicKey.VerifyData($payload, [Convert]::FromBase64String($manifest.signature),
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'Signed update manifest failed verification'
    } finally { $publicKey.Dispose() }
    # Trust only this pinned public certificate in the disposable hosted machine.
    # CurrentUser Root demands interactive consent; the hosted administrator's
    # LocalMachine Root supports unattended import without changing revocation policy.
    $cer = Join-Path $root 'pinned-signer.cer'
    [IO.File]::WriteAllBytes($cer, $signature.SignerCertificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $null = Invoke-BoundedCertificateStep "Trust pinned public certificate in disposable runner for $version" {
        param($CertificatePath)
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
    } @($cer)
    $null = Assert-Signature $path
    $payloadHashes[$version] = Read-VerifiedPayloadHash $path $version
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence "manifest-$version.json") -Encoding utf8
    $installers[$version] = $path
}

# No token is inherited by the installer or its automatically relaunched app.
foreach ($name in @((Get-ChildItem Env: | Where-Object { $_.Name -match 'TOKEN|SECRET|PASSWORD|CREDENTIAL' }).Name) + @('HAPPY_AGENT_SERVER_SOCKET_PATH')) {
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}
$env:HAPPY_DESKTOP_WINDOWS_HIDDEN = '1'
$env:HAPPY_HOME_DIR = $happy
$env:HOME = $ownedHome
$env:USERPROFILE = $ownedHome
if ($Mcp115) {
    # Electron consults these Windows paths before the packaged QA guard runs.
    # Keep its startup/cache folders outside the deliberately empty test HOME.
    $env:APPDATA = Join-Path $root 'appdata'
    $env:LOCALAPPDATA = Join-Path $root 'localappdata'
    $env:TEMP = Join-Path $root 'launcher-tmp'
    $env:TMP = $env:TEMP
    New-Item -ItemType Directory -Path $env:APPDATA, $env:LOCALAPPDATA, $env:TEMP -Force | Out-Null
    $exe = Join-Path $payloadDirectories['0.0.115'] 'CyberFi.exe'
    Assert-True ((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -eq '0.0.115.0') '115 payload PE version mismatch'
    $null = Assert-Signature $exe
    [ordered]@{ purpose = 'CyberFi isolated MCP acceptance'; home = $ownedHome; userData = $userData } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'owned-acceptance.json') -Encoding utf8
    $env:CYBERFI_MCP_ACCEPTANCE = '1'
    $env:CYBERFI_MCP_ACCEPTANCE_ROOT = $root
    $env:CYBERFI_MCP_ACCEPTANCE_REPORT = Join-Path $root 'mcp-acceptance.json'
    $env:ACCEPTANCE_EXE = $exe
    $env:ACCEPTANCE_USER_DATA = $userData
    @'
import assert from 'node:assert/strict';
import { gymElectronProcessRun } from './packages/happy-desktop-gym/sources/electron/launch.ts';
const result = await gymElectronProcessRun({ executablePath: process.env.ACCEPTANCE_EXE,
    args: [`--user-data-dir=${process.env.ACCEPTANCE_USER_DATA}`], env: process.env, timeout: 40*60_000 });
assert.equal(result.exitCode, 0, result.output);
'@ | Set-Content -LiteralPath (Join-Path $UpstreamPath 'acceptance-mcp.mjs') -Encoding utf8
    Push-Location $UpstreamPath
    try { & node --import tsx acceptance-mcp.mjs; Assert-True ($LASTEXITCODE -eq 0) 'Packaged 115 MCP acceptance failed' }
    finally { Pop-Location }
    $mcpResult = Get-Content -LiteralPath $env:CYBERFI_MCP_ACCEPTANCE_REPORT -Raw | ConvertFrom-Json
    Assert-True ($mcpResult.success -and $mcpResult.platform -eq 'win32' -and $mcpResult.arch -eq 'x64' -and
        $mcpResult.bootstrap.servers.Count -eq 9 -and $mcpResult.calls.Count -eq 9 -and
        @($mcpResult.bootstrap.servers | Where-Object { $_.state -ne 'ready' }).Count -eq 0 -and
        @($mcpResult.calls | Where-Object { $_.toolCount -le 0 -or $_.result.isError }).Count -eq 0) 'Nine real MCP calls did not pass'
    'Signed packaged 115 production MCP bootstrap and nine representative tool calls passed.'
    return
}
$env:HAPPY_DESKTOP_SMOKE_REPORT = Join-Path $evidence "fresh-$fromVersion.json"
$env:HAPPY_DESKTOP_SMOKE_SCREENSHOT = Join-Path $evidence "fresh-$fromVersion.png"
$fresh = Start-Process -FilePath $installers[$fromVersion] -ArgumentList "/S /D=$installation" -WindowStyle Hidden -PassThru
Assert-True ($fresh.WaitForExit(180000) -and $fresh.ExitCode -eq 0) "Fresh $fromVersion installation failed"
$before = Assert-Installed $fromVersion
@'
import assert from 'node:assert/strict';
import { gymElectronProcessRun } from './packages/happy-desktop-gym/sources/electron/launch.ts';
const result = await gymElectronProcessRun({ executablePath: process.env.ACCEPTANCE_EXE,
    args: [`--user-data-dir=${process.env.ACCEPTANCE_USER_DATA}`], env: process.env, timeout: 120000 });
assert.equal(result.exitCode, 0, result.output);
'@ | Set-Content -LiteralPath (Join-Path $UpstreamPath 'acceptance-smoke.mjs') -Encoding utf8
$env:ACCEPTANCE_EXE = $exe
$env:ACCEPTANCE_USER_DATA = $userData
Push-Location $UpstreamPath
try { & node --import tsx acceptance-smoke.mjs; Assert-True ($LASTEXITCODE -eq 0) "Fresh $fromVersion app launch failed" }
finally { Pop-Location }
Assert-Smoke $env:HAPPY_DESKTOP_SMOKE_REPORT

# Defaults may remain in memory until the first preference change. Seed an owned,
# valid user preference file to exercise persistence through the real upgrade.
$settings = Join-Path $userData 'desktop/config.json'
if (-not (Test-Path -LiteralPath $settings)) {
    New-Item -ItemType Directory -Path (Split-Path $settings) -Force | Out-Null
    '{"appearance":"dark","defaultPermissionMode":"read_only"}' | Set-Content -LiteralPath $settings -Encoding utf8
}
$mcp = Join-Path $ownedHome 'happy/config/mcp.toml'
$skill = Join-Path $ownedHome '.agents/skills/acceptance-sentinel/SKILL.md'
New-Item -ItemType Directory -Path (Split-Path $mcp), (Split-Path $skill) -Force | Out-Null
"[mcp_servers.acceptance_sentinel]`nenabled = false`ncommand = 'node'`nargs = ['--version']`n" | Set-Content $mcp -Encoding utf8
"---`nname: acceptance-sentinel`ndescription: Installer preservation marker`n---`nPreserve this file.`n" | Set-Content $skill -Encoding utf8
$marker = Join-Path $userData 'acceptance-sentinel.txt'
'113 settings and catalogue belong to this disposable profile' | Set-Content $marker -Encoding utf8
$preserve = @($settings, $mcp, $skill, $marker)
$hashes = @{}
foreach ($path in $preserve) { $hashes[$path] = (Get-FileHash $path -Algorithm SHA256).Hash }
$mcpOriginalLength = (Get-Item -LiteralPath $mcp).Length
$hashes | ConvertTo-Json | Set-Content (Join-Path $evidence 'preserved-before.json') -Encoding utf8

$env:HAPPY_DESKTOP_SMOKE_REPORT = Join-Path $evidence "automatic-relaunch-$toVersion.json"
$env:HAPPY_DESKTOP_SMOKE_SCREENSHOT = Join-Path $evidence "automatic-relaunch-$toVersion.png"
$started = Get-Date
# These are the production updater's exact NSIS arguments; no manual 114 app launch follows.
$upgrade = Start-Process -FilePath $installers[$toVersion] -ArgumentList '--updated /S --force-run' -WindowStyle Hidden -PassThru
Assert-True ($upgrade.WaitForExit(180000) -and $upgrade.ExitCode -eq 0) "Silent $toVersion upgrade failed"
$after = Assert-Installed $toVersion
[ordered]@{ installed = $after; installerExitCode = $upgrade.ExitCode; currentSession = (Get-Process -Id $PID).SessionId;
    processes = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('CyberFi.exe', 'explorer.exe') } |
        Select-Object Name, ProcessId, ParentProcessId, SessionId, ExecutablePath, CommandLine) } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evidence 'post-upgrade-diagnostic.json') -Encoding utf8
$deadline = (Get-Date).AddSeconds(120)
while (-not (Test-Path -LiteralPath $env:HAPPY_DESKTOP_SMOKE_REPORT) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
$hiddenRelaunch = Test-Path -LiteralPath $env:HAPPY_DESKTOP_SMOKE_REPORT
$nativeWindowEvidence = @()
if ($hiddenRelaunch) {
    Assert-Smoke $env:HAPPY_DESKTOP_SMOKE_REPORT
} else {
    # NSIS ExecShellAsUser delegates to Explorer, which can omit the installer's
    # QA-only environment. Observe the real automatic launch on this disposable
    # runner without activating, launching, or photographing any window.
    Add-Type -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool IsWindowVisible(System.IntPtr window);' -Name NativeWindows -Namespace CyberFiQA
    $nativeWindowEvidence = @(Get-Process -Name CyberFi -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -eq $exe -and $_.StartTime -ge $started -and $_.MainWindowHandle -ne 0 -and
        [CyberFiQA.NativeWindows]::IsWindowVisible($_.MainWindowHandle) -and $_.MainWindowTitle -eq 'CyberFi'
    } | Select-Object Id, Path, StartTime, SessionId, MainWindowTitle, MainWindowHandle)
    [ordered]@{ installed = $after; installerExitCode = $upgrade.ExitCode; observedNativeWindows = $nativeWindowEvidence;
        currentSession = (Get-Process -Id $PID).SessionId;
        processes = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('CyberFi.exe', 'explorer.exe') } |
            Select-Object Name, ProcessId, ParentProcessId, SessionId, ExecutablePath, CommandLine) } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evidence 'post-upgrade-diagnostic.json') -Encoding utf8
    Assert-True ($nativeWindowEvidence.Count -gt 0) 'No automatic owned CyberFi launch or visible native window was observed; inspect post-upgrade-diagnostic.json'
    foreach ($process in @(Get-Process -Id $nativeWindowEvidence.Id -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })) {
        $null = $process.CloseMainWindow()
        if (-not $process.WaitForExit(10000)) { & taskkill.exe /PID $process.Id /T /F | Out-Null }
    }
}
$deadline = (Get-Date).AddSeconds(30)
do {
    $running = @(Get-Process -Name CyberFi -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
    if ($running.Count) { Start-Sleep -Milliseconds 250 }
} while ($running.Count -and (Get-Date) -lt $deadline)
Assert-True ($running.Count -eq 0) 'Automatically relaunched app did not finish its smoke and flush settings'
foreach ($path in $preserve) {
    if ($path -eq $mcp) {
        $bytes = [IO.File]::ReadAllBytes($path)
        Assert-True ($bytes.Length -ge $mcpOriginalLength) 'Existing MCP configuration was truncated'
        $prefix = [byte[]]::new($mcpOriginalLength)
        [Array]::Copy($bytes, $prefix, $prefix.Length)
        Assert-True ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($prefix)) -ceq $hashes[$path]) 'Existing MCP bytes changed; only appended defaults are allowed'
    } else {
        Assert-True ((Get-FileHash $path -Algorithm SHA256).Hash -ceq $hashes[$path]) "Settings/catalogue changed during upgrade: $path"
    }
}
if ($hiddenRelaunch) { Assert-True ((Get-Item $env:HAPPY_DESKTOP_SMOKE_REPORT).LastWriteTime -ge $started) 'Stale relaunch evidence' }
[ordered]@{ status = 'PASS'; fresh = $before; upgraded = $after; automaticRelaunch = $true;
    hiddenWindowsVerified = $hiddenRelaunch; nativeAutomaticWindow = $nativeWindowEvidence;
    preservedFiles = $preserve; existingMcpBytesPreserved = $true; installerArguments = '--updated /S --force-run';
    applicationUpdaterDownloadUiTested = $false; note = 'Released installer path tested; app download/button/feed path is a separate test.'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding utf8
"Real released $fromVersion install -> $toVersion silent upgrade and automatic relaunch passed."
