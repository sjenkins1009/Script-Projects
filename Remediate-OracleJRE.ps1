#Requires -Version 5.1
<#
.SYNOPSIS
    Upgrades Oracle JRE 8 to the newest release and removes the vulnerable older updates.

.DESCRIPTION
    Built for Microsoft Defender Vulnerability Management "vulnerabilities in Oracle Jre"
    findings, where TVM flags old jre1.8.0_xxx folders under Program Files\Java.

    - Looks up the newest Java 8 release on java.com at runtime, including its build number,
      and downloads the offline installers directly from Oracle (signature verified).
    - Compares full versions including build (e.g. 8.0.5110.33 = 8u511-b33). Oracle can
      re-release the same update as a new build for out-of-band security fixes (8u511 shipped
      as b31, b32 and b33), so "Update 511" alone does not mean compliant.
    - Inventories Oracle JRE from the Uninstall registry (x64 and x86) AND from the Java
      folders on disk. TVM flags files, so leftover folders matter as much as installs.
    - Stays on the major version: only Java 8 is upgraded/removed. Other Oracle JRE majors
      (6, 7, 9, 10 - all end-of-life) are reported, never touched. JDKs are reported only.
    - Installs only for architectures that already have Java 8 (x86 stays x86, x64 stays x64).
    - Removes older Java 8 updates only after the target version is verified installed for
      that architecture. Exception: an older build of the SAME update (e.g. 8u511-b32 when
      the target is 8u511-b33) shares its folder and MSI product code, so it is uninstalled
      immediately before the new build is installed.
    - Deletes leftover jre1.8.0_xxx folders older than the target that survive uninstall.

.PARAMETER InstallerX64
    Optional override. Path, UNC path or HTTPS URL to an Oracle JRE 8 x64 installer (.exe or
    .msi), e.g. for devices without internet access. Default: newest release from java.com.

.PARAMETER InstallerX86
    Same as InstallerX64 for the 32-bit (i586) installer.

.PARAMETER TargetVersion
    Optional override of the minimum compliant version, as '8u511-b33', '8u511' or
    '8.0.5110.33'. Default: the newest release on java.com (or the supplied installer's version).

.PARAMETER KeepOldVersions
    Install/verify the target version but do not uninstall older updates or delete folders.

.PARAMETER KeepOrphanFolders
    Uninstall older updates but leave any leftover jre1.8.0_xxx folders on disk.

.PARAMETER InstallTimeoutMinutes
    How long to wait for each install/uninstall before stopping it and failing. Default 20.

.EXAMPLE
    .\Remediate-OracleJRE.ps1
    Pulls the newest Java 8 from Oracle and remediates.

.EXAMPLE
    .\Remediate-OracleJRE.ps1 -WhatIf
    Dry run: logs what would be installed, uninstalled and deleted without changing anything.

.EXAMPLE
    .\Remediate-OracleJRE.ps1 -InstallerX64 '\\fs01\deploy\jre-8u511-windows-x64.exe' -InstallerX86 '\\fs01\deploy\jre-8u511-windows-i586.exe'
    Uses staged installers instead of downloading.

.NOTES
    Run as SYSTEM or an elevated admin. Relaunches itself in 64-bit PowerShell when started
    from a 32-bit RMM agent.
    Exit codes: 0 = compliant, 3010 = compliant but reboot pending, 1 = failure / not compliant.
    Log: %ProgramData%\JavaRemediation\Remediate-OracleJRE.log (installer/uninstall logs alongside)
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallerX64,
    [string]$InstallerX86,
    [string]$TargetVersion,
    [switch]$KeepOldVersions,
    [switch]$KeepOrphanFolders,
    [ValidateRange(1, 240)][int]$InstallTimeoutMinutes = 20,
    [string]$LogPath = "$env:ProgramData\JavaRemediation\Remediate-OracleJRE.log"
)

$ErrorActionPreference = 'Stop'
$Major = 8
$ReleasePage = 'https://www.java.com/en/download/manual.jsp'
$DownloadDir = Join-Path $env:TEMP 'JavaRemediation'

#region 64-bit relaunch (32-bit RMM agents see redirected registry and Program Files)
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and -not [Environment]::Is64BitProcess) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($p in $PSBoundParameters.GetEnumerator()) {
        if ($p.Value -is [switch]) { if ($p.Value.IsPresent) { $argList += "-$($p.Key)" } }
        else { $argList += "-$($p.Key)", "$($p.Value)" }
    }
    & "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe" @argList
    exit $LASTEXITCODE
}
#endregion

#region Helpers
function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try { [IO.File]::AppendAllText($LogPath, $line + [Environment]::NewLine) } catch { }
}

# Java 8 file/registry versions encode update and build as 8.0.<update*10>.<build>, e.g. 8u511-b33 = 8.0.5110.33
function New-JavaVersion([int]$Update, [int]$Build = 0) { [version]::new($Major, 0, $Update * 10, $Build) }

function Format-JavaVersion([version]$Version) {
    if (-not $Version) { return 'unknown version' }
    '{0}u{1}-b{2}' -f $Version.Major, [math]::Floor($Version.Build / 10), [math]::Max($Version.Revision, 0)
}

# Accepts '8u511-b33', '8u511', '511' or '8.0.5110.33'.
function ConvertTo-JavaVersion([string]$Text) {
    if ($Text -match '^(?:\d+u)?(\d+)(?:-b(\d+))?$') { return New-JavaVersion $Matches[1] ([int]$Matches[2]) }
    $v = $null
    if ([version]::TryParse($Text, [ref]$v)) { return [version]::new($v.Major, $v.Minor, [math]::Max($v.Build, 0), [math]::Max($v.Revision, 0)) }
    throw "Unrecognized version '$Text'. Use 8u511-b33, 8u511 or 8.0.5110.33."
}

# Full version of a Java folder from its executables; $null if none are present.
function Get-FolderVersion([string]$Path) {
    foreach ($exe in 'bin\java.exe', 'bin\jabswitch.exe', 'bin\javaw.exe') {
        $file = Join-Path $Path $exe
        if (Test-Path -LiteralPath $file) {
            $v = (Get-Item -LiteralPath $file).VersionInfo
            if ($v.FileMajorPart -gt 0) { return [version]::new($v.FileMajorPart, $v.FileMinorPart, $v.FileBuildPart, $v.FilePrivatePart) }
        }
    }
    return $null
}

$archInfo = [ordered]@{}
if ([Environment]::Is64BitOperatingSystem) {
    $archInfo['x64'] = @{ UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; JavaRoot = Join-Path $env:ProgramFiles 'Java'; Installer = $InstallerX64 }
    $archInfo['x86'] = @{ UninstallKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; JavaRoot = Join-Path ${env:ProgramFiles(x86)} 'Java'; Installer = $InstallerX86 }
}
else {
    $archInfo['x86'] = @{ UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; JavaRoot = Join-Path $env:ProgramFiles 'Java'; Installer = $InstallerX86 }
}

# Returns one object per Oracle JRE found, from the registry and from disk.
function Get-OracleJre {
    foreach ($arch in $archInfo.Keys) {
        $info = $archInfo[$arch]

        # -LiteralPath: key names like "Bomgar Jump Client [host-ID]" are invalid wildcard patterns
        foreach ($key in Get-ChildItem -LiteralPath $info.UninstallKey -ErrorAction SilentlyContinue) {
            # Read only the values needed: Get-ItemProperty reads every value and throws
            # "Specified cast is not valid" when another app's key holds malformed data.
            try {
                $props = [pscustomobject]@{
                    DisplayName     = $key.GetValue('DisplayName')
                    Publisher       = $key.GetValue('Publisher')
                    DisplayVersion  = $key.GetValue('DisplayVersion')
                    InstallLocation = $key.GetValue('InstallLocation')
                }
            }
            catch { continue }
            if ($props.Publisher -notmatch 'Oracle' -or $props.DisplayName -notmatch '^Java(?:\(TM\))? (\d+) Update (\d+)') { continue }
            $maj = [int]$Matches[1]; $upd = [int]$Matches[2]
            $ver = $null
            if (-not [version]::TryParse([string]$props.DisplayVersion, [ref]$ver) -or $ver.Major -ne $maj) { $ver = New-JavaVersion $upd }
            $code = if ($key.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $key.PSChildName } else { $null }
            [pscustomobject]@{ Source = 'Registry'; Arch = $arch; Major = $maj; Update = $upd; Version = $ver; Name = $props.DisplayName; ProductCode = $code; Path = $props.InstallLocation }
        }

        if (-not (Test-Path -LiteralPath $info.JavaRoot)) { continue }
        foreach ($dir in Get-ChildItem -LiteralPath $info.JavaRoot -Directory -ErrorAction SilentlyContinue) {
            # Skip links like the family junction jre-1.8 -> jre1.8.0_xxx (handled by Remove-StaleJavaLinks)
            if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($dir.Name -notmatch '^jre(?:1\.(\d+)\.0_(\d+)|-?(\d+))') { continue }
            $folderMatch = $Matches.Clone()
            $ver = Get-FolderVersion $dir.FullName
            if ($folderMatch[1]) { $maj = [int]$folderMatch[1]; $upd = [int]$folderMatch[2] }
            else {
                # Older folder styles (jre7, jre8, jre-9.0.4): update comes from the executables
                $maj = [int]$folderMatch[3]
                $upd = if ($ver) { [int][math]::Floor($ver.Build / 10) } else { $null }
            }
            if (-not $ver -and $null -ne $upd -and $maj -eq $Major) { $ver = New-JavaVersion $upd }
            [pscustomobject]@{ Source = 'Disk'; Arch = $arch; Major = $maj; Update = $upd; Version = $ver; Name = $dir.Name; ProductCode = $null; Path = $dir.FullName }
        }
    }
}

# Reads the newest Java 8 release, its build and the Windows offline installer links from java.com.
function Get-LatestJreRelease {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    $html = (Invoke-WebRequest -Uri $ReleasePage -UseBasicParsing).Content

    if ($html -notmatch 'Version (\d+) Update (\d+)') { throw "Could not find the current Java version on $ReleasePage" }
    if ([int]$Matches[1] -ne $Major) { throw "java.com now publishes Java $($Matches[1]), not Java $Major - review before upgrading majors." }
    $update = [int]$Matches[2]

    $release = @{}
    $links = @{ x64 = 'Windows Offline \(64-bit\)'; x86 = 'Windows Offline' }
    foreach ($arch in $links.Keys) {
        if ($html -notmatch "<a[^>]+href=`"(https://javadl\.oracle\.com/[^`"]+)`"[^>]*>\s*$($links[$arch])\s*</a>") {
            throw "Could not find the $arch offline installer link on $ReleasePage"
        }
        $release[$arch] = $Matches[1]
    }

    # The download redirects to .../jdk/8u511-b33/..., which gives the build without downloading
    $build = 0
    try {
        $head = Invoke-WebRequest -Uri $release['x64'] -Method Head -UseBasicParsing
        if ($head.BaseResponse.ResponseUri.AbsolutePath -match "/$($Major)u$update-b(\d+)/") { $build = [int]$Matches[1] }
    }
    catch { }
    if (-not $build) { Write-Log "Could not read the build number from the download link - will use the installer's file version." WARN }
    $release['Version'] = New-JavaVersion $update $build
    return $release
}

# Copies/downloads the installer if needed and confirms it is Oracle-signed.
function Resolve-Installer([string]$Source, [string]$Arch) {
    if ($Source -match '^https?://') {
        [IO.Directory]::CreateDirectory($DownloadDir) | Out-Null
        # Unique name: an installer left running by an interrupted run keeps its file locked
        $file = Join-Path $DownloadDir "jre-$Major-$Arch-$(Get-Date -Format 'yyyyMMddHHmmss').exe"
        if ($Source -match '\.msi$') { $file = [IO.Path]::ChangeExtension($file, '.msi') }
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        Write-Log "[$Arch] Downloading $Source"
        Invoke-WebRequest -Uri $Source -OutFile $file -UseBasicParsing
        $Source = $file
    }
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Installer not found: $Source" }

    $sig = Get-AuthenticodeSignature -LiteralPath $Source
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O="?Oracle') {
        throw "Installer is not validly signed by Oracle ($($sig.Status)): $Source"
    }
    return $Source
}

# Full version of an installer: exe file version (8.0.5110.33), else "8u511-b33" in the filename.
function Get-InstallerVersion([string]$Path) {
    if ($Path -match '\.exe$') {
        $v = (Get-Item -LiteralPath $Path).VersionInfo
        if ($v.FileMajorPart -eq $Major -and $v.FileBuildPart -gt 0) { return [version]::new($v.FileMajorPart, $v.FileMinorPart, $v.FileBuildPart, $v.FilePrivatePart) }
    }
    if ((Split-Path $Path -Leaf) -match "$($Major)u(\d+)(?:-b(\d+))?") { return New-JavaVersion $Matches[1] ([int]$Matches[2]) }
    return $null
}

# Stops anything running out of the Oracle Java folders (java, javaw, javaws, jp2launcher, jusched...).
# Called before every install/uninstall/delete, since users can relaunch Java apps mid-run.
function Stop-JavaProcesses {
    $roots = @($archInfo.Values | ForEach-Object { $_.JavaRoot })
    $roots += @($env:CommonProgramFiles, ${env:CommonProgramFiles(x86)} | Where-Object { $_ } | ForEach-Object { Join-Path $_ 'Java' })
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $procPath = $_.Path
        $procPath -and ($roots | Where-Object { $procPath -like "$_\*" })
    }
    foreach ($proc in $procs) {
        if ($PSCmdlet.ShouldProcess("$($proc.Name) (PID $($proc.Id))", 'Stop process')) {
            Write-Log "Stopping $($proc.Name) (PID $($proc.Id)) - $($proc.Path)"
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

# Waits until no other install is running: Windows Installer busy (the _MSIExecute mutex) or a Java
# installer still running, e.g. from an earlier run that was interrupted. Returns $false on timeout.
function Wait-InstallerIdle {
    $deadline = (Get-Date).AddMinutes($InstallTimeoutMinutes)
    $logged = $false
    while ($true) {
        $busy = @()
        try {
            $mutex = $null
            if ([Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [ref]$mutex)) { $mutex.Dispose(); $busy += 'Windows Installer' }
        }
        catch { $busy += 'Windows Installer' }  # exists but access denied
        $busy += @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.Path -and ($_.Path -like "$DownloadDir\*" -or $_.Name -match '^jre-\d+u\d+')
            } | ForEach-Object { "$($_.Name) (PID $($_.Id))" })

        if (-not $busy) { return $true }
        if ((Get-Date) -gt $deadline) { Write-Log "Another installation is still running after $InstallTimeoutMinutes minutes: $($busy -join ', ')" ERROR; return $false }
        if (-not $logged) { Write-Log "Waiting for another installation to finish: $($busy -join ', ')" WARN; $logged = $true }
        Start-Sleep -Seconds 15
    }
}

# Runs an installer and waits for that process only. Start-Process -Wait would also wait for every
# child it spawns, and the Java installer can leave jusched.exe running forever.
# Waits for other installs first, and retries once on 1618 (another installation in progress).
function Invoke-Setup([string]$FilePath, [string]$Arguments) {
    foreach ($attempt in 1, 2) {
        if (-not (Wait-InstallerIdle)) { return 1618 }
        Stop-JavaProcesses
        $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden
        $null = $proc.Handle  # keeps the handle so ExitCode is readable after exit
        if (-not $proc.WaitForExit($InstallTimeoutMinutes * 60000)) {
            Write-Log "$(Split-Path $FilePath -Leaf) still running after $InstallTimeoutMinutes minutes - stopping it." ERROR
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            return 1460  # ERROR_TIMEOUT - not -1, which installers return themselves
        }
        if ($proc.ExitCode -ne 1618 -or $attempt -eq 2) { return $proc.ExitCode }
        Write-Log "$(Split-Path $FilePath -Leaf) returned 1618 (another installation in progress) - waiting and retrying." WARN
    }
}

function Install-Jre([string]$Installer, [string]$Arch) {
    $props = 'INSTALL_SILENT=1 AUTO_UPDATE=0 WEB_ANALYTICS=0 SPONSORS=0 REBOOT=0'
    $setupLog = Join-Path (Split-Path $LogPath) "jre-install-$Arch.log"
    Write-Log "[$Arch] Installer log: $setupLog"
    if ($Installer -match '\.msi$') {
        return Invoke-Setup msiexec.exe "/i `"$Installer`" /qn /norestart $props /l*v `"$setupLog`""
    }
    # The Java exe wrapper exits 255 before installing anything if it rejects its command line,
    # so fall back to fewer options: without /L, then plain /s with auto-update off.
    $attempts = @("/s $props /L $setupLog", "/s $props", '/s AUTO_UPDATE=0')
    if ($setupLog -match '\s') { $attempts = $attempts[1..2] }  # /L can't take a quoted path
    foreach ($arguments in $attempts) {
        $code = Invoke-Setup $Installer $arguments
        if ($code -in 0, 3010, 1618, 1460) { return $code }
        Write-Log "[$Arch] Installer exited $code with arguments '$arguments'." WARN
    }
    return $code
}

# Windows Installer keys use a "packed" GUID: {71024AE4-039E-4CA4-87B4-2F32180481F0} -> 4EA42017E930...
function ConvertTo-PackedGuid([string]$ProductCode) {
    $g = $ProductCode -replace '[{}-]', ''
    $rev = { param($s) -join ($s.ToCharArray()[($s.Length - 1)..0]) }
    $pairs = -join (0..7 | ForEach-Object { $p = $g.Substring(16 + $_ * 2, 2); $p[1] + $p[0] })
    (& $rev $g.Substring(0, 8)) + (& $rev $g.Substring(8, 4)) + (& $rev $g.Substring(12, 4)) + $pairs
}

$MsiHive = [Microsoft.Win32.Registry]::LocalMachine
$MsiUserData = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18'

# $true if Windows Installer's cached copy of the product's MSI exists and opens. Without it the
# product can't be uninstalled, and Oracle's installer crashes (exit 255) when it inspects it.
function Test-MsiCache([string]$ProductCode) {
    $key = $MsiHive.OpenSubKey("$MsiUserData\Products\$(ConvertTo-PackedGuid $ProductCode)\InstallProperties")
    if (-not $key) { return $false }
    try { $package = $key.GetValue('LocalPackage') } finally { $key.Close() }
    if (-not $package -or -not (Test-Path -LiteralPath $package)) { return $false }
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($package, 0))
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
        return $true
    }
    catch { return $false }
}

# Deletes a product's Windows Installer and uninstall registration when its cached MSI is gone,
# the same cleanup Microsoft's Program Install and Uninstall troubleshooter performs. Files are
# left for the leftover-folder step.
function Remove-MsiRegistration($Entry, [string]$Arch) {
    $packed = ConvertTo-PackedGuid $Entry.ProductCode
    if (-not $PSCmdlet.ShouldProcess("[$Arch] $($Entry.Name) $($Entry.ProductCode)", 'Remove broken Windows Installer registration')) { return $true }
    Write-Log "[$Arch] Removing Windows Installer registration for $($Entry.Name) $($Entry.ProductCode) (packed $packed)"

    $uninstallPath = ($archInfo[$Arch].UninstallKey -replace '^HKLM:\\', '') + "\$($Entry.ProductCode)"
    $javaSoft = if ($Arch -eq 'x86' -and [Environment]::Is64BitOperatingSystem) { 'SOFTWARE\WOW6432Node\JavaSoft' } else { 'SOFTWARE\JavaSoft' }
    $props = $MsiHive.OpenSubKey("$MsiUserData\Products\$packed\InstallProperties")
    $package = if ($props) { $props.GetValue('LocalPackage'); $props.Close() }

    foreach ($path in "SOFTWARE\Classes\Installer\Products\$packed", "SOFTWARE\Classes\Installer\Features\$packed",
        "$MsiUserData\Products\$packed", $uninstallPath, "$javaSoft\Java Runtime Environment\1.$Major.0_$($Entry.Update)") {
        if ($MsiHive.OpenSubKey($path)) { $MsiHive.DeleteSubKeyTree($path); Write-Log "[$Arch]   deleted HKLM\$path" }
    }

    # Component and upgrade-code keys list the product as a value; drop the value, and the key if it was the last one
    $removed = 0
    foreach ($parent in "$MsiUserData\Components", 'SOFTWARE\Classes\Installer\UpgradeCodes') {
        $root = $MsiHive.OpenSubKey($parent)
        if (-not $root) { continue }
        $names = $root.GetSubKeyNames(); $root.Close()
        foreach ($name in $names) {
            $sub = $MsiHive.OpenSubKey("$parent\$name", $true)
            if (-not $sub) { continue }
            try {
                if ($sub.GetValueNames() -contains $packed) {
                    $sub.DeleteValue($packed); $removed++
                    if ($sub.ValueCount -eq 0 -and $sub.SubKeyCount -eq 0) { $sub.Close(); $sub = $null; $MsiHive.DeleteSubKey("$parent\$name") }
                }
            }
            finally { if ($sub) { $sub.Close() } }
        }
    }
    Write-Log "[$Arch]   removed product from $removed component/upgrade-code entries"
    if ($package -and (Test-Path -LiteralPath $package)) { Remove-Item -LiteralPath $package -Force -ErrorAction SilentlyContinue }
    return $true
}

# Java 8 installers create a hidden family junction (Java\jre-1.8 -> jre1.8.0_xxx). If it points at a
# JRE that is no longer registered, Oracle's installer refuses to run ("FamilyJunctionValidator: jre-1.8
# exists, and no JRE is registered to be installed there", exit -1). Removes only the link, never its target.
function Remove-StaleJavaLinks([string]$Arch) {
    $root = $archInfo[$Arch].JavaRoot
    if (-not (Test-Path -LiteralPath $root)) { return }
    $registered = @(Get-OracleJre | Where-Object { $_.Arch -eq $Arch -and $_.Source -eq 'Registry' -and $_.Path } |
            ForEach-Object { $_.Path.TrimEnd('\') })
    $links = Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $_.Name -match '^jre-\d' }
    foreach ($link in $links) {
        $target = @((Get-Item -LiteralPath $link.FullName -Force).Target)[0]
        if ($target) { $target = $target.TrimEnd('\') }
        if ($target -and (Test-Path -LiteralPath $target) -and ($registered -contains $target)) { continue }
        if ($PSCmdlet.ShouldProcess("$($link.FullName) -> $target", 'Remove stale Java family link')) {
            Write-Log "[$Arch] Removing stale link $($link.FullName) -> $target (target not a registered JRE)"
            [IO.Directory]::Delete($link.FullName, $false)  # deletes the junction itself, not the folder it points to
        }
    }
}

# Silently uninstalls a registered JRE. Returns $false on failure.
# Falls back to removing the registration when the cached MSI is missing or damaged.
function Uninstall-Jre($Entry, [string]$Arch) {
    if (-not $Entry.ProductCode) { Write-Log "[$Arch] $($Entry.Name) has no MSI product code - cannot uninstall silently." WARN; return $false }
    if (-not $PSCmdlet.ShouldProcess("[$Arch] $($Entry.Name) $(Format-JavaVersion $Entry.Version) $($Entry.ProductCode)", 'Uninstall')) { return $true }
    Stop-JavaProcesses
    if (-not (Test-MsiCache $Entry.ProductCode)) {
        Write-Log "[$Arch] Windows Installer's cached MSI for $($Entry.Name) is missing or damaged - it can't be uninstalled normally." WARN
        return Remove-MsiRegistration $Entry $Arch
    }
    Write-Log "[$Arch] Uninstalling $($Entry.Name) ($(Format-JavaVersion $Entry.Version)) $($Entry.ProductCode)"
    $setupLog = Join-Path (Split-Path $LogPath) "jre-uninstall-$Arch-$($Entry.Update).log"
    $exitCode = Invoke-Setup msiexec.exe "/x $($Entry.ProductCode) /qn /norestart /l*v `"$setupLog`""
    switch ($exitCode) {
        { $_ -in 0, 1605, 1614 } { Write-Log "[$Arch] Removed $($Entry.Name) (exit $_)"; return $true }
        3010 { Write-Log "[$Arch] Removed $($Entry.Name) - reboot required"; $script:rebootRequired = $true; return $true }
        { $_ -in 1610, 1612 } {
            Write-Log "[$Arch] Uninstall of $($Entry.Name) can't find its source (exit $_)." WARN
            return Remove-MsiRegistration $Entry $Arch
        }
        default { Write-Log "[$Arch] Uninstall of $($Entry.Name) failed with exit code $_" ERROR; return $false }
    }
}
#endregion

#region Main
try { [IO.Directory]::CreateDirectory((Split-Path $LogPath)) | Out-Null } catch { }
Write-Log "===== Oracle JRE $Major remediation starting on $env:COMPUTERNAME$(if ($WhatIfPreference) { ' (WhatIf)' }) ====="

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log 'Must run as SYSTEM or elevated administrator.' ERROR
    exit 1
}

$targetOverride = $null
if ($TargetVersion) {
    try { $targetOverride = ConvertTo-JavaVersion $TargetVersion } catch { Write-Log $_.Exception.Message ERROR; exit 1 }
}

$inventory = @(Get-OracleJre)
if (-not $inventory) { Write-Log 'No Oracle JRE found. Nothing to do.'; exit 0 }
foreach ($i in $inventory) { Write-Log "Found [$($i.Arch)] [$($i.Source)] Java $($i.Major) Update $($i.Update) ($(Format-JavaVersion $i.Version)) - $($i.Name) $($i.Path)" }

foreach ($i in $inventory | Where-Object { $_.Major -ne $Major }) {
    Write-Log "[$($i.Arch)] Java $($i.Major) ($($i.Name)) is end-of-life with no in-major fix. Not touched - remove or migrate manually." WARN
}
foreach ($root in $archInfo.Values | ForEach-Object { $_.JavaRoot } | Where-Object { Test-Path -LiteralPath $_ }) {
    foreach ($jdk in Get-ChildItem -LiteralPath $root -Directory -Filter 'jdk*' -ErrorAction SilentlyContinue) {
        Write-Log "JDK present (not handled by this script): $($jdk.FullName)" WARN
    }
}

$failed = $false
$rebootRequired = $false

# Newest release from java.com, used for any architecture without a supplied installer
$latest = $null
$needsLatest = $archInfo.Keys | Where-Object { $a = $_; -not $archInfo[$a].Installer -and ($inventory | Where-Object { $_.Arch -eq $a -and $_.Major -eq $Major }) }
if ($needsLatest) {
    try {
        $latest = Get-LatestJreRelease
        Write-Log "Newest release on java.com: $(Format-JavaVersion $latest.Version) ($($latest.Version))"
    }
    catch {
        Write-Log "Could not look up the newest Java $Major release: $($_.Exception.Message)" ERROR
        $failed = $true
    }
}

foreach ($arch in $archInfo.Keys) {
    $current = @($inventory | Where-Object { $_.Arch -eq $arch -and $_.Major -eq $Major })
    if (-not $current) { Write-Log "[$arch] No Java $Major present - skipping (not installing a new architecture)."; continue }

    try {
        $source = $archInfo[$arch].Installer
        if (-not $source -and $latest) { $source = $latest[$arch] }

        $target = $targetOverride
        if (-not $target -and -not $archInfo[$arch].Installer -and $latest -and $latest.Version.Revision -gt 0) { $target = $latest.Version }

        # Only download when the target isn't already installed
        $alreadyCurrent = $target -and ($current | Where-Object { $_.Source -eq 'Registry' -and $_.Version -ge $target })
        $installer = $null
        if ($source -and -not $alreadyCurrent) { $installer = Resolve-Installer $source $arch }
        $installerVersion = if ($installer) { Get-InstallerVersion $installer } else { $null }

        if (-not $target) { $target = $installerVersion }
        if (-not $target) { throw "Cannot determine the target version. Supply -TargetVersion or -Installer$($arch.ToUpper())." }
        if ($installerVersion -and $installerVersion -lt $target) { throw "Installer is $(Format-JavaVersion $installerVersion), older than target $(Format-JavaVersion $target)." }
        Write-Log "[$arch] Target: $(Format-JavaVersion $target) ($target) or newer"

        # 1. Get the target version in place
        if ($current | Where-Object { $_.Source -eq 'Registry' -and $_.Version -ge $target }) {
            Write-Log "[$arch] $(Format-JavaVersion $target) or newer already installed."
        }
        else {
            if (-not $installer) { throw "$(Format-JavaVersion $target) is not installed and no installer was supplied for $arch." }
            Stop-JavaProcesses

            # Oracle's installer inspects every installed Java's cached MSI and crashes (exit 255) if one is
            # missing or damaged. Older Java 8 versions are being replaced anyway, so clear those first.
            $brokenCache = @(Get-OracleJre) | Where-Object {
                $_.Source -eq 'Registry' -and $_.ProductCode -and $_.Version -lt $target -and -not (Test-MsiCache $_.ProductCode)
            }
            foreach ($b in $brokenCache) {
                if ($b.Major -ne $Major) {
                    Write-Log "[$($b.Arch)] $($b.Name) has a missing/damaged cached MSI and may make the installer crash. Not touched (Java $($b.Major))." WARN
                    continue
                }
                Write-Log "[$($b.Arch)] $($b.Name) has a missing/damaged cached MSI, which makes Oracle's installer crash - removing it before install."
                if (-not (Uninstall-Jre $b $b.Arch)) { throw "Could not remove broken $($b.Name) before installing $(Format-JavaVersion $target)." }
            }
            Remove-StaleJavaLinks $arch

            # An older build of the same update (e.g. 8u511-b32) occupies the same folder and product
            # code, so the new build can't install beside it - remove it first.
            $sameUpdate = @($current | Where-Object { $_.Source -eq 'Registry' -and $_.Update -eq [math]::Floor($target.Build / 10) -and $_.Version -lt $target })
            foreach ($s in $sameUpdate) {
                Write-Log "[$arch] $($s.Name) is an older build ($(Format-JavaVersion $s.Version)) of the target update - removing before install."
                if (-not (Uninstall-Jre $s $arch)) { throw "Could not remove $($s.Name) before installing $(Format-JavaVersion $target)." }
            }

            if ($PSCmdlet.ShouldProcess("[$arch] $installer", 'Install')) {
                Write-Log "[$arch] Installing $installer ($(Format-JavaVersion $installerVersion))"
                $code = Install-Jre $installer $arch
                Write-Log "[$arch] Installer exit code: $code"
                $stillRegistered = @(Get-OracleJre) | Where-Object { $_.Arch -eq $arch -and $_.Major -eq $Major -and $_.Source -eq 'Registry' }
                $notice = if ($stillRegistered) { 'Older versions left in place.' } else { "$arch has no Java $Major registered (older files remain on disk) - investigate." }
                if ($code -eq 3010) { $rebootRequired = $true }
                elseif ($code -ne 0) { throw "Installer failed with exit code $code. $notice" }

                $verified = @(Get-OracleJre) | Where-Object { $_.Arch -eq $arch -and $_.Major -eq $Major -and $_.Source -eq 'Registry' -and $_.Version -ge $target }
                if (-not $verified) { throw "Installer returned $code but $(Format-JavaVersion $target) is not registered. $notice" }
                Write-Log "[$arch] Verified: $($verified[0].Name) ($(Format-JavaVersion $verified[0].Version))"
            }
        }

        if ($KeepOldVersions) { Write-Log "[$arch] -KeepOldVersions set - leaving older updates in place."; continue }

        # 2. Uninstall older registered versions of the same major
        $old = @(Get-OracleJre) | Where-Object { $_.Arch -eq $arch -and $_.Major -eq $Major -and $_.Source -eq 'Registry' -and $_.Version -lt $target }
        foreach ($o in $old) {
            if (-not (Uninstall-Jre $o $arch)) { $failed = $true }
        }

        # 3. Delete leftover folders the uninstallers missed (these are what TVM keeps flagging)
        if ($KeepOrphanFolders) { Write-Log "[$arch] -KeepOrphanFolders set - leaving leftover folders."; continue }
        $leftover = @(Get-OracleJre) | Where-Object { $_.Arch -eq $arch -and $_.Major -eq $Major -and $_.Source -eq 'Disk' }
        foreach ($f in $leftover) {
            if ($null -eq $f.Version) { Write-Log "[$arch] Cannot determine version of $($f.Path) - not deleting." WARN; continue }
            if ($f.Version -ge $target) { continue }
            if ($PSCmdlet.ShouldProcess($f.Path, 'Delete leftover folder')) {
                Stop-JavaProcesses
                Write-Log "[$arch] Deleting leftover folder $($f.Path) ($(Format-JavaVersion $f.Version))"
                try { Remove-Item -LiteralPath $f.Path -Recurse -Force }
                catch { Write-Log "[$arch] Could not fully delete $($f.Path): $($_.Exception.Message)" ERROR; $failed = $true }
            }
        }
    }
    catch {
        Write-Log "[$arch] $($_.Exception.Message)" ERROR
        $failed = $true
    }
}

if (Test-Path -LiteralPath $DownloadDir) { Remove-Item -LiteralPath $DownloadDir -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false }

# Final state
Write-Log '----- Final state -----'
$final = @(Get-OracleJre)
foreach ($i in $final) { Write-Log "[$($i.Arch)] [$($i.Source)] Java $($i.Major) Update $($i.Update) ($(Format-JavaVersion $i.Version)) - $($i.Path)" }

if ($failed) { Write-Log 'Completed with errors.' ERROR; exit 1 }
if ($rebootRequired) { Write-Log 'Completed. Reboot required to finish.'; exit 3010 }
Write-Log 'Completed successfully.'
exit 0
#endregion
