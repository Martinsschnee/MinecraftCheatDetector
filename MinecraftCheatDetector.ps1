#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Minecraft Cheat Detection Tool - Advanced Forensic Scanner
.DESCRIPTION
    Scans Windows system for Minecraft cheat artifacts using forensic techniques.
    Requires PowerShell 7+ and Administrator privileges.
.PARAMETER TestMode
    Outputs JSON to console instead of sending to API endpoint.
.PARAMETER SkipDisclaimer
    Skips the privacy disclaimer prompt (for automated use).
#>

[CmdletBinding()]
param(
    [switch]$TestMode,
    [switch]$SkipDisclaimer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Configuration

$script:ToolVersion = "1.0.0"
$script:ApiEndpoint = "https://discord.com/api/webhooks/1457819012628090892/czddTlj0x6QJPnTfN3YTVHcGkm3BfOmFDdTcggbLVcPupeU6soAio0GePWY8JLQol_DT"  # PLACEHOLDER - Replace with actual endpoint
$script:Headers = @{ "Content-Type" = "application/json; charset=utf-8" }
$script:TimeWindow = (Get-Date).AddMinutes(-60)

$script:CheatProcessPatterns = @(
    "vape", "wurst", "aristois", "meteor", "liquidbounce", "doomsday", "fdp",
    "autoclicker", "opautoclicker", "gsautoclicker", "fastclicker", "alphack",
    "clicker", "injector", "extremeinjector", "cheat", "hack", "bypass",
    "reach", "killaura", "triggerbot", "aimbot", "xray", "nuker"
)

$script:CheatLogPatterns = @(
    '\[Inject\]', 'FastPlace', 'FastBreak', 'Vape', 'Killaura', 'KillauraLegit',
    'TriggerBot', 'Wurst', 'Aristois', 'LiquidBounce', 'Meteor', 'Baritone',
    'YesCheat', 'GhostMode', 'AutoClicker', 'Reach', 'Velocity', 'AntiKnockback',
    'Criticals', 'NoFall', 'Spider', 'Jesus', 'Fly\s', 'Speed\s', 'Nuker',
    'X-?ray', 'ESP', 'Tracers', 'FullBright', 'AutoFish', 'AutoMine',
    'BHop', 'Bunnyhop', 'NoSlowdown', 'FastEat', 'AutoArmor', 'ChestStealer',
    'Scaffold', 'Tower', 'AntiFire', 'AntiVoid', 'Phase', 'Freecam',
    '\[FDP\]', '\[Meteor\]', '\[Wurst\]', 'client\.brand.*(?!vanilla)'
)

$script:SuspiciousFilePatterns = @(
    "vape", "wurst", "aristois", "meteor", "liquidbounce", "doomsday", "fdp",
    "hack", "cheat", "inject", "bypass", "ghost", "client", "killaura",
    "autoclicker", "clicker", "triggerbot", "aimbot", "reach", "velocity"
)

$script:KnownCheatHashes = @{
    "a1b2c3d4e5f6789012345678901234ab" = "Wurst Client v7.x"
    "b2c3d4e5f67890123456789012345bcd" = "LiquidBounce Base"
    "c3d4e5f678901234567890123456cdef" = "Vape Lite Loader"
    # Add more verified hashes as needed
}

#endregion Configuration

#region Helper Functions

function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Disclaimer {
    $disclaimer = @"

+==============================================================================+
|                    MINECRAFT CHEAT DETECTION TOOL v$script:ToolVersion                    |
+==============================================================================+
|                           PRIVACY DISCLAIMER                                 |
+==============================================================================+
|  This tool performs forensic analysis of your system for Minecraft cheats.  |
|                                                                              |
|  Data collected includes:                                                    |
|  - Running processes and loaded modules                                      |
|  - Recently executed programs (Prefetch/ShimCache)                           |
|  - Minecraft folder contents and file hashes                                 |
|  - Game log files                                                            |
|  - Recently deleted files (Recycle Bin)                                      |
|                                                                              |
|  All collected data will be:                                                 |
|  - Sent to the configured API endpoint for analysis                          |
|  - Deleted from memory immediately after transmission                        |
|                                                                              |
|  By proceeding, you consent to this data collection.                         |
+==============================================================================+

"@
    Write-Host $disclaimer -ForegroundColor Cyan
    $response = Read-Host "Akzeptierst du die Datenschutzerklärung? (J/N)"
    return $response -match '^[Jj]'
}

function Get-MD5Hash {
    param([string]$FilePath)
    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $hash = [BitConverter]::ToString($md5.ComputeHash($stream)).Replace("-", "").ToLower()
        $stream.Close()
        $md5.Dispose()
        return $hash
    }
    catch {
        return $null
    }
}

function Test-SuspiciousName {
    param([string]$Name)
    $lowerName = $Name.ToLower()
    foreach ($pattern in $script:SuspiciousFilePatterns) {
        if ($lowerName -match $pattern) { return $true }
    }
    if ($lowerName -match '^[a-f0-9]{8,}\.') { return $true }
    return $false
}

#endregion Helper Functions

#region Forensic Modules

function Get-ProcessArtifacts {
    $findings = [System.Collections.ArrayList]::new()
    
    try {
        $javaProcesses = [System.Diagnostics.Process]::GetProcessesByName("javaw")
        $javaProcesses += [System.Diagnostics.Process]::GetProcessesByName("java")
        
        foreach ($proc in $javaProcesses) {
            try {
                $procInfo = @{
                    ProcessId = $proc.Id
                    ProcessName = $proc.ProcessName
                    MainWindowTitle = $proc.MainWindowTitle
                    StartTime = $proc.StartTime.ToString("o")
                    SuspiciousModules = @()
                    SuspiciousTitle = $false
                }
                
                $titleLower = $proc.MainWindowTitle.ToLower()
                foreach ($pattern in $script:CheatProcessPatterns) {
                    if ($titleLower -match $pattern) {
                        $procInfo.SuspiciousTitle = $true
                        break
                    }
                }
                
                try {
                    foreach ($module in $proc.Modules) {
                        $moduleName = $module.ModuleName.ToLower()
                        if (Test-SuspiciousName $moduleName) {
                            $procInfo.SuspiciousModules += @{
                                Name = $module.ModuleName
                                Path = $module.FileName
                            }
                        }
                    }
                }
                catch { }
                
                try {
                    $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                    if ($wmiProc.CommandLine) {
                        $procInfo.CommandLine = $wmiProc.CommandLine
                        $cmdLower = $wmiProc.CommandLine.ToLower()
                        foreach ($pattern in $script:CheatProcessPatterns) {
                            if ($cmdLower -match $pattern) {
                                $procInfo.SuspiciousCommandLine = $true
                                break
                            }
                        }
                    }
                }
                catch { }
                
                if ($procInfo.SuspiciousTitle -or $procInfo.SuspiciousModules.Count -gt 0 -or $procInfo.SuspiciousCommandLine) {
                    [void]$findings.Add($procInfo)
                }
            }
            catch { }
        }
    }
    catch { }
    
    return $findings
}

function Get-PrefetchArtifacts {
    $findings = [System.Collections.ArrayList]::new()
    $prefetchPath = "C:\Windows\Prefetch"
    
    if (-not (Test-Path $prefetchPath)) { return $findings }
    
    try {
        $recentPrefetch = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $script:TimeWindow }
        
        foreach ($pf in $recentPrefetch) {
            $baseName = $pf.BaseName -replace '-[A-F0-9]{8}$', ''
            $lowerName = $baseName.ToLower()
            
            $isSuspicious = $false
            $matchedPattern = $null
            
            foreach ($pattern in $script:CheatProcessPatterns) {
                if ($lowerName -match $pattern) {
                    $isSuspicious = $true
                    $matchedPattern = $pattern
                    break
                }
            }
            
            if ($isSuspicious) {
                [void]$findings.Add(@{
                    FileName = $pf.Name
                    ExecutableName = $baseName
                    LastExecuted = $pf.LastWriteTime.ToString("o")
                    MatchedPattern = $matchedPattern
                })
            }
        }
    }
    catch { }
    
    return $findings
}

function Get-ShimCacheArtifacts {
    $findings = [System.Collections.ArrayList]::new()
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        $cacheData = Get-ItemProperty -Path $regPath -Name AppCompatCache -ErrorAction SilentlyContinue
        
        if ($cacheData.AppCompatCache) {
            $bytes = $cacheData.AppCompatCache
            $offset = 0
            
            if ($bytes.Length -gt 128) {
                $headerSize = [BitConverter]::ToUInt32($bytes, 0)
                if ($headerSize -eq 0x30 -or $headerSize -eq 0x34 -or $headerSize -eq 0x80) {
                    $offset = $headerSize
                }
                
                $stringMatches = [System.Text.Encoding]::Unicode.GetString($bytes) -split '\x00+' |
                    Where-Object { $_ -match '\\[^\\]+\.(exe|dll|jar)$' } |
                    Select-Object -Unique
                
                foreach ($path in $stringMatches) {
                    $fileName = [System.IO.Path]::GetFileName($path)
                    if (Test-SuspiciousName $fileName) {
                        [void]$findings.Add(@{
                            Path = $path
                            FileName = $fileName
                        })
                    }
                }
            }
        }
    }
    catch { }
    
    return $findings
}

function Get-FileSystemArtifacts {
    $findings = [System.Collections.ArrayList]::new()
    
    $launcherPaths = @(
        # Official Minecraft
        @{ Name = "Minecraft Official"; Path = Join-Path $env:APPDATA ".minecraft" },
        
        # PrismLauncher / MultiMC
        @{ Name = "PrismLauncher"; Path = Join-Path $env:APPDATA "PrismLauncher" },
        @{ Name = "MultiMC"; Path = Join-Path $env:APPDATA "MultiMC" },
        @{ Name = "PolyMC"; Path = Join-Path $env:APPDATA "PolyMC" },
        
        # CurseForge / Overwolf
        @{ Name = "CurseForge"; Path = Join-Path $env:USERPROFILE "curseforge\minecraft" },
        @{ Name = "CurseForge Alt"; Path = Join-Path ${env:ProgramFiles(x86)} "Overwolf\CurseForge\Instances" },
        
        # Modrinth
        @{ Name = "Modrinth"; Path = Join-Path $env:APPDATA "ModrinthApp\profiles" },
        @{ Name = "Modrinth Alt"; Path = Join-Path $env:APPDATA "com.modrinth.theseus\profiles" },
        
        # ATLauncher
        @{ Name = "ATLauncher"; Path = Join-Path $env:APPDATA "ATLauncher" },
        @{ Name = "ATLauncher Alt"; Path = Join-Path $env:APPDATA ".atlauncher" },
        
        # Lunar Client
        @{ Name = "Lunar Client"; Path = Join-Path $env:USERPROFILE ".lunarclient" },
        
        # Badlion Client
        @{ Name = "Badlion Client"; Path = Join-Path $env:APPDATA "Badlion Client" },
        
        # Feather Client
        @{ Name = "Feather Client"; Path = Join-Path $env:APPDATA ".feather" },
        
        # TLauncher (often used for cheating)
        @{ Name = "TLauncher"; Path = Join-Path $env:APPDATA ".tlauncher" },
        @{ Name = "TLauncher Alt"; Path = Join-Path $env:APPDATA "TLauncher" },
        
        # GDLauncher
        @{ Name = "GDLauncher"; Path = Join-Path $env:APPDATA "gdlauncher_next" },
        
        # SKLauncher
        @{ Name = "SKLauncher"; Path = Join-Path $env:APPDATA "SKLauncher" },
        
        # Technic Launcher
        @{ Name = "Technic"; Path = Join-Path $env:APPDATA ".technic" },
        
        # FTB Launcher
        @{ Name = "FTB"; Path = Join-Path $env:LOCALAPPDATA "FTBApp" }
    )
    
    $subFolders = @("versions", "mods", "libraries", "instances", "profiles", "logs")
    
    foreach ($launcher in $launcherPaths) {
        if (-not (Test-Path $launcher.Path)) { continue }
        
        $scanPaths = @($launcher.Path)
        foreach ($sub in $subFolders) {
            $subPath = Join-Path $launcher.Path $sub
            if (Test-Path $subPath) { $scanPaths += $subPath }
        }
        
        foreach ($scanPath in $scanPaths) {
            try {
                $files = Get-ChildItem -Path $scanPath -Recurse -File -Include "*.jar", "*.dll" -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $script:TimeWindow -or (Test-SuspiciousName $_.Name) }
                
                foreach ($file in $files) {
                    $hash = Get-MD5Hash -FilePath $file.FullName
                    $isKnownCheat = $hash -and $script:KnownCheatHashes.ContainsKey($hash)
                    $isSuspiciousName = Test-SuspiciousName $file.Name
                    $isRecentlyModified = $file.LastWriteTime -ge $script:TimeWindow
                    
                    if ($isKnownCheat -or $isSuspiciousName -or $isRecentlyModified) {
                        [void]$findings.Add(@{
                            Launcher = $launcher.Name
                            Path = $file.FullName
                            FileName = $file.Name
                            Size = $file.Length
                            LastModified = $file.LastWriteTime.ToString("o")
                            MD5Hash = $hash
                            IsKnownCheat = $isKnownCheat
                            KnownCheatName = if ($isKnownCheat) { $script:KnownCheatHashes[$hash] } else { $null }
                            IsSuspiciousName = $isSuspiciousName
                            IsRecentlyModified = $isRecentlyModified
                        })
                    }
                }
            }
            catch { }
        }
    }
    
    return $findings
}

function Get-LogArtifacts {
    $findings = [System.Collections.ArrayList]::new()
    
    $logFilesToScan = @(
        # Direct log file paths (fastest)
        (Join-Path $env:APPDATA ".minecraft\logs\latest.log"),
        (Join-Path $env:APPDATA ".minecraft\launcher_log.txt"),
        (Join-Path $env:APPDATA "PrismLauncher\logs\latest.log"),
        (Join-Path $env:APPDATA "MultiMC\logs\latest.log"),
        (Join-Path $env:USERPROFILE "curseforge\minecraft\Install\logs\latest.log"),
        (Join-Path $env:APPDATA "ATLauncher\logs\latest.log"),
        (Join-Path $env:USERPROFILE ".lunarclient\logs\latest.log"),
        (Join-Path $env:APPDATA ".tlauncher\logs\latest.log")
    )
    
    $combinedPattern = $script:CheatLogPatterns -join '|'
    
    foreach ($logPath in $logFilesToScan) {
        if (-not (Test-Path $logPath)) { continue }
        
        try {
            $fileInfo = Get-Item $logPath -ErrorAction SilentlyContinue
            if ($fileInfo.Length -gt 5MB) { continue }
            
            $content = Get-Content -Path $logPath -Raw -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            
            $regexMatches = [regex]::Matches($content, ".*($combinedPattern).*", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            foreach ($match in $regexMatches) {
                $lineText = $match.Value.Trim()
                if ($lineText.Length -gt 300) { $lineText = $lineText.Substring(0, 300) + "..." }
                
                [void]$findings.Add(@{
                    LogFile = $logPath
                    MatchedLine = $lineText
                    MatchedPattern = $match.Groups[1].Value
                })
                
                if ($findings.Count -ge 50) { break }
            }
        }
        catch { }
        
        if ($findings.Count -ge 50) { break }
    }
    
    return $findings
}

function Get-RecycleBinArtifacts {
    $findings = [System.Collections.ArrayList]::new()
    
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xA)
        
        if ($recycleBin) {
            foreach ($item in $recycleBin.Items()) {
                $name = $item.Name
                $ext = [System.IO.Path]::GetExtension($name).ToLower()
                
                if ($ext -in @(".exe", ".jar", ".dll")) {
                    try {
                        $deleteDate = $recycleBin.GetDetailsOf($item, 2)
                        $originalPath = $recycleBin.GetDetailsOf($item, 1)
                        
                        $parsedDate = $null
                        if ([DateTime]::TryParse($deleteDate, [ref]$parsedDate)) {
                            if ($parsedDate -ge $script:TimeWindow) {
                                $isSuspicious = Test-SuspiciousName $name
                                
                                [void]$findings.Add(@{
                                    FileName = $name
                                    OriginalPath = $originalPath
                                    DeletedAt = $parsedDate.ToString("o")
                                    IsSuspiciousName = $isSuspicious
                                })
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    }
    catch { }
    
    return $findings
}

#endregion Forensic Modules

#region Output

function Format-Report {
    param([hashtable]$ScanResults)
    
    return [PSCustomObject]@{
        Metadata = @{
            ToolVersion = $script:ToolVersion
            ScanTime = (Get-Date).ToString("o")
            Hostname = $env:COMPUTERNAME
            Username = $env:USERNAME
            TimeWindowMinutes = 60
        }
        ProcessArtifacts = $ScanResults.ProcessArtifacts
        PrefetchArtifacts = $ScanResults.PrefetchArtifacts
        ShimCacheArtifacts = $ScanResults.ShimCacheArtifacts
        FileSystemArtifacts = $ScanResults.FileSystemArtifacts
        LogArtifacts = $ScanResults.LogArtifacts
        RecycleBinArtifacts = $ScanResults.RecycleBinArtifacts
        Summary = @{
            TotalFindings = (
                $ScanResults.ProcessArtifacts.Count +
                $ScanResults.PrefetchArtifacts.Count +
                $ScanResults.ShimCacheArtifacts.Count +
                $ScanResults.FileSystemArtifacts.Count +
                $ScanResults.LogArtifacts.Count +
                $ScanResults.RecycleBinArtifacts.Count
            )
            ProcessFindings = $ScanResults.ProcessArtifacts.Count
            PrefetchFindings = $ScanResults.PrefetchArtifacts.Count
            ShimCacheFindings = $ScanResults.ShimCacheArtifacts.Count
            FileSystemFindings = $ScanResults.FileSystemArtifacts.Count
            LogFindings = $ScanResults.LogArtifacts.Count
            RecycleBinFindings = $ScanResults.RecycleBinArtifacts.Count
        }
    }
}

function Send-Report {
    param([PSCustomObject]$Report)
    
    if ($TestMode) {
        Write-Host "`n[TEST MODE] JSON Report:" -ForegroundColor Yellow
        $Report | ConvertTo-Json -Depth 10 | Write-Host
        return $true
    }
    
    try {
        $isDiscordWebhook = $script:ApiEndpoint -match "discord\.com/api/webhooks"
        
        if ($isDiscordWebhook) {
            $color = if ($Report.Summary.TotalFindings -gt 0) { 16711680 } else { 65280 }
            $status = if ($Report.Summary.TotalFindings -gt 0) { "SUSPICIOUS FINDINGS DETECTED" } else { "CLEAN - No Cheats Found" }
            
            $fields = @(
                @{ name = "Hostname"; value = $Report.Metadata.Hostname; inline = $true }
                @{ name = "Username"; value = $Report.Metadata.Username; inline = $true }
                @{ name = "Scan Time"; value = $Report.Metadata.ScanTime; inline = $true }
                @{ name = "Total Findings"; value = "$($Report.Summary.TotalFindings)"; inline = $true }
                @{ name = "Process"; value = "$($Report.Summary.ProcessFindings)"; inline = $true }
                @{ name = "Prefetch"; value = "$($Report.Summary.PrefetchFindings)"; inline = $true }
                @{ name = "ShimCache"; value = "$($Report.Summary.ShimCacheFindings)"; inline = $true }
                @{ name = "File System"; value = "$($Report.Summary.FileSystemFindings)"; inline = $true }
                @{ name = "Logs"; value = "$($Report.Summary.LogFindings)"; inline = $true }
                @{ name = "Recycle Bin"; value = "$($Report.Summary.RecycleBinFindings)"; inline = $true }
            )
            
            if ($Report.Summary.TotalFindings -gt 0) {
                $detailsText = ""
                foreach ($artifact in $Report.FileSystemArtifacts | Select-Object -First 5) {
                    $detailsText += "- $($artifact.FileName)`n"
                }
                foreach ($artifact in $Report.PrefetchArtifacts | Select-Object -First 3) {
                    $detailsText += "- [Prefetch] $($artifact.ExecutableName)`n"
                }
                if ($detailsText) {
                    $fields += @{ name = "Suspicious Files"; value = "``````$detailsText``````"; inline = $false }
                }
            }
            
            $discordPayload = @{
                embeds = @(
                    @{
                        title = "Minecraft Cheat Detection Report"
                        description = $status
                        color = $color
                        fields = $fields
                        footer = @{ text = "Tool Version: $($Report.Metadata.ToolVersion)" }
                        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                )
            }
            
            $json = $discordPayload | ConvertTo-Json -Depth 10 -Compress
        }
        else {
            $json = $Report | ConvertTo-Json -Depth 10 -Compress
        }
        
        $response = Invoke-RestMethod -Uri $script:ApiEndpoint -Method Post -Headers $script:Headers -Body $json -TimeoutSec 30
        Write-Host "[SUCCESS] Report sent to API endpoint." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to send report: $_" -ForegroundColor Red
        return $false
    }
}

function Clear-SensitiveData {
    $variablesToClear = @(
        "scanResults", "report", "json", "content", "matches",
        "javaProcesses", "files", "cacheData", "bytes"
    )
    
    foreach ($var in $variablesToClear) {
        Remove-Variable -Name $var -Scope Script -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name $var -Force -ErrorAction SilentlyContinue
    }
    
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

#endregion Output

#region Main

function Invoke-CheatDetection {
    Write-Host "`n[*] Starting Minecraft Cheat Detection Tool v$script:ToolVersion" -ForegroundColor Cyan
    Write-Host "[*] Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "[*] Time Window: Last 60 minutes`n" -ForegroundColor Cyan
    
    if (-not (Test-AdminPrivileges)) {
        Write-Host "[ERROR] This tool requires Administrator privileges." -ForegroundColor Red
        Write-Host "[ERROR] Please run PowerShell as Administrator and try again." -ForegroundColor Red
        exit 1
    }
    
    if (-not $SkipDisclaimer) {
        if (-not (Show-Disclaimer)) {
            Write-Host "`n[ABORTED] User declined the disclaimer. Exiting." -ForegroundColor Yellow
            exit 0
        }
    }
    
    Write-Host "[*] Running forensic scans..." -ForegroundColor Cyan
    
    $scanResults = @{
        ProcessArtifacts = @()
        PrefetchArtifacts = @()
        ShimCacheArtifacts = @()
        FileSystemArtifacts = @()
        LogArtifacts = @()
        RecycleBinArtifacts = @()
    }
    
    Write-Host "    [1/6] Scanning processes..." -ForegroundColor Gray
    $scanResults.ProcessArtifacts = @(Get-ProcessArtifacts)
    
    Write-Host "    [2/6] Scanning Prefetch..." -ForegroundColor Gray
    $scanResults.PrefetchArtifacts = @(Get-PrefetchArtifacts)
    
    Write-Host "    [3/6] Scanning ShimCache..." -ForegroundColor Gray
    $scanResults.ShimCacheArtifacts = @(Get-ShimCacheArtifacts)
    
    Write-Host "    [4/6] Scanning file system..." -ForegroundColor Gray
    $scanResults.FileSystemArtifacts = @(Get-FileSystemArtifacts)
    
    Write-Host "    [5/6] Scanning log files..." -ForegroundColor Gray
    $scanResults.LogArtifacts = @(Get-LogArtifacts)
    
    Write-Host "    [6/6] Scanning Recycle Bin..." -ForegroundColor Gray
    $scanResults.RecycleBinArtifacts = @(Get-RecycleBinArtifacts)
    
    Write-Host "`n[*] Generating report..." -ForegroundColor Cyan
    $report = Format-Report -ScanResults $scanResults
    
    Write-Host "`n[*] SCAN SUMMARY:" -ForegroundColor Cyan
    Write-Host "    Total Findings:      $($report.Summary.TotalFindings)" -ForegroundColor $(if ($report.Summary.TotalFindings -gt 0) { "Yellow" } else { "Green" })
    Write-Host "    Process Artifacts:   $($report.Summary.ProcessFindings)" -ForegroundColor Gray
    Write-Host "    Prefetch Artifacts:  $($report.Summary.PrefetchFindings)" -ForegroundColor Gray
    Write-Host "    ShimCache Artifacts: $($report.Summary.ShimCacheFindings)" -ForegroundColor Gray
    Write-Host "    File System:         $($report.Summary.FileSystemFindings)" -ForegroundColor Gray
    Write-Host "    Log Artifacts:       $($report.Summary.LogFindings)" -ForegroundColor Gray
    Write-Host "    Recycle Bin:         $($report.Summary.RecycleBinFindings)" -ForegroundColor Gray
    
    Write-Host "`n[*] Sending report..." -ForegroundColor Cyan
    $sendResult = Send-Report -Report $report
    
    Write-Host "`n[*] Cleaning up sensitive data..." -ForegroundColor Cyan
    Clear-SensitiveData
    
    Write-Host "[*] Scan complete.`n" -ForegroundColor Cyan
    
    return $report.Summary.TotalFindings
}

Invoke-CheatDetection

Write-Host ""
Read-Host "Press Enter to close..."

#endregion Main
