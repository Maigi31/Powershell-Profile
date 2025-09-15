# =====================================================================
#  PowerShell Profile – Ultimate Optimized + Enhanced for Windows 11
#  Author: Aamir + Copilot
# =====================================================================

# Performance Monitoring Setup
$script:profileLoadStart = Get-Date

# ensure a single, well-defined profile log directory and files (avoid bare-token / scoping issues)
$script:profileLogDir = Join-Path $HOME '.powershell'
if (-not (Test-Path $script:profileLogDir)) {
    New-Item -ItemType Directory -Path $script:profileLogDir -Force | Out-Null
}
$script:profileLoadLog   = Join-Path $script:profileLogDir 'profile_performance.log'
$script:logFile          = Join-Path $script:profileLogDir 'profile.log'
$script:errorLogFile     = Join-Path $script:profileLogDir 'profile_errors.log'

# Initialize performance/log variables correctly (single, explicit initialization)
$script:LoadTimes = @{}

# Ensure profile log directory exists early (so trap/write functions can add content)
$script:logFile = "$HOME\.powershell\profile.log"
$script:errorLogFile = "$HOME\.powershell\profile_errors.log"
foreach ($p in @($script:profileLoadLog, $script:logFile, $script:errorLogFile)) {
    $dir = Split-Path $p
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Package Manager Integration
function Update-AllPackages {
    [CmdletBinding()]
    param(
        [switch]$Parallel
    )
    
    $updates = @()
    $packageManagers = @(
        @{
            Name = 'Winget'
            Condition = { Get-Command winget -ErrorAction SilentlyContinue }
            Action = { winget upgrade --all --accept-source-agreements }
        }
        @{
            Name = 'Chocolatey'
            Condition = { Get-Command choco -ErrorAction SilentlyContinue }
            Action = { choco upgrade all -y }
        }
        @{
            Name = 'Scoop'
            Condition = { Get-Command scoop -ErrorAction SilentlyContinue }
            Action = { scoop update *; scoop cleanup * }
        }
        @{
            Name = 'PowerShell Modules'
            Condition = { $true }
            Action = { 
                Update-Module -Force
                Update-Help -Force -ErrorAction SilentlyContinue
            }
        }
    )
    
    foreach ($pm in $packageManagers) {
        $condResult = $false
        try {
            if ($pm.Condition -is [scriptblock]) { $condResult = & $pm.Condition }
            elseif ($pm.Condition) { $condResult = & $pm.Condition }
        } catch { $condResult = $false }

        if ($condResult) {
            Write-Host "Updating $($pm.Name)..." -ForegroundColor Yellow
            if ($Parallel) {
                # Ensure Action is a scriptblock for Start-Job
                if ($pm.Action -is [scriptblock]) {
                    $updates += Start-Job -Name $pm.Name -ScriptBlock $pm.Action
                } else {
                    $scriptBlock = [scriptblock]::Create($pm.Action.ToString())
                    $updates += Start-Job -Name $pm.Name -ScriptBlock $scriptBlock
                }
            }
            else {
                try {
                    if ($pm.Action -is [scriptblock]) { & $pm.Action }
                    elseif (-not [string]::IsNullOrWhiteSpace($pm.Action)) { Invoke-Expression $pm.Action }
                }
                catch {
                    Write-Warning "$($pm.Name) update failed: $_"
                }
            }
        }
    }
    
    if ($Parallel -and $updates) {
        $updates | Wait-Job | Receive-Job
        Remove-Job -Job $updates
    }
    
    Write-Host "Package updates completed!" -ForegroundColor Green
}

# Chocolatey
$ChocProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path $ChocProfile) { 
    Import-Module $ChocProfile -ErrorAction SilentlyContinue
}
# Ensure LoadTimes variable is defined (was accidentally injected as a bare token)
$script:LoadTimes = @{}

function Write-ProfilePerformance {
    param(
        [string]$Component,
        [datetime]$StartTime,
        [switch]$IsError
    )
    $duration = (Get-Date) - $StartTime
    $message = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] $Component took $($duration.TotalMilliseconds)ms"
    if ($IsError) { $message += " (ERROR)" }
    Add-Content -Path $script:profileLoadLog -Value $message -ErrorAction SilentlyContinue
}

# Ensure log directory exists
if (-not (Test-Path (Split-Path $profileLoadLog))) {
    New-Item -ItemType Directory -Path (Split-Path $profileLoadLog) -Force | Out-Null
}

# 1 ─── Admin & Environment Detection ─────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Terminal Enhancements
if ($env:WT_SESSION) {
    # Windows Terminal specific settings
    $Host.UI.RawUI.WindowTitle = "PowerShell 7+"
    $PSStyle.FileInfo.Directory = "`e[34m"
    $PSStyle.Formatting.TableHeader = "`e[93m"
    $PSStyle.Formatting.FormatAccent = "`e[96m"
}

# Modern command prompt with git status and execution time
function prompt {
    $lastCommand = Get-History -Count 1
    $executionTime = if ($lastCommand) {
        $duration = $lastCommand.EndExecutionTime - $lastCommand.StartExecutionTime
        " [$([math]::Round($duration.TotalMilliseconds))ms]"
    } else { "" }

    $location = $ExecutionContext.SessionState.Path.CurrentLocation.Path
    $shortPath = $location.Replace($HOME, "~")
    
    $gitBranch = git branch --show-current 2>$null
    $gitStatus = if ($gitBranch) { " [$gitBranch]" } else { "" }
    
    $adminMark = if ($isAdmin) { "[ADMIN] " } else { "" }
    
    "`e[36m$env:USERNAME`e[0m@`e[32m$env:COMPUTERNAME`e[0m " +
    "$adminMark`e[33m$shortPath`e[0m$gitStatus$executionTime`n❯ "
}

# Remove the duplicate simple prompt function (keeps the enhanced prompt above)

# 2 ─── Trust PSGallery & Ensure PATH ──────────────────────────────────
if (-not (Get-PSResourceRepository -Name PSGallery).Trusted) {
    Set-PSResourceRepository -Name PSGallery -Trusted
}

$scriptPath = "$HOME\Documents\PowerShell\Modules"
if ($env:PATH -notlike "*$scriptPath*") {
    [Environment]::SetEnvironmentVariable(
        'PATH',
        "$($env:PATH);$scriptPath",
        [EnvironmentVariableTarget]::User
    )
}

# 3 ─── Auto-Update Help (Background) ──────────────────────────────────
Start-Job { Update-Help -ErrorAction SilentlyContinue } | Out-Null

# 4 ─── Editor Setup ───────────────────────────────────────────────────
$EDITOR = if (Get-Command nvim -ErrorAction SilentlyContinue) { 'nvim' } else { 'notepad' }

# Ensure $EDITOR is always a non-empty valid fallback
if ([string]::IsNullOrWhiteSpace($EDITOR)) { $EDITOR = 'notepad' }

function Edit-Profile {
    param()
    # Defensive: avoid calling & with an empty command
    if (-not [string]::IsNullOrWhiteSpace($EDITOR) -and (Get-Command -Name $EDITOR -ErrorAction SilentlyContinue)) {
        & $EDITOR $PROFILE
    } else {
        Write-Host "Editor '$EDITOR' not found; opening profile with Notepad."
        notepad $PROFILE
    }
}
Set-Alias ep Edit-Profile

# 5 ─── Essential Aliases ──────────────────────────────────────────────
Set-Alias ll  Get-ChildItem -Option AllScope  
Set-Alias la  'Get-ChildItem -Force' -Option AllScope  
Set-Alias reload Restart-Profile -Option AllScope  
Set-Alias cls Clear-Host  

# Error Handling and Logging Setup
$ErrorActionPreference = 'Stop'

function Write-ProfileLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info' { 
            Add-Content -Path $script:logFile -Value $logMessage
            Write-Verbose $logMessage
        }
        'Warning' {
            Add-Content -Path $script:logFile -Value $logMessage
            Write-Warning $Message
        }
        'Error' {
            Add-Content -Path $script:errorLogFile -Value $logMessage
            Write-Error $Message
        }
    }
}

# Create log directories if they don't exist
$logDir = Split-Path $script:logFile
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Rotate logs if they get too large (>1MB)
foreach ($log in @($script:logFile, $script:errorLogFile)) {
    if (Test-Path $log) {
        $file = Get-Item $log
        if ($file.Length -gt 1MB) {
            Move-Item $log "$log.old" -Force
        }
    }
}

# Error handling for the entire session
# This trap block catches all unhandled errors in the session, logs them with stack trace for diagnostics,
# and continues execution to prevent the session from terminating unexpectedly.
trap {
    $errorStackTrace = if ($_.ScriptStackTrace) { $_.ScriptStackTrace } else { $_.InvocationInfo.PositionMessage }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Error] Unhandled error: $_`nStack trace: $errorStackTrace"
    Add-Content -Path $script:errorLogFile -Value $logMessage -ErrorAction SilentlyContinue
    Write-Error $logMessage
    continue
}

# List of modules to import
$ModulesToImport = @(
    'Terminal-Icons',
    'posh-git',
    'PSReadLine',
    'PSScriptAnalyzer',
    'Pester',
    'PSWindowsUpdate',
    'PSYaml',
    'PSFzf'
)

# Create cache directory if it doesn't exist
$cacheDir = "$HOME\.powershell\moduleCache"
if (-not (Test-Path $cacheDir)) { 
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null 
}

# Add to your cache cleanup routine
$maxCacheAge = (Get-Date).AddDays(-30)
Get-ChildItem $cacheDir -File | 
    Where-Object LastWriteTime -lt $maxCacheAge |
    Remove-Item -Force

# Parallel module import with caching
$jobs = @()
foreach ($m in $ModulesToImport) {
    $cacheFile = Join-Path $cacheDir "$m.cache"
    $jobs += Start-Job -ScriptBlock {
        param($module, $cachePath)
        if (Get-Module -ListAvailable -Name $module) {
            if (-not (Test-Path $cachePath) -or (Get-Item $cachePath).LastWriteTime -lt (Get-Date).AddDays(-7)) {
                Import-Module $module -ErrorAction SilentlyContinue
                Get-Module $module | Export-Clixml -Path $cachePath
            } else {
                Import-Clixml -Path $cachePath | Import-Module
            }
        }
    } -ArgumentList $m, $cacheFile
}

# Wait for all jobs to complete with timeout
Wait-Job -Job $jobs -Timeout 5 | Out-Null
Remove-Job -Job $jobs -Force

# 7 ─── Core Utilities & Startup Diagnostics ──────────────────────────
function uptime {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $u    = (Get-Date) - $boot
    Write-Host "Uptime: $($u.Days)d $($u.Hours)h $($u.Minutes)m" -ForegroundColor Cyan
}

function Clear-Cache {
    Write-Host "Clearing temp caches..." -ForegroundColor Cyan
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache
    Write-Host "Done." -ForegroundColor Green
}

function flushdns    { Clear-DnsClientCache; Write-Host "DNS cache cleared" }
function Get-PubIP   { (Invoke-WebRequest http://ifconfig.me/ip -UseBasicParsing).Content }
function sysinfo     { Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsHardwareAbstractionLayer }
function Restart-Profile {
    param()
    if (-not [string]::IsNullOrWhiteSpace($PROFILE) -and (Test-Path $PROFILE)) {
        & $PROFILE
    } else {
        Write-Warning "Profile path is missing or does not exist."
    }
}

function Get-SystemHealth {
    Write-Host "`n=== System Health Snapshot ===" -ForegroundColor Yellow
    
    # Start async jobs for resource-intensive operations
    $jobs = @{
        Uptime = Start-Job { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
        CPU = Start-Job { (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue }
        Memory = Start-Job { (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory }
        Disk = Start-Job { (Get-PSDrive C).Free }
        Updates = Start-Job { (Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot).Count }
        PublicIP = Start-Job { (Invoke-WebRequest -Uri 'http://ifconfig.me/ip' -UseBasicParsing).Content }
    }

    # Collect results with timeout
    $results = @{}
    foreach ($key in $jobs.Keys) {
        $results[$key] = Wait-Job $jobs[$key] -Timeout 3 | Receive-Job -ErrorAction SilentlyContinue
        Remove-Job $jobs[$key] -Force
    }

    # Display results
    $boot = $results.Uptime
    if ($boot) {
        $uptime = (Get-Date) - $boot
        Write-Host "Uptime   : $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
    }
    
    Write-Host "CPU Load : $([math]::Round($results.CPU, 1))%"
    Write-Host "Memory   : $([math]::Round($results.Memory/1MB, 1)) GB free"
    Write-Host "Disk C   : $([math]::Round($results.Disk/1GB, 1)) GB free"
    Write-Host "Public IP: $($results.PublicIP)"
    Write-Host "Updates  : $($results.Updates) pending"
    Write-Host "===============================`n"
}

# Run health check at startup (call in current session so function is available)
try {
    if (Get-Command -Name Get-SystemHealth -ErrorAction SilentlyContinue) {
        Get-SystemHealth
    } else {
        Write-ProfileLog -Message "Get-SystemHealth not available at startup" -Level Warning
    }
} catch {
    Write-ProfileLog -Message "Get-SystemHealth failed on startup: $_" -Level Error
}

# 8 ─── Process & File Operations ─────────────────────────────────────
function pkill($n) { Get-Process $n -ErrorAction SilentlyContinue | Stop-Process }
function pgrep($n) { Get-Process $n -ErrorAction SilentlyContinue }
function nf($n)    { New-Item -ItemType File -Path . -Name $n }
function mkcd($d)  { mkdir $d -Force; Set-Location $d }
function cpy($t)   { Set-Clipboard $t; Write-Host "Copied to clipboard." }
function pst       { Get-Clipboard }

# 9 ─── Git Shortcuts ──────────────────────────────────────────────────
function gs    { git status }
function ga    { git add . }
function gc($m) { git commit -m "$m" }
function gl    { git log --oneline --graph --decorate }
function gpush { git push }
function gpull { git pull }
function gcom($m) { git add .; git commit -m "$m" }
function lazyg($m) { git add .; git commit -m "$m"; git push }

# 10 ─── PSReadLine Enhancements ───────────────────────────────────────
# Optimize PSReadLine for performance and better UX
Set-PSReadLineOption -HistorySavePath "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\history.txt" `
    -MaximumHistoryCount 20000 `
    -HistoryNoDuplicates `
    -PredictionSource HistoryAndPlugin `
    -PredictionViewStyle ListView `
    -Colors @{
        Command            = 'Yellow'
        Parameter         = 'DarkCyan'
        InlinePrediction = 'DarkGray'
        Operator         = 'DarkRed'
        String           = 'Green'
    }

# Enhanced key bindings for better productivity
Set-PSReadLineKeyHandler -Chord 'Ctrl+r' -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Chord 'Ctrl+f' -Function ForwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+d' -Function DeleteWord
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete

# Ensure history is saved on exit
Register-EngineEvent PowerShell.Exiting -Action { [Microsoft.PowerShell.PSConsoleReadLine]::SaveHistory() }

# 11 ─── Prompt & Navigation Enhancements ─────────────────────────────
if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
    $ompInit = (oh-my-posh init pwsh --config 'https://cdn.jsdelivr.net/gh/JanDeDobbeleer/oh-my-posh@latest/themes/cobalt2.omp.json') 2>$null
    if (-not [string]::IsNullOrWhiteSpace($ompInit)) {
        Invoke-Expression $ompInit
    } else {
        Write-ProfileLog -Message "oh-my-posh init returned empty or failed" -Level Warning
    }
}

# Initialize zoxide for PowerShell
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    try {
        $zOut = zoxide init powershell 2>$null
        if ($zOut -is [System.Object[]]) { $zInit = $zOut -join "`n" } else { $zInit = [string]$zOut }

        if (-not [string]::IsNullOrWhiteSpace($zInit)) {
            try {
                Invoke-Expression $zInit
            } catch {
                Write-ProfileLog -Message "Failed to invoke zoxide init output: $_" -Level Warning
            }
        } else {
            Write-ProfileLog -Message "zoxide init returned empty or failed" -Level Warning
        }
    } catch {
        Write-ProfileLog -Message "zoxide init execution failed: $_" -Level Warning
    }
}

if (Get-Command fzf -ErrorAction SilentlyContinue) {
    function fcd { Set-Location (Get-ChildItem -Directory -Recurse -ErrorAction SilentlyContinue | fzf).FullName }
    function fhist { Get-History | fzf }
}

# 12 ─── Package Manager Integrations ─────────────────────────────────
# PSWindowsUpdate
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction SilentlyContinue
}
Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

# Chocolatey
$ChocProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path $ChocProfile) { Import-Module $ChocProfile -ErrorAction SilentlyContinue }

# Scoop
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    function Update-Scoop { scoop update * }
    Set-Alias sup Update-Scoop
}

# Winget
function Update-Winget { winget upgrade --all --accept-source-agreements --accept-package-agreements }
Set-Alias wup Update-Winget

# pip & npm
function pi($p)  { if (Get-Command pip) { pip install $p } else { Write-Warning 'pip not found' } }
function ngi($p) { if (Get-Command npm) { npm install -g $p } else { Write-Warning 'npm not found' } }

# 13 ─── Networking & Service Control ─────────────────────────────────
function Get-NetstatSummary { netstat -ano | Select-String 'LISTENING' }
function Test-TracertGoogle { tracert 8.8.8.8 }
function Get-DnsLookup($d) { Resolve-DnsName $d }

function Start-Svc($n)   { Start-Service $n; Write-Host "$n started" }
function Stop-Svc($n)    { Stop-Service $n; Write-Host "$n stopped" }
function Restart-Svc($n) { Restart-Service $n; Write-Host "$n restarted" }

# 14 ─── Search, Archive & Conversion Tools ────────────────────────────
function find-file($n) { Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include *$n* }
function find-proc($n) { Get-Process | Where-Object ProcessName -Like "*$n*" }
function find-event($id) { Get-WinEvent -FilterHashtable @{Id=$id} -MaxEvents 20 }

function zip($s,$d)   { Compress-Archive -Path $s -DestinationPath $d -Force }
function unzip($s,$d) { Expand-Archive   -Path $s -DestinationPath $d -Force }

function Export-JsonFile($o,$p) { $o | ConvertTo-Json -Depth 5 | Set-Content $p }
function Import-JsonFile($p)    { Get-Content $p | ConvertFrom-Json }
function Export-YamlFile($o,$p) { $o | ConvertTo-Yaml | Set-Content $p }
function Import-YamlFile($p)    { Get-Content $p | ConvertFrom-Yaml }

# 15 ─── Secure Strings & Final Touch ─────────────────────────────────
function Protect-Encrypt($t) {
    $s = ConvertTo-SecureString $t -AsPlainText -Force
    $s | ConvertFrom-SecureString
}
function Protect-Decrypt($e) {
    $e | ConvertTo-SecureString | ConvertFrom-SecureString -AsPlainText
}

Write-Host "`n✅ Ultimate Windows 11 PowerShell profile loaded!" -ForegroundColor Green

# External unix-pwsh Loader with cp/del patch
$ux = Join-Path $env:USERPROFILE 'unix-pwsh\Microsoft.PowerShell_profile.ps1'
if (Test-Path $ux) {
    (Get-Content $ux) `
      -replace 'Set-Alias cp Copy-Item',  'Set-Alias cp Copy-Item  -Force' `
      -replace 'Set-Alias del Remove-Item','Set-Alias del Remove-Item -Force' |
      Set-Content $ux
    . $ux
} else {
    $remote = Invoke-WebRequest 'https://raw.githubusercontent.com/CrazyWolf13/unix-pwsh/main/Microsoft.PowerShell_profile.ps1' -UseBasicParsing -ErrorAction SilentlyContinue
    if ($remote -and -not [string]::IsNullOrWhiteSpace($remote.Content)) {
        Invoke-Expression $remote.Content
    } else {
        Write-ProfileLog -Message "Failed to fetch remote unix-pwsh profile or content was empty" -Level Warning
    }
}

# show the path PowerShell will use for the current profile
$PROFILE

# compute a hash of your profile file so we can verify the content matches what I edited
Get-FileHash 'C:\Users\maig3\OneDrive\Documents\PowerShell\Microsoft.PowerShell_profile.ps1' -Algorithm SHA256

# show the lines around where the original errors referenced (400-420)
Select-String -Path 'C:\Users\maig3\OneDrive\Documents\PowerShell\Microsoft.PowerShell_profile.ps1' -Context 3,3 -Pattern 'oh-my-posh|zoxide|Invoke-Expression'

function Invoke-WithRetry {
    param(
        [scriptblock]$Action,
        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 2
    )
    $attempt = 1
    while ($attempt -le $RetryCount) {
        try {
            return & $Action
        } catch {
            if ($attempt -eq $RetryCount) { throw }
            Start-Sleep -Seconds $RetryDelaySeconds
            $attempt++
        }
    }
}

$envConfig = @{
    Development = @{
        ErrorActionPreference = 'Stop'
        VerbosePreference = 'Continue'
    }
    Production = @{
        ErrorActionPreference = 'Stop'
        VerbosePreference = 'SilentlyContinue'
    }
}