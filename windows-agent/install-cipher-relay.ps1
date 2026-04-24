param(
    [string]$InstallRoot = "$env:ProgramData\CyberCipherWindowsRelay",
    [int]$Port = 8091,
    [string]$RoutePrefix = "cc-winrelay",
    [int]$ExportIntervalMinutes = 15,
    [int]$InitialLookbackHours = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated PowerShell session."
    }
}

function Write-InstallLog {
    param([string]$Message)

    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    Write-Host "[$timestamp] $Message"
}

function Register-OrReplaceTask {
    param(
        [string]$TaskName,
        [Microsoft.Management.Infrastructure.CimInstance[]]$Triggers,
        [Microsoft.Management.Infrastructure.CimInstance]$Action
    )

    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Triggers -Settings $settings -Principal $principal | Out-Null
}

Assert-Administrator

$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptsDir = Join-Path $InstallRoot "scripts"
$stateDir = Join-Path $InstallRoot "state"
$logDir = Join-Path $stateDir "logs"

New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

Copy-Item -LiteralPath (Join-Path $sourceDir "cipher-relay-exporter.ps1") -Destination (Join-Path $scriptsDir "cipher-relay-exporter.ps1") -Force
Copy-Item -LiteralPath (Join-Path $sourceDir "cipher-relay-httpd.ps1") -Destination (Join-Path $scriptsDir "cipher-relay-httpd.ps1") -Force

$config = [ordered]@{
    listen_port            = $Port
    route_prefix           = $RoutePrefix
    state_dir              = $stateDir
    initial_lookback_hours = $InitialLookbackHours
}

$config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $scriptsDir "config.json") -Encoding UTF8

$httpTaskName = "CyberCipher-WindowsRelay-Httpd"
$exportTaskName = "CyberCipher-WindowsRelay-Exporter"
$httpScript = Join-Path $scriptsDir "cipher-relay-httpd.ps1"
$exportScript = Join-Path $scriptsDir "cipher-relay-exporter.ps1"
$configPath = Join-Path $scriptsDir "config.json"

$httpAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$httpScript`" -ConfigPath `"$configPath`""
$httpTrigger = New-ScheduledTaskTrigger -AtStartup
Register-OrReplaceTask -TaskName $httpTaskName -Triggers $httpTrigger -Action $httpAction

$exportAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$exportScript`" -ConfigPath `"$configPath`""
$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$scheduleTrigger = New-ScheduledTaskTrigger -Daily -At 12:00AM
$scheduleTrigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes $ExportIntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 1)).Repetition
Register-OrReplaceTask -TaskName $exportTaskName -Triggers @($startupTrigger, $scheduleTrigger) -Action $exportAction

if (-not (Get-NetFirewallRule -DisplayName "CyberCipher Windows Relay $Port" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "CyberCipher Windows Relay $Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
}

Start-ScheduledTask -TaskName $exportTaskName
Start-ScheduledTask -TaskName $httpTaskName

Write-InstallLog "Cipher Relay installed."
Write-InstallLog "HTTP endpoint: http://<this-host>:$Port/$RoutePrefix/latest/manifest.json"
Write-InstallLog "State directory: $stateDir"
