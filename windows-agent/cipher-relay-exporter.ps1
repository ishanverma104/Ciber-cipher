param(
    [string]$ConfigPath = "$PSScriptRoot\config.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-RelayLog {
    param([string]$Message)

    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    Write-Host "[$timestamp] $Message"
}

function Get-RelayConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Relay config not found at $Path"
    }

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-LastExportTime {
    param(
        [string]$Path,
        [int]$DefaultLookbackHours
    )

    if (Test-Path -LiteralPath $Path) {
        $raw = (Get-Content -LiteralPath $Path -Raw).Trim()
        if ($raw) {
            return [DateTime]::Parse($raw).ToUniversalTime()
        }
    }

    return (Get-Date).ToUniversalTime().AddHours(-1 * $DefaultLookbackHours)
}

function Get-WindowsChannels {
    return @(
        "Security",
        "System",
        "Application",
        "Windows PowerShell",
        "Microsoft-Windows-Windows Defender/Operational"
    )
}

function Convert-EventRecord {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord,
        [string]$Channel
    )

    $messageText = ""
    try {
        if ($null -ne $EventRecord.Message) {
            $messageText = $EventRecord.Message.Trim()
        }
    }
    catch {
        $messageText = "Message rendering failed for event $($EventRecord.Id)"
    }

    return [ordered]@{
        TimeCreated      = $EventRecord.TimeCreated.ToUniversalTime().ToString("o")
        MachineName      = $env:COMPUTERNAME
        LogName          = $Channel
        ProviderName     = $EventRecord.ProviderName
        Id               = $EventRecord.Id
        RecordId         = $EventRecord.RecordId
        LevelDisplayName = $EventRecord.LevelDisplayName
        Message          = $messageText
    }
}

function Export-WindowsEvents {
    param(
        [DateTime]$StartTimeUtc
    )

    $collected = New-Object System.Collections.Generic.List[object]

    foreach ($channel in Get-WindowsChannels) {
        try {
            $filter = @{
                LogName   = $channel
                StartTime = $StartTimeUtc
            }

            Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object {
                $collected.Add((Convert-EventRecord -EventRecord $_ -Channel $channel))
            }

            Write-RelayLog "Collected events from $channel"
        }
        catch {
            Write-RelayLog "Skipping $channel: $($_.Exception.Message)"
        }
    }

    return $collected | Sort-Object TimeCreated
}

function Write-Manifest {
    param(
        [string]$Path,
        [string]$Timestamp
    )

    $manifest = [ordered]@{
        export_timestamp = $Timestamp
        platform         = "windows"
        collector        = "cipher-relay"
        sources          = @(
            [ordered]@{
                type     = "windows_eventlog"
                format   = "json"
                filename = "windows_eventlog.json"
                present  = $true
            }
        )
    }

    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Sync-LatestExport {
    param(
        [string]$SourceDir,
        [string]$LatestDir
    )

    New-Item -ItemType Directory -Force -Path $LatestDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $SourceDir "windows_eventlog.json") -Destination (Join-Path $LatestDir "windows_eventlog.json") -Force
    Copy-Item -LiteralPath (Join-Path $SourceDir "manifest.json") -Destination (Join-Path $LatestDir "manifest.json") -Force
}

$config = Get-RelayConfig -Path $ConfigPath
$stateDir = $config.state_dir
$exportsDir = Join-Path $stateDir "exports"
$latestDir = Join-Path $stateDir "latest"
$lastExportPath = Join-Path $stateDir "last_export_utc.txt"

New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
New-Item -ItemType Directory -Force -Path $exportsDir | Out-Null
New-Item -ItemType Directory -Force -Path $latestDir | Out-Null

$startTimeUtc = Get-LastExportTime -Path $lastExportPath -DefaultLookbackHours ([int]$config.initial_lookback_hours)
$timestampUtc = (Get-Date).ToUniversalTime()
$timestampText = $timestampUtc.ToString("o")
$exportDir = Join-Path $exportsDir ($timestampUtc.ToString("yyyyMMdd_HHmmss"))

New-Item -ItemType Directory -Force -Path $exportDir | Out-Null

Write-RelayLog "Exporting Windows event logs since $($startTimeUtc.ToString("o"))"
$events = Export-WindowsEvents -StartTimeUtc $startTimeUtc

$eventPath = Join-Path $exportDir "windows_eventlog.json"
$events | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $eventPath -Encoding UTF8
Write-Manifest -Path (Join-Path $exportDir "manifest.json") -Timestamp $timestampText
Sync-LatestExport -SourceDir $exportDir -LatestDir $latestDir

$timestampText | Set-Content -LiteralPath $lastExportPath -Encoding ASCII
Write-RelayLog "Exported $($events.Count) event(s) to $exportDir"
