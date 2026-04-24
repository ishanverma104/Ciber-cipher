param(
    [string]$ConfigPath = "$PSScriptRoot\config.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RelayConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Relay config not found at $Path"
    }

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Write-RelayLog {
    param(
        [string]$LogFile,
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    Add-Content -LiteralPath $LogFile -Value "[$timestamp] $Message"
}

function Get-ContentType {
    param([string]$Path)

    switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        ".json" { return "application/json" }
        ".txt" { return "text/plain; charset=utf-8" }
        default { return "application/octet-stream" }
    }
}

function Send-TextResponse {
    param(
        [System.Net.HttpListenerContext]$Context,
        [int]$StatusCode,
        [string]$Body,
        [string]$ContentType = "text/plain; charset=utf-8"
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = $ContentType
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.Close()
}

$config = Get-RelayConfig -Path $ConfigPath
$stateDir = $config.state_dir
$latestDir = Join-Path $stateDir "latest"
$logDir = Join-Path $stateDir "logs"
$logFile = Join-Path $logDir "httpd.log"

New-Item -ItemType Directory -Force -Path $latestDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$routePrefix = $config.route_prefix.Trim("/")
$port = [int]$config.listen_port
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://+:$port/$routePrefix/")
$listener.Start()

Write-RelayLog -LogFile $logFile -Message "Cipher Relay HTTPD listening on port $port for /$routePrefix/"

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $requestPath = $context.Request.Url.AbsolutePath.TrimStart("/")

        if ($requestPath -eq "$routePrefix/healthz") {
            Send-TextResponse -Context $context -StatusCode 200 -Body "ok"
            continue
        }

        if (-not $requestPath.StartsWith("$routePrefix/")) {
            Send-TextResponse -Context $context -StatusCode 404 -Body "Not Found"
            continue
        }

        $relativePath = $requestPath.Substring($routePrefix.Length).TrimStart("/")
        if ([string]::IsNullOrWhiteSpace($relativePath)) {
            $relativePath = "latest/manifest.json"
        }

        $targetPath = Join-Path $stateDir $relativePath

        if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
            Send-TextResponse -Context $context -StatusCode 404 -Body "Not Found"
            continue
        }

        $bytes = [IO.File]::ReadAllBytes($targetPath)
        $context.Response.StatusCode = 200
        $context.Response.ContentType = Get-ContentType -Path $targetPath
        $context.Response.ContentLength64 = $bytes.Length
        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $context.Response.Close()

        Write-RelayLog -LogFile $logFile -Message "Served $requestPath"
    }
}
finally {
    if ($listener.IsListening) {
        $listener.Stop()
    }
    $listener.Close()
}
