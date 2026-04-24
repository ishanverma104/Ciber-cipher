# Cyber-Cipher Windows Relay

This is the Windows-only endpoint pipeline for Cyber-Cipher.

It is intentionally separate from the Linux `agent/` implementation:

- Installer: `install-cipher-relay.ps1`
- Exporter: `cipher-relay-exporter.ps1`
- HTTP server: `cipher-relay-httpd.ps1`

The relay exports Windows Event Log data to `windows_eventlog.json`, serves it over a lightweight PowerShell `HttpListener`, and lets the SIEM pull it with the dedicated Windows collector.

## Install on Windows

1. Copy the `windows-agent/` directory to the target Windows host.
2. Open an elevated PowerShell session.
3. Run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install-cipher-relay.ps1 -Port 8091 -RoutePrefix cc-winrelay
```

After installation, the Windows host serves:

```text
http://<windows-host>:8091/cc-winrelay/latest/manifest.json
http://<windows-host>:8091/cc-winrelay/latest/windows_eventlog.json
```

## What it collects

- `Security`
- `System`
- `Application`
- `Windows PowerShell`
- `Microsoft-Windows-Windows Defender/Operational`

The exporter runs on startup and then on a scheduled interval, writing fresh JSON into the relay state directory before the HTTP endpoint serves it.
