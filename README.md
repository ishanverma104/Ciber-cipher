# Cyber-Cipher

A SIEMple to use SIEM.

## Linux agent pipeline

Linux endpoints use the existing `agent/` implementation and are collected from the SIEM with:

```bash
./engine/collect-logs.sh
```

## Windows relay pipeline

Windows endpoints use the separate `windows-agent/` implementation.

- Install on Windows with `windows-agent/install-cipher-relay.ps1`
- Collect on the SIEM with `./engine/collect-windows-relays.sh`
- Configure Windows endpoints in `engine/config/windows-agents.yaml`

The Windows relay exports `windows_eventlog.json`, which the existing security parser can ingest so events appear on the normal timeline dashboard.
