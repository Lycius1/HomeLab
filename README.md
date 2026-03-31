# 🏠 HomeLab Security Stack

A self-hosted network security monitoring and threat detection stack built on Windows 11 + WSL2. Designed to monitor home network traffic, detect malicious activity, and provide full DNS-level visibility across all connected devices.

## Stack

| Component | Role | URL |
|-----------|------|-----|
| **Pi-hole** | Network-wide DNS filtering + ad blocking (1.5M+ blocked domains) | `http://<host-ip>/admin` |
| **Wazuh** | SIEM, threat detection, host monitoring, CIS benchmarking | `https://localhost:8443` |
| **Graylog** | Centralised log ingestion + search | `http://localhost:9000` |
| **Grafana** | Dashboards + visualisation | `http://localhost:3000` |
| **OpenSearch** | Log indexing backend (Graylog) | Internal |
| **MongoDB** | Graylog metadata store | Internal |

## Architecture
```
Internet
    │
    ▼
Archer C7 Router
(DHCP DNS → Windows host IP)
    │
    ▼
dnsproxy (Windows host :53)
    │
    ▼
Pi-hole FTL (WSL2 :53)
1.5M blocked domains
    │
    ├──► DNS logs ──► rsyslog ──► Graylog ──► OpenSearch
    │                                              │
    └──► Wazuh Agent ──► Wazuh Manager ────────────┤
                                                   │
                                               Grafana
```

## Requirements

- Windows 11 with WSL2 (Ubuntu 24.04)
- Docker Desktop with WSL2 backend
- 16GB+ RAM (stack uses ~6GB)
- Archer C7 or any router with configurable DHCP DNS

## Quick Start

### 1. Pi-hole (WSL2)
```bash
curl -sSL https://install.pi-hole.net | bash
pihole setpassword
```

Disable WSL2 DNS tunneling — add to `%USERPROFILE%\.wslconfig`:
```ini
[wsl2]
dnsTunneling=false
```

Restart WSL: `wsl --shutdown`

### 2. DNS Proxy (Windows host)

Download [dnsproxy v0.81.0+](https://github.com/AdguardTeam/dnsproxy/releases) and run:
```powershell
.\dnsproxy.exe -l 0.0.0.0 -p 53 -u <WSL2-IP>:53
```

Open firewall:
```powershell
netsh advfirewall firewall add rule name="PiHole DNS UDP" dir=in action=allow protocol=UDP localport=53
netsh advfirewall firewall add rule name="PiHole DNS TCP" dir=in action=allow protocol=TCP localport=53
```

### 3. Router DNS

Set your router's DHCP **Primary DNS** to your Windows machine's LAN IP.

### 4. SIEM Stack (Docker)
```powershell
cd homelab
docker compose up -d
```

### 5. Wazuh (Docker — separate compose)
```powershell
cd homelab/wazuh-docker/single-node
docker compose up -d
```

Generate certs first:
```powershell
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 6. Wazuh Agent (Windows)

Download agent from [Wazuh releases](https://github.com/wazuh/wazuh/releases) matching your manager version, then:
```powershell
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 127.0.0.1 -p 1515
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic
```

## Blocklists

| List | Domains | Purpose |
|------|---------|---------|
| [StevenBlack hosts](https://github.com/StevenBlack/hosts) | 88,764 | Ads + malware |
| [Hagezi Pro](https://github.com/hagezi/dns-blocklists) | 379,466 | Multi-purpose |
| [Hagezi TIF](https://github.com/hagezi/dns-blocklists) | 1,003,462 | Threat intelligence |
| [KADhosts](https://github.com/PolishFiltersTeam/KADhosts) | 62,628 | Fraud + phishing |

**Total: 1,384,058 unique blocked domains**

## Persistence

A startup script (`pihole-startup.ps1`) registered as a Windows scheduled task handles:
- Getting the fresh WSL2 IP on each boot
- Starting Pi-hole FTL inside WSL2
- Launching dnsproxy on the Windows host
- Re-adding port proxy rules

## Credentials

Copy `.env.example` to `.env` and fill in values before running the stack. Never commit `.env`.

## Known Issues

- WSL2 IP changes on reboot — handled by startup script
- Wazuh Docker requires `vm.max_map_count=262144` set in WSL2
- Port 53 on Windows is held by HNS (Docker) — use dnsproxy as bridge

## License

MIT