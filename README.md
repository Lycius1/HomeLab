\# Homelab Security Stack



A self-hosted network security monitoring stack running on Windows 11 with WSL2.



\## Stack



| Component | Purpose | Access |

|-----------|---------|--------|

| Pi-hole | Network-wide DNS filtering + ad blocking (1.5M blocked domains) | `http://<host-ip>/admin` |

| Wazuh | SIEM + threat detection + host monitoring | `https://localhost:8443` |

| Graylog | Centralised log ingestion + search | `http://localhost:9000` |

| Grafana | Dashboards + visualisation | `http://localhost:3000` |



\## Architecture

```

Internet

&#x20;   │

Archer C7 Router (DNS → Pi-hole)

&#x20;   │

Pi-hole (WSL2) ──► Graylog (Docker)

&#x20;   │                    │

&#x20;   └──► Wazuh ◄─────────┘

&#x20;             │

&#x20;         Grafana

```



\## Requirements



\- Windows 11 with WSL2 (Ubuntu)

\- Docker Desktop

\- 16GB+ RAM recommended



\## Setup



\### 1. Pi-hole (WSL2)

```bash

curl -sSL https://install.pi-hole.net | bash

pihole setpassword

```



Configure WSL2 DNS tunneling off in `%USERPROFILE%\\.wslconfig`:

```ini

\[wsl2]

dnsTunneling=false

```



\### 2. DNS Proxy (Windows)



Download \[dnsproxy](https://github.com/AdguardTeam/dnsproxy/releases) and run:

```powershell

.\\dnsproxy.exe -l 0.0.0.0 -p 53 -u <WSL2-IP>:53

```



\### 3. SIEM Stack (Docker)

```powershell

cd homelab

docker compose up -d

```

```powershell

cd homelab/wazuh-docker/single-node

docker compose up -d

```



\### 4. Wazuh Agent (Windows)



Download from \[Wazuh releases](https://github.com/wazuh/wazuh/releases) and register:

```powershell

\& "C:\\Program Files (x86)\\ossec-agent\\agent-auth.exe" -m 127.0.0.1 -p 1515

Start-Service WazuhSvc

```



\### 5. Router DNS



Point your router's DHCP Primary DNS to your Windows machine's LAN IP.



\## Blocklists



\- \[StevenBlack hosts](https://github.com/StevenBlack/hosts)

\- \[Hagezi Pro](https://github.com/hagezi/dns-blocklists)

\- \[Hagezi Threat Intelligence Feed](https://github.com/hagezi/dns-blocklists)

\- \[KADhosts](https://github.com/PolishFiltersTeam/KADhosts)



\## Credentials



All credentials are stored in environment variables. Copy `.env.example` to `.env` and fill in your values.



\## License



MIT

