# FAST Deployment Guide

This guide covers a clean deployment of FAST on the current `main` branch.

## Recommended lab topology

```text
Linux/Windows endpoints
        |
     Tailscale
        |
        v
Cloud/Linux Manager VM
  - Wazuh Manager
  - Wazuh Indexer
  - Wazuh Dashboard
  - FAST IOC Collector
  - FAST Web UI
```

Tailscale is recommended for lab administration so Wazuh management ports do not need to be exposed directly to the Internet.

## Requirements

- Linux Manager host (Ubuntu/Debian-family recommended)
- Docker Engine
- Docker Compose plugin
- Git
- Python 3 for host-side helper scripts
- about 4 GB RAM minimum for the single-node Wazuh lab stack
- about 10 GB free disk for a practical test environment

Check:

```bash
docker --version
docker compose version
docker info >/dev/null && echo "Docker OK"
git --version
python3 --version
```

## 1. Clone main

```bash
git clone https://github.com/eppzx2/fast-test.git fast-test
cd fast-test
git checkout main
git pull --ff-only origin main
```

## 2. Configure local environment

```bash
cp .env.example .env
```

Important settings:

```env
ABUSECH_AUTH_KEY=
FAST_WEB_BIND=127.0.0.1

FAST_WAZUH_API_URL=https://wazuh.manager:55000
FAST_WAZUH_INDEXER_URL=https://wazuh.indexer:9200

FAST_AUTH_ENABLED=0
FAST_SESSION_SECRET=
FAST_ADMIN_USER=admin
FAST_ADMIN_PASSWORD=
```

Use a free abuse.ch Auth-Key for current URLhaus/MalwareBazaar Community access.

Keep `.env` out of git.

## 3. Optional: Tailscale

On the Manager and lab endpoints:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4
```

Use the Manager's Tailscale IPv4 for agent registration.

## 4. Deploy FAST

With an explicit Manager address:

```bash
./bin/fast up --ip <MANAGER_TAILSCALE_IP>
```

Or auto-detect:

```bash
./bin/fast up
```

FAST performs the following high-level sequence:

1. clones the pinned Wazuh 4.9.0 single-node Docker stack if missing;
2. validates the TLS certificate bundle;
3. regenerates stale/incomplete/mixed certificates while preserving named volumes;
4. starts Manager, Indexer and Dashboard;
5. checks Manager processes and current-start critical logs;
6. builds the IOC collector image;
7. repairs legacy root-owned FAST state files from older deployments;
8. runs collector jobs with the host UID/GID to prevent new root-owned SQLite/export files;
9. fetches, normalizes, deduplicates and scores IOCs;
10. generates a validated IPv4/CIDR Wazuh CDB list;
11. installs the CDB and current custom rules;
12. validates Wazuh analysis configuration with `wazuh-analysisd -t`;
13. restarts the Manager once to load the validated assets;
14. verifies Manager health and Filebeat -> Indexer connectivity;
15. starts the persistent FAST web container.

Force a clean certificate rebuild without deleting Wazuh data:

```bash
./bin/fast up --reset-certs
```

Offline/demo IOC seed:

```bash
./bin/fast demo
```

## 5. Verify health

```bash
./bin/fast status
```

Healthy output includes:

```text
Wazuh Manager        [ UP ]
Wazuh Indexer        [ UP ]
Wazuh Dashboard      [ UP ]
Wazuh Manager health (current start only): healthy
Filebeat -> Indexer alert pipeline: healthy
FAST                 [ HEALTHY ]
```

A running container is not enough. FAST reports `HEALTHY` only when the Manager process checks and Filebeat -> Indexer output path pass.

## 6. FAST UI

Default:

```text
http://127.0.0.1:5000
```

Health endpoint:

```bash
curl http://127.0.0.1:5000/api/health
```

If you intentionally bind directly to a Tailscale address, set `FAST_WEB_BIND` in `.env`. For the preferred shared-demo model, leave it on localhost and use `./bin/fast-share` instead.

## 7. Wazuh Dashboard

FAST overrides the lab Dashboard host mapping to localhost port 5601 so Tailscale Funnel can own HTTPS 443 for the FAST UI.

Local Wazuh URL:

```text
https://127.0.0.1:5601
```

Upstream lab credentials:

```text
admin
SecretPassword
```

Change upstream defaults before any real exposure.

## 8. Collector CLI

Use the wrapper:

```bash
./bin/fast-cli --fetch
./bin/fast-cli --count
./bin/fast-cli --show | head -15
./bin/fast-cli --export both
./bin/fast-cli --export wazuh
```

The wrapper automatically:

- prepares the virtualenv on first use;
- installs missing apt Python venv/pip packages when required;
- installs Python requirements;
- repairs legacy root-owned `ioc_database.db` and `sample_output` files when needed.

## 9. Connect agents

### Linux

On the target:

```bash
git clone https://github.com/eppzx2/fast-test.git fast-test
cd fast-test
sudo ./linux/install-wazuh-agent.sh --ip <MANAGER_TAILSCALE_IP>
```

Optional name:

```bash
sudo ./linux/install-wazuh-agent.sh --ip <MANAGER_TAILSCALE_IP> --name kali-target
```

### Windows

Elevated PowerShell:

```powershell
.\windows\install-wazuh-agent.ps1 -ManagerIP "<MANAGER_TAILSCALE_IP>"
```

Confirm from the Manager:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

## 10. Prepare Linux target for validation

Run on the Linux target:

```bash
cd ~/fast-test
git pull --ff-only origin main
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

It configures:

- OpenSSH;
- journald collection;
- logging-only `FAST_PORTSCAN` iptables observation ports `56001..56012`;
- auditd `execve` rule with key `audit-wazuh-c`;
- Wazuh collection of `/var/log/audit/audit.log`.

See [SIMULATION_GUIDE.md](SIMULATION_GUIDE.md).

## 11. Share the UI with Tailscale

```bash
./bin/fast-share on
./bin/fast-share status
```

This publishes:

- public FAST UI: Funnel HTTPS 443;
- private Wazuh Dashboard: tailnet-only Serve HTTPS 8443.

Before using Funnel outside a controlled demo, enable FAST authentication.

## 12. Refresh IOCs safely

```bash
./refresh_iocs.sh
```

The refresh runs the collector as the host UID/GID and fails instead of replacing the live CDB when feed collection, export validation, Wazuh validation, Manager recovery, or Filebeat -> Indexer health fails.

## Detection chain deployed by FAST

```text
IOC CDB:       100100 -> 100101 / 100102
SSH:           5710/5760 -> 100199 (silent) -> 100200
Port scan:     4100 -> 100210 -> 100211
LOLBin:        80792 -> 100220 -> 100221
```

## Troubleshooting

### Docker permission denied

```bash
sudo usermod -aG docker "$USER"
```

Reconnect your SSH/login session, then verify:

```bash
docker ps
```

### SQLite/export permission denied

Older Docker runs may have created host files as root. Current FAST normally repairs this automatically.

```bash
./bin/fast-cli --count
./bin/fast-cli --export both
```

If manual repair is required:

```bash
sudo chown "$USER:$(id -gn)" ioc_database.db
sudo chown -R "$USER:$(id -gn)" sample_output
```

### TLS / x509 problems

```bash
./bin/fast up --reset-certs
```

### Manager has alerts but Threat Hunting is empty

```bash
./bin/fast status
```

Filebeat -> Indexer must be healthy.

### SSH brute-force base events exist but 100200 does not

The final rule requires 5 staged failures from the same source IP within 60 seconds. Confirm the deployed rules and validate configuration:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
```

See [runbook.md](runbook.md) for exact rule logic.

## Stop / reset

Preserve persistent Wazuh data:

```bash
./bin/fast down
```

Destructive lab reset:

```bash
cd wazuh-docker/single-node
docker compose down -v
cd ../..
rm -rf wazuh-docker
```

Do not use the destructive reset merely to refresh IOCs or repair TLS.

**Last reviewed:** 2026-09-29
