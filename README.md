# F.A.S.T. — Fully Automated SIEM & Threat Intelligence Platform

FAST combines OSINT threat intelligence, a pinned Wazuh 4.9.0 single-node SIEM, custom detections, incident workflow, MITRE ATT&CK mapping, and validation tooling in one lab-oriented platform.

## Quick start

```bash
git clone https://github.com/eppzx2/fast-test.git fast-test
cd fast-test
./bin/fast up
./bin/fast status
```

Main lifecycle commands:

```bash
./bin/fast up                 # deploy/start FAST with live IOC feeds
./bin/fast demo               # deploy with bundled IOC fixture
./bin/fast status             # verify containers, Manager and Filebeat -> Indexer
./bin/fast restart
./bin/fast down               # stop while preserving named Wazuh data volumes
./bin/fast up --reset-certs   # rebuild the Wazuh TLS bundle without deleting data
```

## Architecture

```text
OSINT feeds
  |
  v
FAST IOC Collector -> SQLite -> validated IPv4/CIDR CDB
                                   |
                                   v
Endpoint -> Wazuh Agent -> Wazuh Manager -> Filebeat -> Wazuh Indexer
                                |                         |
                                |                         +-> Threat Hunting
                                +-> FAST custom rules
                                                           |
                                                           v
                                                     FAST Web UI
                                                     - Overview
                                                     - IOC Database
                                                     - Incidents
                                                     - Detections
                                                     - MITRE ATT&CK
                                                     - Validation
                                                     - Architecture
                                                     - System Health
```

Wazuh remains the source of truth for agents and alerts. FAST stores IOC data plus analyst-owned workflow metadata in separate SQLite files.

## Threat feeds

| Feed | FAST data | Access |
|---|---|---|
| Feodo Tracker | botnet C2 IPv4s | public |
| URLhaus | malicious URLs | abuse.ch Auth-Key preferred; compatibility fallback retained |
| MalwareBazaar | malware hashes/metadata | free abuse.ch Auth-Key recommended |
| Spamhaus DROP | malicious IPv4/CIDR netblocks | public |

Configure local feed credentials:

```bash
cp .env.example .env
# set ABUSECH_AUTH_KEY=...
```

The file is git-ignored.

## Collector CLI

Use the bootstrap wrapper. It creates `.venv`, installs missing Python packages on apt-based systems, installs `requirements.txt`, repairs legacy root-owned FAST state files when needed, and then runs `cli.py` with the virtualenv Python.

```bash
./bin/fast-cli --help
./bin/fast-cli --init-db
./bin/fast-cli --fetch
./bin/fast-cli --count
./bin/fast-cli --show
./bin/fast-cli --show | head -15
./bin/fast-cli --export csv
./bin/fast-cli --export json
./bin/fast-cli --export both
./bin/fast-cli --export wazuh
```

No manual `source .venv/bin/activate` step is required.

The Wazuh export contains only validated IPv4/IPv4-CIDR keys. URL/hash IOCs remain available in FAST but are not written to `sample_output/ioc-ips`.

## Detection rules

### IOC/CDB rules

| Rule | Purpose | Level |
|---|---|---:|
| `100100` | silent IOC CDB lookup base | 0 |
| `100101` | known-bad source IP in a network event | 12 |
| `100102` | authentication attempt from a known-bad source IP | 12 |

### Validation detections

| Rule | Detection | Trigger | Level |
|---|---|---|---:|
| `100199` | SSH staging | Wazuh `5710`/`5760`, `no_log` | 1 |
| `100200` | SSH brute force | 5 failures, same source IP, 60s; repeat suppression 60s | 10 |
| `100210` | port-scan probe | one `FAST_PORTSCAN` kernel event | 3 |
| `100211` | port scan | 8+ probes from one source in 60s | 7 |
| `100220` | LOLBin signal | process named `httpd` from non-standard path | 6 |
| `100221` | confirmed LOLBin | 100220 plus wget-style arguments | 12 |

Expected validation alerts are `100200`, `100211`, and `100221`.

## Web UI and security operations

Default local FAST UI:

```text
http://127.0.0.1:5000
```

The security-operations layer uses real Wazuh data for:

- agent/asset inventory;
- detection health and last-triggered state;
- incident cases with inline expandable details;
- analyst state: status, assignee and notes;
- source/destination/process context;
- MITRE ATT&CK mapping;
- detection validation;
- product-side audit events.

For local process events such as the LOLBin simulation, Wazuh may not provide a network `srcip`. FAST then displays the Wazuh agent IP as `Source IP (host/local event)` instead of inventing an attacker network address.

Authentication is optional and disabled by default for local/demo compatibility. Enable it before exposing a real deployment.

## Tailscale sharing

After FAST is healthy:

```bash
./bin/fast-share on
./bin/fast-share status
./bin/fast-share off
```

The helper publishes:

- FAST UI through Tailscale Funnel on HTTPS 443;
- Wazuh Dashboard through tailnet-only Tailscale Serve on HTTPS 8443.

Do not expose the public FAST UI with authentication disabled outside a controlled demo.

## Refresh IOCs

```bash
./refresh_iocs.sh
```

The refresh fails safely if collection/export/Manager validation or Filebeat -> Indexer verification fails.

## Agents

Linux:

```bash
sudo ./linux/install-wazuh-agent.sh --ip <MANAGER_IP>
```

Windows, elevated PowerShell:

```powershell
.\windows\install-wazuh-agent.ps1 -ManagerIP "<MANAGER_IP>"
```

## Tests and CI

Normal CI on `main` performs:

- Python compilation;
- browser JavaScript syntax checks;
- Bash syntax checks;
- deterministic unit/static integration tests.

Live acceptance tests require a deployed Manager and Linux target:

```bash
export TARGET_HOST=<TARGET_IP>
export TARGET_SSH_USER=<TARGET_USER>
python -m pytest tests/acceptance -v
```

## Documentation

Start with [docs/README.md](docs/README.md).

Key guides:

- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- [IOC Collector User Guide](docs/user_guide.md)
- [UI / Tailscale Deployment](docs/UI_DEPLOYMENT.md)
- [Security Operations](docs/SECURITY_OPERATIONS.md)
- [Attack Simulation Guide](docs/SIMULATION_GUIDE.md)
- [Detection Runbook](docs/runbook.md)
- [MITRE ATT&CK Mapping](docs/MITRE_MAPPING.md)
- [Feed Mapping](docs/feed_map.md)

## Security notes

The repository is suitable for lab/demo use by default, not direct Internet production exposure. Before production use:

- change upstream Wazuh default credentials;
- restrict Wazuh ports with a firewall/VPN;
- enable FAST authentication and use a strong session secret;
- use secure cookies when served over HTTPS;
- keep `.env` out of git;
- verify TLS instead of relying on demo self-signed defaults where practical;
- do not expose Docker socket or privileged deployment controls to the web container.

**Documentation baseline:** 2026-09-29
