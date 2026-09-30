# FAST Documentation Index

This directory documents the current `main` branch of FAST.

## Start here

| Goal | Document |
|---|---|
| Deploy FAST/Wazuh from scratch | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) |
| Use the IOC collector / `fast-cli` | [user_guide.md](user_guide.md) |
| Publish the UI with Tailscale | [UI_DEPLOYMENT.md](UI_DEPLOYMENT.md) |
| Understand platform UI behavior | [PLATFORM_UI.md](PLATFORM_UI.md) |
| Configure security-operations features | [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) |
| Run the three Linux validation scenarios | [SIMULATION_GUIDE.md](SIMULATION_GUIDE.md) |
| Understand exact detection chains and response | [runbook.md](runbook.md) |
| Review ATT&CK mappings | [MITRE_MAPPING.md](MITRE_MAPPING.md) |
| Review threat-feed field mapping | [feed_map.md](feed_map.md) |

## Sources of truth

Documentation should follow these implementation files:

| Topic | Source of truth |
|---|---|
| lifecycle/status | `bin/fast`, `deploy.sh` |
| collector CLI | `bin/fast-cli`, `cli.py` |
| safe refresh | `refresh_iocs.sh` |
| sharing | `bin/fast-share` |
| detections | `docker/rules/local_rules.xml`, `core/detections.py` |
| Wazuh integration | `core/wazuh_client.py` |
| security-operations APIs | `core/platform_api.py`, `core/security_ops.py` |
| authentication/RBAC | `core/auth.py`, `.env.example` |
| ATT&CK mapping | `core/mitre.py` |
| validation scripts | `tests/acceptance/sim/` |
| agent installation | `linux/`, `windows/` |

## Current validated detection IDs

```text
100200  SSH brute force
100211  Port scan
100221  LOLBin / masquerading
```

Supporting rules `100199`, `100210`, and `100220` are staging/intermediate rules.

## Documentation conventions

- Commands target the repository's `main` branch.
- Canonical local checkout name in examples is `fast`.
- `./bin/fast-cli` is preferred over direct `python cli.py`.
- Wazuh is authoritative for telemetry; FAST never fabricates validation alerts.
- Timestamps and examples are illustrative unless explicitly described as live output.

**Last reviewed:** 2026-09-29
