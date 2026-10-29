# FAST Documentation

This index describes the implementation on the `test` branch. Start with the guide that matches your task.

## Start here

| Goal | Document |
|---|---|
| Deploy FAST/Wazuh from scratch | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) |
| Use the IOC collector / `fast-cli` | [user_guide.md](user_guide.md) |
| Publish the UI with Tailscale | [UI_DEPLOYMENT.md](UI_DEPLOYMENT.md) |
| Understand UI tabs and data behavior | [PLATFORM_UI.md](PLATFORM_UI.md) |
| Configure security-operations features | [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) |
| Run the three Linux validation scenarios | [SIMULATION_GUIDE.md](SIMULATION_GUIDE.md) |
| Understand detection chains and response | [runbook.md](runbook.md) |
| Review ATT&CK mappings | [MITRE_MAPPING.md](MITRE_MAPPING.md) |
| Review threat-feed field mapping | [feed_map.md](feed_map.md) |

## Implementation sources of truth

| Topic | Source |
|---|---|
| Lifecycle and status | `bin/fast`, `deploy.sh` |
| Collector CLI | `bin/fast-cli`, `cli.py` |
| Safe IOC refresh | `refresh_iocs.sh` |
| Tailscale sharing | `bin/fast-share` |
| Detections | `docker/rules/local_rules.xml`, `core/detections.py` |
| Wazuh integration | `core/wazuh_client.py`, `core/platform_api.py` |
| Authentication and RBAC | `core/auth.py`, `.env.example` |
| ATT&CK mapping | `core/mitre.py` |
| Validation scripts | `tests/acceptance/sim/` |
| Agent installation | `linux/`, `windows/` |
| UI navigation and incident workflow | `static/fast-platform.js`, `static/security-ops.js` |

## Current primary detection IDs

```text
100200  SSH brute force
100211  Port scan
100221  LOLBin / masquerading
```

Supporting rules `100199`, `100210`, and `100220` are staging/intermediate rules.

## Documentation conventions

- Deployment and update commands target the `test` branch documented here.
- The canonical local checkout directory is `fast`.
- Use `./bin/fast-cli` for collector operations.
- Wazuh is authoritative for agent and alert telemetry; FAST does not fabricate validation alerts.
- Examples are illustrative unless explicitly identified as live output.

**Reviewed:** 2026-10-29
