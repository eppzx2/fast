# FAST Platform UI

The FAST web application is a security-operations interface layered on top of the IOC collector and live Wazuh telemetry.

## Data integrity principle

The UI does not generate fake alerts. Security views are backed by:

- FAST's SQLite IOC database;
- Wazuh Server API;
- Wazuh Indexer `wazuh-alerts-*`;
- FAST's separate analyst-state/audit SQLite database.

## Main views

### Overview

Summarizes the current FAST environment and IOC/security state.

### IOC Database

Displays normalized IOC records collected from FAST threat feeds.

### Incidents

Shows real Wazuh alerts for the canonical FAST validation rules.

Each row can expand inline to display alert details. The expanded content remains in the same table flow rather than using a detached side panel.

Analyst-editable fields:

- status;
- assignee;
- notes.

Saving provides visible success/error feedback.

### Detections

Combines the static catalogue in `core/detections.py` with live Wazuh activity.

Current catalogue:

```text
100200  SSH Brute Force
100211  Port Scan
100221  LOLBin / Masquerading
```

Supporting staging rules are intentionally not shown as primary catalogue detections.

### MITRE ATT&CK

Shows Enterprise ATT&CK tactics with current FAST mappings and live observation state.

The UI distinguishes:

- mapped coverage;
- observed activity;
- unmapped tactics.

It does not claim full ATT&CK coverage.

### Detection Validation

Validation is evidence-based:

- PASS;
- STALE;
- WAITING.

FAST does not launch attacks from the browser. Use the scripts under `tests/acceptance/sim/` and allow Wazuh to generate the expected real alert.

### Architecture / Asset Catalog

The asset catalogue queries the Wazuh Server API and can show:

- agent ID;
- hostname;
- OS;
- IP;
- status;
- Wazuh version;
- last keepalive;
- transparent FAST risk score.

The risk score is based on agent health and recent FAST detections only.

### System Health / Audit

System Health exposes current platform state and product-side audit information subject to role permissions.

## Incident field normalization

FAST normalizes common alert fields from the Indexer:

- `data.srcip` / `data.src_ip`;
- `data.dstip` / `data.dst_ip`;
- `data.srcport` / `data.dstport`;
- `audit.command` / `data.command`;
- `audit.exe` / `data.exe`;
- `full_log`.

For local process events without a network source address, the agent IP is used as host context and is explicitly marked in the UI as a local-event source.

## Authentication behavior

Authentication is optional.

When `FAST_AUTH_ENABLED=1`:

- unauthenticated UI requests redirect to login;
- unauthenticated API requests return 401;
- role checks apply;
- CSRF is required for protected state-changing routes.

When disabled, existing local/demo use remains available.

## Runtime routing

The backend provides non-secret UI metadata through:

```text
GET /api/ui-config
```

The Open Wazuh target is derived from:

1. explicit `FAST_WAZUH_DASHBOARD_URL`;
2. the current `*.ts.net` hostname on port 8443;
3. local fallback on port 5601.

## Connectivity

The Docker web container joins:

- its default FAST compose network;
- the existing Wazuh single-node network.

Default internal services:

```text
https://wazuh.manager:55000
https://wazuh.indexer:9200
```

The browser never receives those credentials.

## Related documentation

- [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md)
- [UI_DEPLOYMENT.md](UI_DEPLOYMENT.md)
- [MITRE_MAPPING.md](MITRE_MAPPING.md)
- [SIMULATION_GUIDE.md](SIMULATION_GUIDE.md)

**Last reviewed:** 2026-09-29
