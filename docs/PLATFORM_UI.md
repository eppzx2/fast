# FAST Platform UI

The FAST web application combines the IOC collector dashboard with a security-operations interface backed by real Wazuh telemetry.

## Navigation

The sidebar order is:

1. Overview
2. IOC Database
3. Incidents
4. MITRE ATT&CK
5. Architecture

Operational views that used to appear as separate tabs are grouped under **Architecture**, including the asset catalog, detection information and validation, and system health. The main sidebar stays focused on the five platform areas above.

## Data integrity

The UI reads from:

- FAST's IOC SQLite database;
- Wazuh Server API for agent and system information;
- Wazuh Indexer `wazuh-alerts-*` for alert telemetry;
- FAST's separate operations SQLite database for analyst state and audit records.

FAST does not rewrite Wazuh alert documents or fabricate validation evidence.

## Main views

### Overview

Summarizes current platform and IOC/security status.

### IOC Database

Displays normalized indicators collected from configured threat feeds. This includes IPs, URLs, and hashes where available.

### Incidents

Shows real alerts from the Wazuh Indexer’s `wazuh-alerts-*` indices, including built-in Wazuh rules and FAST custom rules. By default it requests the latest 24 hours and the newest 300 results. If more alerts match, the UI marks the result as sampled.

Filter by time range (1 hour, 24 hours, or 7 days), minimum Wazuh rule level, agent ID, exact rule ID, rule group, or text search. Text search covers alert descriptions, rule groups, agent identifiers/names, source/destination IPs, and raw log text.

The canonical FAST detection catalogue remains the three validated rules:

```text
100200  SSH brute force
100211  Port scan
100221  LOLBin / masquerading
```

That catalogue continues to drive FAST-specific detection health, validation, MITRE coverage, and correlation.

Click **Open** to expand an incident inline. The expanded view only shows fields present in the alert, so unavailable values do not appear as empty fields. Relevant context may include timestamp, rule and level, agent, source/destination addresses and ports, process details, ATT&CK mapping, decoder, Manager, and raw event.

Analyst state includes status, assignee, and notes. Saving a change stores that metadata separately from the Wazuh alert and returns the alert to its compact row. A failed save keeps the form available and shows an error.

For local process events such as the LOLBin simulation, the event may not have a network `srcip`; FAST uses the Wazuh agent IP as explicitly labeled host context.

### MITRE ATT&CK

Shows the current FAST detection catalogue mapped to Enterprise ATT&CK and overlays observed Wazuh activity. Mapped coverage means a catalogue rule declares a technique; observed means a corresponding alert exists in the selected time window. It does not imply full ATT&CK coverage or prevention.

### Architecture

Provides a view of platform components and operational status. It includes the Wazuh-backed asset catalog, detection health/validation information, and system health. The asset catalog may include agent ID, hostname, OS, IP, status, Wazuh version, and last keepalive. Any displayed risk score is an operational prioritization signal based on agent health and recent FAST alerts, not a vulnerability or compliance score.

## Authentication

Authentication is optional and disabled by default for local/demo compatibility.

When `FAST_AUTH_ENABLED=1`:

- unauthenticated UI requests redirect to login;
- unauthenticated API requests return 401;
- role checks are applied;
- protected state-changing routes require CSRF protection.

When disabled, local/demo access remains available.

## Connectivity and runtime routing

The backend provides non-secret UI metadata through:

```text
GET /api/ui-config
```

The Open Wazuh target is selected from:

1. explicit `FAST_WAZUH_DASHBOARD_URL`;
2. the current `*.ts.net` hostname on port 8443;
3. local fallback on port 5601.

The web container joins its FAST network and the Wazuh single-node network. It accesses:

```text
https://wazuh.manager:55000
https://wazuh.indexer:9200
```

Wazuh credentials remain server-side and the web container does not receive the Docker socket.

## Related guides

- [Security Operations](SECURITY_OPERATIONS.md)
- [UI and Tailscale Deployment](UI_DEPLOYMENT.md)
- [MITRE ATT&CK Mapping](MITRE_MAPPING.md)
- [Attack Simulation](SIMULATION_GUIDE.md)

**Reviewed:** 2026-10-29
