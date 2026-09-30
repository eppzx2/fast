# FAST Security Operations

This document describes the security-operations layer implemented on the current `main` branch.

## Design principle

Wazuh remains authoritative for:

- agent inventory;
- alert telemetry;
- rule execution;
- indexed security events.

FAST adds a product layer for:

- analyst workflow state;
- alert context normalization;
- read-only correlations;
- detection health;
- ATT&CK mapping;
- validation status;
- product audit events.

FAST does not rewrite Wazuh alert documents.

## 1. Authentication and RBAC

Authentication is optional and disabled by default for local/demo compatibility.

Enable it in `.env`:

```env
FAST_AUTH_ENABLED=1
FAST_SESSION_SECRET=<long-random-secret>
FAST_SESSION_HOURS=8
FAST_SESSION_COOKIE_SECURE=1
FAST_ADMIN_USER=admin
FAST_ADMIN_PASSWORD=<strong-password>
```

Optional additional users:

```env
FAST_USERS_JSON={"analyst":{"password":"change-me","role":"analyst"},"viewer":{"password":"change-me","role":"viewer"}}
```

Roles:

| Role | Capabilities |
|---|---|
| Viewer | read platform/security telemetry |
| Analyst | Viewer + update incident status/assignee/notes |
| Admin | Analyst + privileged product operations such as audit visibility and intelligence actions |

When authentication is enabled:

- UI/API requests require a session except health/static/login paths;
- state-changing routes can require CSRF;
- cookies are HTTP-only and SameSite=Strict;
- `FAST_SESSION_COOKIE_SECURE=1` should be used behind HTTPS.

When authentication is disabled, FAST behaves as a local admin session for backward-compatible lab operation.

## 2. Incident workflow

Incidents are built from real FAST rule alerts stored in the Wazuh Indexer.

Default incident rule set:

```text
100200  SSH brute force
100211  Port scan
100221  LOLBin / masquerading
```

The Incidents table expands inline. Selecting `Open` adds an expandable detail row directly below the alert instead of opening a detached side panel.

Displayed context includes, when available:

- timestamp;
- detection / rule ID / level;
- agent ID/name;
- agent IP;
- source/destination IP and ports;
- process name;
- executable path;
- ATT&CK IDs/tactics/techniques;
- log location;
- decoder;
- Manager;
- event ID;
- raw event.

### Local-event source IP behavior

Some events are not network events. The LOLBin simulation is based on local audit process execution, so Wazuh may provide no `data.srcip`.

FAST normalization uses:

```text
event srcip, when present
otherwise agent.ip
```

When the fallback is used, the UI labels it as:

```text
Source IP (host/local event)
```

This provides host context without pretending the agent IP is a remote attacker address.

## 3. Analyst state

FAST stores only analyst-owned metadata in `fast_operations.db`:

- `status`: `new`, `investigating`, `resolved`, `false_positive`;
- assignee;
- notes;
- updated time;
- updated by.

The Wazuh alert remains unchanged.

The save workflow provides visible feedback:

```text
Saving... -> Saved ✓
```

and updates the row in place without collapsing the open incident.

Relevant route:

```text
PATCH /api/security/incidents/<event_id>
```

The backend validates that the event exists in the searchable Wazuh window or already has FAST analyst state before persisting an update.

## 4. Read-only correlation

`/api/security/incidents` also returns conservative correlation findings.

FAST groups existing real alert documents by:

- asset;
- source;
- time bucket.

A correlation requires at least two real events. It does not synthesize a Wazuh alert and does not write back to Wazuh.

## 5. Asset catalogue and risk score

`GET /api/security/assets` combines:

- Wazuh agent inventory;
- real FAST detections from the last 24 hours.

The risk score uses only transparent signals:

- agent not Active;
- maximum FAST alert level;
- alert volume;
- number of distinct FAST detection rules.

This is an operational prioritization score, not a vulnerability/compliance score.

## 6. Detection health

`GET /api/security/detections` reports for each canonical FAST detection:

- configured rule ID/name/level;
- ATT&CK mapping;
- alert count in the last 24 hours;
- latest trigger;
- latest agent;
- active/total Wazuh agents.

The detection catalogue is defined in `core/detections.py`.

## 7. Detection Validation

`GET /api/security/validation` evaluates only real Wazuh activity.

States:

- `PASS` - expected rule fired inside `FAST_VALIDATION_FRESH_MINUTES`;
- `STALE` - rule has activity in the 24-hour search window, but not inside the freshness window;
- `WAITING` - no matching alert was observed.

The browser does not execute attack simulations. Run the scripts from the documented lab host and let FAST verify the resulting Wazuh alert.

## 8. MITRE ATT&CK

`GET /api/security/mitre` combines the canonical rule catalogue with live rule activity.

Definitions:

- Mapped: a FAST catalogue detection declares that ATT&CK technique.
- Observed: Wazuh stored at least one alert for the mapped rule in the selected time window.

Mapped does not mean full coverage or prevention.

## 9. Audit trail

FAST records product-side events such as:

- login/logout;
- IOC intelligence sync/export;
- incident workflow changes.

Audit data is stored separately from Wazuh telemetry.

Route:

```text
GET /api/security/audit
```

This route requires Admin when authentication is enabled.

## 10. Wazuh connectivity

The web container joins the Wazuh Docker network and uses server-side credentials:

```text
Wazuh API:     https://wazuh.manager:55000
Wazuh Indexer: https://wazuh.indexer:9200
```

Credentials are configured with `FAST_WAZUH_*` environment variables and are not returned to the browser.

The web container does not receive the Docker socket.

## 11. Operations database

Default:

```env
FAST_OPS_DB_PATH=fast_operations.db
```

This database is separate from `ioc_database.db`.

Current deploy/web container ownership handling is designed so host-side FAST tools can write shared bind-mounted state without creating root-owned files.

## Update / deploy

```bash
cd ~/fast
git checkout main
git pull --ff-only origin main
./bin/fast restart
./bin/fast status
```

**Last reviewed:** 2026-09-29
