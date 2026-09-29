# FAST MITRE ATT&CK Mapping

FAST maps its canonical security-operations detections to MITRE ATT&CK Enterprise and overlays real Wazuh activity on that mapping.

## Canonical UI detection mappings

| FAST rule | Detection | ATT&CK technique | Tactic |
|---|---|---|---|
| `100200` | SSH Brute Force | T1110 Brute Force | Credential Access |
| `100211` | Port Scan | T1046 Network Service Scanning | Discovery |
| `100221` | LOLBin / Masquerading | T1036.003 Masquerading: Rename System Utilities | Defense Evasion |
| `100221` | LOLBin / Masquerading | T1105 Ingress Tool Transfer | Command and Control |

These mappings are defined by `core/detections.py` and named/tactic-enriched by `core/mitre.py`.

## Scope boundary

The Wazuh rules file also contains IOC/CDB detections such as `100101` and `100102` with MITRE IDs. Those rules are operational Wazuh detections, but they are not currently part of the three-rule security-operations catalogue used by the MITRE UI.

Therefore the MITRE page represents:

```text
current FAST catalogue coverage
not every MITRE tag present anywhere in local_rules.xml
```

## UI semantics

- **Mapped**: at least one current catalogue rule declares a technique under the tactic.
- **Observed**: Wazuh stored at least one alert for a mapped rule inside the selected window.
- **Not mapped**: no current catalogue rule maps to that tactic.

Mapped coverage does not imply:

- prevention;
- full technique coverage;
- coverage of every sub-technique variant;
- validation on every connected operating system.

## Live data

The UI requests:

```text
GET /api/security/mitre?minutes=1440
```

The backend uses Wazuh Indexer rule activity for:

- alert counts;
- latest trigger;
- latest agents.

Default window: 1440 minutes.

Maximum supported request window in the API: 10080 minutes.

## Enterprise tactic display

FAST renders all Enterprise tactic categories so unmapped areas are visible rather than hidden.

Current mapped tactics from the three-rule catalogue:

```text
Credential Access
Discovery
Defense Evasion
Command and Control
```

## Validation relationship

MITRE mapping is descriptive. Detection Validation separately answers whether a mapped FAST rule has recently produced real Wazuh evidence.

See:

- [SIMULATION_GUIDE.md](SIMULATION_GUIDE.md)
- [runbook.md](runbook.md)

**Last reviewed:** 2026-09-29
