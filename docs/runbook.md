# FAST Detection Runbook

This runbook documents the current Linux validation detections, investigation context, response workflow, and troubleshooting.

Rules: `docker/rules/local_rules.xml`

Simulators: `tests/acceptance/sim/`

## Rule chain summary

| Rule | Scenario | Level | Parent / trigger |
|---|---|---:|---|
| `100199` | SSH staging | 1 / no_log | Wazuh `5710` or `5760` |
| `100200` | SSH brute force | 10 | 5 staged failures, same source IP, 60s; `ignore=60` |
| `100210` | port-scan probe | 3 | Wazuh `4100` + `FAST_PORTSCAN` |
| `100211` | port scan | 7 | 8+ `100210` events from same source in 60s |
| `100220` | LOLBin signal | 6 | Wazuh `80792`, `audit.command=httpd`, non-standard executable path |
| `100221` | confirmed LOLBin | 12 | `100220` + wget-style raw arguments |

Primary incident/validation rules are `100200`, `100211`, and `100221`.

---

## 1. SSH brute force — rule 100200

### Detection logic

Wazuh base authentication failures:

```text
5710  invalid/non-existent SSH user
5760  failed password/authentication error
```

FAST stages them:

```xml
<rule id="100199" level="1">
  <if_sid>5710,5760</if_sid>
  <options>no_log</options>
</rule>
```

Final correlation:

```xml
<rule id="100200" level="10" frequency="5" timeframe="60" ignore="60">
  <if_matched_sid>100199</if_matched_sid>
  <same_srcip />
  ...
</rule>
```

### Engineering rationale

One alert per failed password creates noise. The staging/correlation model instead generates a single high-value brute-force incident once the threshold is crossed and suppresses repeated final alerts for 60 seconds.

`100199` must be level 1 rather than level 0 because Wazuh correlation requires matched events to be retained internally. `no_log` prevents those staging events from creating FAST alert noise.

### Triage

Check:

- source IP;
- target agent/host;
- timestamp;
- whether the source is expected administration infrastructure;
- whether failures are followed by successful authentication;
- whether the same source touches multiple hosts.

### Initial response

For an unexpected external source:

1. confirm the event is not a test;
2. inspect surrounding SSH authentication events;
3. identify whether any login succeeded;
4. restrict/block the source where appropriate;
5. review exposed SSH paths and credentials;
6. preserve relevant logs;
7. update FAST incident status/assignee/notes.

---

## 2. Port scan — rule 100211

### Detection logic

Target preparation adds a logging-only `mangle/PREROUTING` rule for TCP SYN packets to `56001..56012` with marker `FAST_PORTSCAN`.

Wazuh rule `4100` parses the kernel/firewall event.

FAST staging:

```text
4100 + FAST_PORTSCAN -> 100210
```

Correlation:

```text
8+ 100210 events
same source IP
within 60 seconds
-> 100211
```

### Triage

Check:

- source IP;
- scanned host;
- destination ports;
- time span and probe volume;
- whether the source is an approved vulnerability scanner;
- whether scanning is followed by authentication or exploitation attempts.

### Response

1. identify authorized scanning infrastructure;
2. compare with maintenance/security-testing windows;
3. inspect adjacent Wazuh/network alerts;
4. block or isolate unexpected hostile scanning where appropriate;
5. escalate if scanning is followed by exploitation or credential attacks.

---

## 3. LOLBin / masquerading — rule 100221

### Detection logic

Prerequisites:

- auditd active;
- `execve` rule key `audit-wazuh-c`;
- Wazuh Agent collects `/var/log/audit/audit.log`.

Base Wazuh grouping:

```text
80792
```

Signal rule `100220` requires:

- `audit.command == httpd`;
- executable path not equal to standard Apache paths.

Confirmation rule `100221` additionally requires wget-style raw arguments such as:

- `http://` or `https://`;
- `--no-check-certificate`;
- `-O` / `--output-document`.

### Triage

Relevant FAST incident fields:

- Host / Agent;
- Agent IP;
- Source IP (host/local event);
- Process;
- Executable;
- Rule ID / Level;
- Raw Event;
- ATT&CK mapping.

Because this is a local process event, absence of a remote network `srcip` is normal.

### Response

1. validate the executable path;
2. hash and inspect the suspicious binary;
3. inspect parent/child process context in available telemetry;
4. review command-line arguments;
5. check persistence and adjacent process activity;
6. isolate the host if malicious execution is suspected;
7. update the FAST incident with findings.

---

## MITRE mapping

| Rule | Technique |
|---|---|
| `100200` | T1110 Brute Force |
| `100211` | T1046 Network Service Scanning |
| `100221` | T1036.003 Masquerading: Rename System Utilities |
| `100221` | T1105 Ingress Tool Transfer |

See [MITRE_MAPPING.md](MITRE_MAPPING.md) for UI semantics.

## One-time target preparation

Run on the Linux target:

```bash
cd ~/fast-test
git pull --ff-only origin main
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

Expected configuration:

```text
journald collected by Wazuh Agent
FAST_PORTSCAN pre-filter logging rule present
auditd execve key audit-wazuh-c active
/var/log/audit/audit.log collected by Wazuh Agent
```

The script creates a one-time backup:

```text
/var/ossec/etc/ossec.conf.fast-backup
```

## Manual simulations

Runner:

```bash
./tests/acceptance/sim/simulate_brute_force.sh <TARGET_IP> nonexistent_bruteforce_test_user 8
./tests/acceptance/sim/simulate_port_scan.sh <TARGET_IP>
```

Target:

```bash
./tests/acceptance/sim/simulate_lolbin.sh
```

## Manager diagnostics

Recent relevant alerts:

```bash
docker exec single-node-wazuh.manager-1   sh -c "grep -E '\"id\":\"(5710|5760|100200|100210|100211|80792|100220|100221)\"'   /var/ossec/logs/alerts/alerts.json | tail -50"
```

Rule/config validation:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
```

Agent list:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Target diagnostics:

```bash
sudo journalctl -k --since '2 minutes ago' | grep FAST_PORTSCAN
sudo auditctl -l | grep audit-wazuh-c
sudo grep -F '<location>/var/log/audit/audit.log</location>' /var/ossec/etc/ossec.conf
```

## Troubleshooting interpretation

- `5710`/`5760` present but no `100200`: verify at least 5 same-source events in 60 seconds and current correlation rule deployment.
- `100200` repeats too frequently: verify deployed rule includes `ignore="60"`.
- `100210` present but no `100211`: fewer than 8 same-source probes were correlated inside 60 seconds.
- `80792` present but no `100220`: inspect `audit.command` and `audit.exe`.
- `100220` present but no `100221`: inspect the same event's raw arguments.
- Manager alert exists but UI/Threat Hunting is empty: verify Filebeat -> Indexer with `./bin/fast status`.

## Tuning guidance

Tune thresholds only with observed environment data.

- Do not reduce SSH threshold merely to make demos faster; the simulator already sends 8 attempts.
- Keep staging rules low/no-log and final rules actionable.
- Keep suppression windows explicit when repeated final alerts would create analyst noise.
- Maintain deterministic test ports separately from production detection logic.
- Validate every rule change with `wazuh-analysisd -t` before Manager restart.
- Update `core/detections.py`, tests and documentation whenever primary rule IDs or semantics change.

**Last reviewed:** 2026-09-29
