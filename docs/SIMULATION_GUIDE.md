# FAST Attack Simulation Guide

Use this guide to validate the three Linux detections implemented by FAST against a real Wazuh agent.

## Roles

- **Manager** — runs FAST/Wazuh.
- **Target** — Linux endpoint with an Active Wazuh Agent.
- **Runner** — sends SSH and port-scan traffic to the Target.
- **LOLBin simulator** — runs on the Target itself because auditd observes local process execution.

The browser never launches these simulations.

## 1. Update and verify the Manager

```bash
cd ~/fast-test
git checkout main
git pull --ff-only origin main
./bin/fast up
./bin/fast status
```

Healthy baseline:

```text
Wazuh Manager health (current start only): healthy
Filebeat -> Indexer alert pipeline: healthy
FAST                 [ HEALTHY ]
```

Confirm the target agent:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

The target should be `Active`.

## 2. Prepare the Linux Target

Run on the Target:

```bash
cd ~/fast-test
git checkout main
git pull --ff-only origin main
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

The setup is idempotent and configures:

1. OpenSSH server;
2. Wazuh journald collection;
3. logging-only `mangle/PREROUTING` observation for ports `56001..56012` with prefix `FAST_PORTSCAN`;
4. auditd with `execve` key `audit-wazuh-c`;
5. Wazuh audit-log collection from `/var/log/audit/audit.log`.

It does not enable UFW and does not add firewall ACCEPT/DROP policy.

## 3. SSH brute-force validation

Run from the Runner:

```bash
sudo apt-get install -y sshpass   # if missing
./tests/acceptance/sim/simulate_brute_force.sh <TARGET_IP> nonexistent_bruteforce_test_user 8
```

The script counts only attempts that reach a verifiable authentication rejection. TCP/SSH transport failures are not counted as successful simulation attempts.

### Expected rule chain

```text
Wazuh 5710 or 5760
        |
        v
FAST 100199  level 1, no_log
        |
        | same source IP, 5 events inside 60s
        v
FAST 100200  level 10
        |
        +-- ignore=60 suppresses repeat 100200 alerts for 60s
```

Important: `100199` is a silent staging rule and is not expected in normal alert output.

With the default 8-attempt simulation, the expected FAST result is one actionable `100200` brute-force alert, not one alert per failed login.

Verify:

```bash
docker exec single-node-wazuh.manager-1   sh -c "grep -E '\"id\":\"(5710|5760|100200)\"' /var/ossec/logs/alerts/alerts.json | tail -30"
```

## 4. Port-scan validation

Run from the Runner:

```bash
./tests/acceptance/sim/simulate_port_scan.sh <TARGET_IP>
```

Behavior:

- root + nmap -> SYN scan;
- non-root + nmap -> TCP connect scan;
- no nmap -> `/dev/tcp` fallback.

All variants probe the reserved test ports `56001..56012`.

Expected chain:

```text
Wazuh 4100
   |
   v
100210  one FAST_PORTSCAN probe
   |
   | 8+ events, same source, 60s
   v
100211  correlated port scan
```

Target-side marker check:

```bash
sudo journalctl -k --since '2 minutes ago' | grep FAST_PORTSCAN
```

Manager check:

```bash
docker exec single-node-wazuh.manager-1   sh -c "grep -E '\"id\":\"(100210|100211)\"' /var/ossec/logs/alerts/alerts.json | tail -30"
```

## 5. LOLBin / masquerading validation

Run on the Target itself:

```bash
cd ~/fast-test
./tests/acceptance/sim/simulate_lolbin.sh
```

The script:

- copies the local `wget` binary to `/tmp/httpd`;
- executes it with wget-style arguments;
- uses a loopback URL, so Internet access is not required;
- removes temporary files.

Expected chain:

```text
80792
  |
  v
100220  process named httpd from non-standard path
  |
  | same event includes wget-style arguments
  v
100221  confirmed LOLBin / masquerading
```

Target prerequisites:

```bash
sudo systemctl is-active auditd
sudo auditctl -l | grep audit-wazuh-c
sudo grep -F '<location>/var/log/audit/audit.log</location>' /var/ossec/etc/ossec.conf
```

### Source IP in FAST Incidents

The LOLBin alert is a local process/audit event, not a remote network event. Wazuh may therefore have no `srcip`.

FAST uses the agent IP as host context and labels it:

```text
Source IP (host/local event)
```

This is expected behavior.

## 6. Detection Validation UI

After each simulation, open the FAST Detection Validation view.

Expected final rules:

```text
100200  SSH brute force
100211  Port scan
100221  LOLBin / masquerading
```

Validation states:

- PASS — expected rule fired inside the configured freshness window;
- STALE — previously observed in the 24-hour search window but not fresh;
- WAITING — no matching real alert observed.

Default freshness:

```env
FAST_VALIDATION_FRESH_MINUTES=30
```

## 7. Live acceptance suite

From a checkout that can access the Manager Docker socket:

```bash
export TARGET_HOST=<TARGET_IP>
export TARGET_SSH_USER=<TARGET_USER>
python -m pytest tests/acceptance -v
```

The acceptance tests inspect only new Manager alerts generated after each simulation starts.

They are intentionally excluded from normal GitHub Actions because they require a live Manager and endpoint.

## Troubleshooting matrix

| Symptom | Check |
|---|---|
| SSH simulator records fewer than 5 real failures | target sshd/password-auth path, OpenSSH per-source penalties |
| 5710/5760 appears but no 100200 | 5 same-source failures inside 60s; current 100199/100200 rules loaded; `wazuh-analysisd -t` |
| many 100200 alerts from one burst | deployed rule should have `ignore="60"` |
| no FAST_PORTSCAN marker | rerun setup; inspect `iptables -t mangle -S PREROUTING` |
| 100210 but no 100211 | need 8+ probes from same source inside 60s |
| LOLBin preflight fails | auditd active, audit key present, agent collects audit.log |
| 80792 but no 100220 | inspect `audit.command` and `audit.exe` |
| 100220 but no 100221 | inspect raw audit arguments for URL / `-O` evidence |
| Manager has alerts but FAST validation is empty | `./bin/fast status`; Filebeat -> Indexer must be healthy |

See [runbook.md](runbook.md) for detection-engineering details and analyst response guidance.

**Last reviewed:** 2026-09-29
