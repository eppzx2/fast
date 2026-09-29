# FAST IOC Collector User Guide

This guide covers the IOC collector and local web/API behavior on the current `main` branch.

## Preferred setup: `fast-cli`

Clone the repository:

```bash
git clone https://github.com/eppzx2/fast-test.git fast-test
cd fast-test
```

Then use:

```bash
./bin/fast-cli
```

On first use the wrapper can:

- install missing `python3-venv` and `python3-pip` on apt-based hosts;
- create `.venv`;
- install `requirements.txt`;
- repair legacy root-owned collector database/export files;
- execute `cli.py` with the virtualenv Python.

You do not need to manually activate the virtualenv.

## Feed credentials

```bash
cp .env.example .env
```

Set:

```env
ABUSECH_AUTH_KEY=<your-key>
```

The file is git-ignored.

## CLI commands

Help:

```bash
./bin/fast-cli --help
```

Initialize database:

```bash
./bin/fast-cli --init-db
```

Fetch and normalize all feeds:

```bash
./bin/fast-cli --fetch
```

Count stored IOCs:

```bash
./bin/fast-cli --count
```

Show IOC rows:

```bash
./bin/fast-cli --show
```

For a short preview:

```bash
./bin/fast-cli --show | head -15
```

The CLI handles the expected early pipe close cleanly without a Python traceback.

Exports:

```bash
./bin/fast-cli --export csv
./bin/fast-cli --export json
./bin/fast-cli --export both
./bin/fast-cli --export wazuh
```

Outputs:

```text
sample_output/ioc_export.csv
sample_output/ioc_export.json
sample_output/ioc-ips
```

## Fetch behavior

FAST isolates provider failures. One broken provider does not stop successful feeds.

A fetch returns failure when:

- every provider returns zero usable records;
- normalization produces no usable IOCs;
- normalized IOCs cannot be written to SQLite.

This prevents automation from treating a completely empty refresh as success.

## Database semantics

SQLite uniqueness:

```text
(ioc_value, ioc_type)
```

Repeated observations merge:

- source feeds;
- tags;
- earliest `first_seen`;
- latest `last_seen`;
- confidence score based on distinct feed count.

Scoring:

```text
1 feed  = 25
2 feeds = 50
3 feeds = 75
4 feeds = 100
```

Timestamps are normalized to UTC ISO-8601.

## Wazuh CDB export

`--export wazuh` creates `sample_output/ioc-ips`.

Only validated IPv4 and IPv4-CIDR values are exported. URL/hash IOCs remain in SQLite and the UI.

Example:

```text
203.0.113.10:1
198.51.100.0/24:1
```

## Permission handling

Current FAST prevents new root-owned collector files by running Docker collection/refresh jobs with the host UID/GID.

The wrapper also repairs legacy writable-state problems for:

```text
ioc_database.db
sample_output/ioc_export.csv
sample_output/ioc_export.json
sample_output/ioc-ips
```

If a manual repair is ever needed:

```bash
sudo chown "$USER:$(id -gn)" ioc_database.db
sudo chown -R "$USER:$(id -gn)" sample_output
```

## Local web dashboard

For source-level development:

```bash
./bin/fast-cli --init-db
.venv/bin/python app.py
```

Default:

```text
http://127.0.0.1:5000
```

For the complete deployed platform, use `./bin/fast up` instead.

Core IOC routes:

- `GET /api/health`
- `GET /api/iocs`
- `POST /api/fetch`
- `GET /api/export?format=csv|json`
- `GET /api/stats`

Security-operations routes are documented in [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md).

## Full stack operations

```bash
./bin/fast up
./bin/fast status
./bin/fast restart
./bin/fast down
```

Offline demo:

```bash
./bin/fast demo
```

## Refresh a deployed CDB

```bash
./refresh_iocs.sh
```

This path validates the CDB, Wazuh analysis configuration, Manager recovery and Filebeat -> Indexer output before declaring success.

## Tests

Deterministic offline suite:

```bash
python -m pytest -q tests --ignore=tests/acceptance
```

Optional live provider checks:

```bash
FAST_LIVE_FEEDS=1 python -m pytest tests/test_fetchers.py -v
```

## Troubleshooting

### Read-only database

Current `fast-cli` attempts to repair a legacy root-owned database automatically. If the problem remains, inspect:

```bash
ls -l ioc_database.db
ls -ld sample_output
ls -l sample_output
```

Then repair ownership if appropriate.

### CSV permission denied while JSON succeeds

This usually means the existing CSV file has different ownership from the directory/JSON file. Run:

```bash
./bin/fast-cli --export both
```

The current wrapper checks and repairs the export directory before launching the CLI.

### All feeds fail

Verify network access and `ABUSECH_AUTH_KEY`, then retry `./bin/fast-cli --fetch`.

For provider-field details, see [feed_map.md](feed_map.md).

**Last reviewed:** 2026-09-29
