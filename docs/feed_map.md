# FAST Feed Mapping

FAST normalizes provider-specific threat-intelligence records into one IOC schema.

Provider failures are isolated: one provider can fail while the others continue. A complete all-feed zero-record result is treated as failure by the CLI/deploy/refresh paths.

## Standard normalized schema

```json
{
  "ioc_value": "203.0.113.10",
  "ioc_type": "ip",
  "source_feed": "feodo",
  "first_seen": "2026-09-29T10:30:00+00:00",
  "last_seen": "2026-09-29T10:30:00+00:00",
  "confidence_score": 25,
  "tags": ["botnet-name"]
}
```

Timestamps are normalized to ISO-8601 UTC.

Confidence is recalculated from the number of distinct feeds observing the same `(ioc_value, ioc_type)` pair:

```text
1 feed  -> 25
2 feeds -> 50
3 feeds -> 75
4 or more feeds -> 100
```

## Feodo Tracker

Source:

```text
https://feodotracker.abuse.ch/downloads/ipblocklist.json
```

Mapping:

| Provider field | FAST field |
|---|---|
| `ip_address` | `ioc_value` |
| fixed | `ioc_type = ip` |
| fixed | `source_feed = feodo` |
| `last_dns_query` or `last_online` | `first_seen`, `last_seen` |
| `botnet`, `malware` | `tags` |

Records without `ip_address` are skipped.

## Blocklist.de

Source:

```text
https://lists.blocklist.de/lists/all.txt
```

The public feed is plain text with one reported attacking IP address per line. Blank/comment lines, malformed IPs and duplicate addresses are skipped.

Mapping:

| Provider field | FAST field |
|---|---|
| line value / `ip_address` | `ioc_value` |
| fixed | `ioc_type = ip` |
| fixed | `source_feed = blocklist_de` |
| collection time | `first_seen`, `last_seen` |
| fixed | `tags = [blocklist.de]` |

## OpenPhish

Source:

```text
https://openphish.com/feed.txt
```

This is OpenPhish's public community phishing URL feed. It is plain text with one URL per line. FAST accepts only HTTP/HTTPS URLs with a hostname and removes duplicates.

Mapping:

| Provider field | FAST field |
|---|---|
| line value / `url` | `ioc_value` |
| fixed | `ioc_type = url` |
| fixed | `source_feed = openphish` |
| collection time | `first_seen`, `last_seen` |
| fixed | `tags = [phishing]` |

## Spamhaus DROP

Source:

```text
https://www.spamhaus.org/drop/drop_v4.json
```

The feed is parsed as JSON/NDJSON lines.

Mapping:

| Provider field | FAST field |
|---|---|
| `cidr` | `ioc_value` |
| fixed | `ioc_type = ip` |
| fixed | `source_feed = spamhaus` |
| collection time | `first_seen`, `last_seen` |
| `sblid` or `reason` | `tags` |

Objects without `cidr` and malformed lines are skipped.

## MalwareBazaar

Source: MalwareBazaar Community API, queried for the latest 100 additions:

~~~text
POST https://mb-api.abuse.ch/api/v1/
query=get_recent
selector=100
~~~

The community API is free under its fair-use terms, and requires a free Auth-Key from https://auth.abuse.ch/. Configure it as ABUSECH_AUTH_KEY in the local .env file or environment. If the key is missing, FAST skips this optional feed while continuing the other providers. FAST never downloads malware samples.

Each valid SHA-256, SHA-1 and MD5 value is stored as an independent hash IOC.

| Provider field | FAST field |
|---|---|
| sha256_hash, sha1_hash, md5_hash | ioc_value |
| fixed | ioc_type = hash |
| fixed | source_feed = malwarebazaar |
| first_seen, last_seen | timestamps |
| signature, file_type, file_format, tags | tags |

Hash IOCs remain searchable in the FAST database/UI. The Wazuh CDB exporter remains limited to validated IPv4/CIDR IOCs.

## Aggregate fetch behavior

Use:

```bash
./bin/fast-cli --fetch
```

FAST:

1. fetches each provider independently;
2. normalizes successful provider output;
3. merges/deduplicates normalized IOCs;
4. writes them to SQLite;
5. exits non-zero if all providers return zero data or nothing can be normalized/stored.

Partial provider success is accepted.

## Deduplication

For duplicate `(ioc_value, ioc_type)` rows FAST:

- unions distinct source feeds;
- unions tags without duplicates;
- preserves earliest `first_seen`;
- preserves latest `last_seen`;
- recalculates confidence from distinct feed count.

## Wazuh CDB subset

Use:

```bash
./bin/fast-cli --export wazuh
```

The CDB export intentionally includes only validated IPv4/IPv4-CIDR `ioc_type=ip` values.

It:

- rejects invalid IP strings;
- excludes IPv6 from this CDB;
- canonicalizes IPv4 CIDRs with `strict=False`;
- removes duplicate keys;
- sorts output deterministically.

Output:

```text
sample_output/ioc-ips
```

Format:

```text
203.0.113.10:1
198.51.100.0/24:1
```

URL/hash IOCs remain in the FAST database/UI and are not exported to this IPv4 CDB.

## Permission behavior

Current deploy/refresh paths run the collector using the host UID/GID so generated SQLite/export files remain host-writable.

The `fast-cli` wrapper also repairs legacy root-owned database/export files before running the CLI.

**Reviewed:** 2026-10-29
