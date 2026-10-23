#!/usr/bin/env bash
# Configure automatic Wazuh index retention for this small single-node lab.
# The policy removes only old time-series indices; state/inventory indices and
# Docker volumes are not removed by this script.
set -Eeuo pipefail

INDEXER_URL="${FAST_WAZUH_RETENTION_INDEXER_URL:-https://127.0.0.1:9200}"
INDEXER_URL="${INDEXER_URL%/}"
INDEXER_USER="${FAST_WAZUH_INDEXER_ADMIN_USER:-admin}"
INDEXER_PASSWORD="${FAST_WAZUH_INDEXER_ADMIN_PASSWORD:-SecretPassword}"
RETENTION_DAYS="${FAST_WAZUH_RETENTION_DAYS:-7}"
POLICY_ID="fast-wazuh-retention"
CURL_ARGS=(--insecure --silent --show-error --connect-timeout 3 --max-time 20 --user "$INDEXER_USER:$INDEXER_PASSWORD")

if [[ ! "$RETENTION_DAYS" =~ ^[1-9][0-9]*$ ]] || (( RETENTION_DAYS > 3650 )); then
    echo "[retention] FAST_WAZUH_RETENTION_DAYS must be an integer from 1 to 3650." >&2
    exit 2
fi

echo "[retention] Waiting for Indexer API..."
ready=false
for ((attempt=1; attempt<=30; attempt++)); do
    if curl "${CURL_ARGS[@]}" --fail "$INDEXER_URL/_cluster/health" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 3
done
if [[ "$ready" != true ]]; then
    echo "[retention] Indexer API did not become ready at $INDEXER_URL." >&2
    exit 1
fi

if curl "${CURL_ARGS[@]}" --fail "$INDEXER_URL/_plugins/_ism/policies" >/dev/null 2>&1; then
    ISM_BASE="$INDEXER_URL/_plugins/_ism"
elif curl "${CURL_ARGS[@]}" --fail "$INDEXER_URL/_opendistro/_ism/policies" >/dev/null 2>&1; then
    ISM_BASE="$INDEXER_URL/_opendistro/_ism"
else
    echo "[retention] Index State Management API is unavailable." >&2
    exit 1
fi

POLICY_URL="$ISM_BASE/policies/$POLICY_ID"
POLICY_BODY="$(cat <<EOF
{
  "policy": {
    "policy_id": "$POLICY_ID",
    "description": "FAST time-series retention; remove old indices after $RETENTION_DAYS days.",
    "schema_version": 1,
    "default_state": "active",
    "states": [
      {
        "name": "active",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": { "min_index_age": "${RETENTION_DAYS}d" }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "retry": { "count": 3, "backoff": "exponential", "delay": "1m" },
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": [
          "wazuh-alerts-4.x-*",
          "wazuh-archives-4.x-*",
          "wazuh-monitoring-*",
          "wazuh-statistics-*"
        ],
        "priority": 100
      }
    ]
  }
}
EOF
)"

existing="$(curl "${CURL_ARGS[@]}" "$POLICY_URL" 2>/dev/null || true)"
seq_no="$(printf '%s' "$existing" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("_seq_no", ""))' 2>/dev/null || true)"
primary_term="$(printf '%s' "$existing" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("_primary_term", ""))' 2>/dev/null || true)"
if [[ "$seq_no" =~ ^[0-9]+$ && "$primary_term" =~ ^[0-9]+$ ]]; then
    POLICY_URL="$POLICY_URL?if_seq_no=$seq_no&if_primary_term=$primary_term"
fi
curl "${CURL_ARGS[@]}" --fail -X PUT "$POLICY_URL" \
    -H "Content-Type: application/json" --data "$POLICY_BODY" >/dev/null
echo "[retention] Policy configured for $RETENTION_DAYS days."

# Apply to existing time-series indices. New indices inherit the policy through
# the ISM template above. Other state/inventory indices are deliberately excluded.
for pattern in 'wazuh-alerts-4.x-*' 'wazuh-archives-4.x-*' 'wazuh-monitoring-*' 'wazuh-statistics-*'; do
    curl "${CURL_ARGS[@]}" --fail -X POST "$ISM_BASE/add/$pattern" \
        -H "Content-Type: application/json" --data "{\"policy_id\":\"$POLICY_ID\"}" >/dev/null || true
done

echo "[retention] Policy installed; matching time-series indices are covered."
