"""Read-only Wazuh integration used by the FAST platform UI.

The browser never receives Wazuh credentials. FAST talks to the Wazuh server
API for agent inventory and to the Wazuh Indexer for alert documents, then
returns only the fields needed by the product UI.
"""

from __future__ import annotations

import os
from typing import Iterable

import requests


FAST_RULE_IDS = ("100200", "100211", "100221")
FAST_CUSTOM_RULE_IDS = frozenset(
    {"100101", "100102", "100199", "100200", "100210", "100211", "100220", "100221"}
)
ATTACK_TYPES = {
    "100200": "SSH brute-force",
    "100211": "Port scan",
    "100221": "LOLBin / masquerading",
}


def _nested_value(value: dict, path: tuple[str, ...]):
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


class WazuhIntegrationError(RuntimeError):
    """Raised when a live Wazuh dependency cannot be queried safely."""


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _clean_base_url(value: str) -> str:
    return value.strip().rstrip("/")


class WazuhClient:
    """Minimal read-only client for the Wazuh API and Indexer."""

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        self.manager_url = _clean_base_url(
            os.getenv("FAST_WAZUH_API_URL", "https://wazuh.manager:55000")
        )
        self.manager_user = os.getenv("FAST_WAZUH_API_USER", "wazuh-wui")
        self.manager_password = os.getenv(
            "FAST_WAZUH_API_PASSWORD", "MyS3cr37P450r.*-"
        )
        self.indexer_url = _clean_base_url(
            os.getenv("FAST_WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
        )
        self.indexer_user = os.getenv("FAST_WAZUH_INDEXER_USER", "admin")
        self.indexer_password = os.getenv(
            "FAST_WAZUH_INDEXER_PASSWORD", "SecretPassword"
        )
        self.timeout = max(2, min(30, int(os.getenv("FAST_WAZUH_TIMEOUT", "8"))))
        ca_bundle = os.getenv("FAST_WAZUH_CA_BUNDLE", "").strip()
        self.verify: bool | str = ca_bundle or _env_bool(
            "FAST_WAZUH_VERIFY_TLS", False
        )

    def _request(self, method: str, url: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            raise WazuhIntegrationError(f"Wazuh request failed: {exc}") from exc

    def _manager_token(self) -> str:
        response = self._request(
            "POST",
            f"{self.manager_url}/security/user/authenticate",
            params={"raw": "true"},
            auth=(self.manager_user, self.manager_password),
        )
        token = response.text.strip()
        if token.startswith("{"):
            try:
                token = response.json().get("data", {}).get("token", "")
            except ValueError as exc:
                raise WazuhIntegrationError(
                    "Wazuh API returned an invalid authentication response"
                ) from exc
        if not token:
            raise WazuhIntegrationError("Wazuh API did not return an auth token")
        return token

    def list_agents(self) -> dict:
        """Return a normalized live asset catalogue from the Wazuh server API."""
        token = self._manager_token()
        response = self._request(
            "GET",
            f"{self.manager_url}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={
                "limit": 500,
                "select": (
                    "id,name,ip,status,os.name,os.version,os.platform,"
                    "version,lastKeepAlive,node_name,manager"
                ),
                "sort": "+id",
            },
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise WazuhIntegrationError("Wazuh API returned invalid JSON") from exc

        data = payload.get("data") or {}
        affected = data.get("affected_items") or []
        items = []
        for agent in affected:
            os_info = agent.get("os") or {}
            items.append(
                {
                    "id": str(agent.get("id") or ""),
                    "hostname": agent.get("name") or "Unknown",
                    "ip": agent.get("ip") or "Unknown",
                    "status": str(agent.get("status") or "unknown").lower(),
                    "os": os_info.get("name") or os_info.get("platform") or "Unknown",
                    "os_version": os_info.get("version") or "",
                    "os_platform": os_info.get("platform") or "",
                    "wazuh_version": agent.get("version") or "",
                    "last_keepalive": agent.get("lastKeepAlive") or "",
                    "node": agent.get("node_name") or "",
                    "manager": agent.get("manager") or "",
                }
            )

        return {
            "source": "wazuh-server-api",
            "items": items,
            "total": int(data.get("total_affected_items") or len(items)),
        }

    def recent_alerts(
        self,
        *,
        rule_ids: Iterable[str] | None = FAST_RULE_IDS,
        limit: int = 30,
        minutes: int = 30,
        min_level: int | None = None,
        agent_id: str = "",
        rule_id: str = "",
        group: str = "",
        search: str = "",
        event_id: str = "",
    ) -> dict:
        """Return recent Wazuh alerts from the Indexer.

        Passing rule_ids=None searches all indexed alerts. The default remains
        FAST_RULE_IDS so existing FAST-specific views keep their exact scope.
        """
        limit = max(1, min(500, int(limit)))
        minutes = max(1, min(10080, int(minutes)))
        selected_rules = (
            [str(rule_id) for rule_id in rule_ids if str(rule_id)]
            if rule_ids is not None
            else None
        )
        if selected_rules is not None and not selected_rules:
            selected_rules = list(FAST_RULE_IDS)

        filters = [{"range": {"timestamp": {"gte": f"now-{minutes}m"}}}]
        if selected_rules is not None:
            filters.append({"terms": {"rule.id": selected_rules}})
        if min_level is not None and int(min_level) > 0:
            filters.append({"range": {"rule.level": {"gte": max(0, min(15, int(min_level)))}}})
        if agent_id:
            filters.append({"term": {"agent.id": str(agent_id)[:64]}})
        if rule_id:
            filters.append({"term": {"rule.id": str(rule_id)[:32]}})
        if group:
            filters.append({"term": {"rule.groups": str(group)[:64]}})
        if event_id:
            filters.append({"ids": {"values": [str(event_id)[:256]]}})
        if search:
            filters.append(
                {
                    "simple_query_string": {
                        "query": str(search)[:120],
                        "fields": [
                            "rule.id",
                            "rule.description",
                            "rule.groups",
                            "agent.name",
                            "agent.id",
                            "data.srcip",
                            "data.dstip",
                            "data.srcuser",
                            "data.dstuser",
                            "data.url",
                            "data.win.eventdata.commandLine",
                            "data.win.eventdata.image",
                            "data.win.eventdata.parentImage",
                            "full_log",
                        ],
                        "default_operator": "and",
                        "lenient": True,
                    }
                }
            )

        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"bool": {"filter": filters}},
            "_source": [
                "timestamp",
                "rule.id",
                "rule.level",
                "rule.description",
                "rule.groups",
                "rule.mitre.id",
                "rule.mitre.tactic",
                "rule.mitre.technique",
                "agent.id",
                "agent.name",
                "agent.ip",
                "manager.name",
                "location",
                "decoder.name",
                "data.srcip",
                "data.src_ip",
                "data.dstip",
                "data.dst_ip",
                "data.srcport",
                "data.dstport",
                "data.srcuser",
                "data.dstuser",
                "data.protocol",
                "data.action",
                "data.url",
                "data.file",
                "data.sha256",
                "data.win.system.eventID",
                "data.win.system.providerName",
                "data.win.system.channel",
                "data.win.eventdata.subjectUserName",
                "data.win.eventdata.targetUserName",
                "data.win.eventdata.ipAddress",
                "data.win.eventdata.commandLine",
                "data.win.eventdata.image",
                "data.win.eventdata.parentImage",
                "data.win.eventdata.processId",
                "data.command",
                "data.exe",
                "audit.command",
                "audit.exe",
                "full_log",
            ],
        }
        response = self._request(
            "POST",
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_password),
            headers={"Content-Type": "application/json"},
            json=query,
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise WazuhIntegrationError("Wazuh Indexer returned invalid JSON") from exc

        hits_block = payload.get("hits") or {}
        raw_hits = hits_block.get("hits") or []
        items = []
        for hit in raw_hits:
            source = hit.get("_source") or {}
            rule = source.get("rule") or {}
            agent = source.get("agent") or {}
            event_data = source.get("data") or {}
            audit_data = source.get("audit") or {}
            mitre = rule.get("mitre") or {}
            rule_id = str(rule.get("id") or "")
            agent_ip = agent.get("ip") or ""
            event_source_ip = (
                event_data.get("srcip")
                or event_data.get("src_ip")
                or ""
            )
            source_ip = event_source_ip or agent_ip
            source_ip_origin = (
                "event"
                if event_source_ip
                else ("agent" if agent_ip else "")
            )
            items.append(
                {
                    "event_id": hit.get("_id") or "",
                    "timestamp": source.get("timestamp") or "",
                    "attack_type": (
                        ATTACK_TYPES.get(rule_id)
                        or rule.get("description")
                        or "Wazuh alert"
                    ),
                    "rule_source": (
                        "FAST custom"
                        if rule_id in FAST_CUSTOM_RULE_IDS
                        else "Wazuh rule"
                    ),
                    "rule_id": rule_id,
                    "level": rule.get("level"),
                    "description": rule.get("description") or "",
                    "groups": rule.get("groups") or [],
                    "mitre_ids": mitre.get("id") or [],
                    "mitre_tactics": mitre.get("tactic") or [],
                    "mitre_techniques": mitre.get("technique") or [],
                    "agent_id": str(agent.get("id") or ""),
                    "agent_name": agent.get("name") or "Unknown",
                    "agent_ip": agent_ip,
                    "source_ip": source_ip,
                    "source_ip_origin": source_ip_origin,
                    "destination_ip": (
                        event_data.get("dstip")
                        or event_data.get("dst_ip")
                        or ""
                    ),
                    "source_port": event_data.get("srcport") or "",
                    "destination_port": event_data.get("dstport") or "",
                    "process_name": (
                        audit_data.get("command")
                        or event_data.get("command")
                        or ""
                    ),
                    "process_executable": (
                        audit_data.get("exe")
                        or event_data.get("exe")
                        or ""
                    ),
                    "location": source.get("location") or "",
                    "decoder": (source.get("decoder") or {}).get("name") or "",
                    "manager": (source.get("manager") or {}).get("name") or "",
                    "full_log": source.get("full_log") or "",
                    "event_context": {
                        label: str(value)
                        for label, value in (
                            ("Windows Event ID", _nested_value(event_data, ("win", "system", "eventID"))),
                            ("Event Provider", _nested_value(event_data, ("win", "system", "providerName"))),
                            ("Event Channel", _nested_value(event_data, ("win", "system", "channel"))),
                            ("User", event_data.get("dstuser") or event_data.get("srcuser") or _nested_value(event_data, ("win", "eventdata", "targetUserName")) or _nested_value(event_data, ("win", "eventdata", "subjectUserName"))),
                            ("Command Line", _nested_value(event_data, ("win", "eventdata", "commandLine"))),
                            ("Image", _nested_value(event_data, ("win", "eventdata", "image"))),
                            ("Parent Image", _nested_value(event_data, ("win", "eventdata", "parentImage"))),
                            ("Protocol", event_data.get("protocol")),
                            ("Action", event_data.get("action")),
                            ("URL", event_data.get("url")),
                            ("File", event_data.get("file")),
                            ("SHA-256", event_data.get("sha256")),
                        )
                        if value is not None and str(value).strip()
                    },
                }
            )

        total_raw = hits_block.get("total", len(items))
        total = (
            int(total_raw.get("value") or 0)
            if isinstance(total_raw, dict)
            else int(total_raw or 0)
        )
        return {
            "source": "wazuh-indexer",
            "items": items,
            "total": total,
            "sampled": total > len(items),
            "window_minutes": minutes,
            "rule_ids": selected_rules or [],
        }

    def rule_activity(
        self,
        *,
        rule_ids: Iterable[str] = FAST_RULE_IDS,
        minutes: int = 1440,
    ) -> dict:
        """Return exact alert counts and latest hits per FAST rule."""
        minutes = max(1, min(10080, int(minutes)))
        selected_rules = [str(rule_id) for rule_id in rule_ids if str(rule_id)] or list(FAST_RULE_IDS)
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"timestamp": {"gte": f"now-{minutes}m"}}},
                        {"terms": {"rule.id": selected_rules}},
                    ]
                }
            },
            "aggs": {
                "by_rule": {
                    "terms": {"field": "rule.id", "size": max(10, len(selected_rules))},
                    "aggs": {
                        "latest": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"timestamp": {"order": "desc"}}],
                                "_source": [
                                    "timestamp",
                                    "rule.id",
                                    "rule.level",
                                    "agent.id",
                                    "agent.name",
                                ],
                            }
                        }
                    },
                }
            },
        }
        response = self._request(
            "POST",
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_password),
            headers={"Content-Type": "application/json"},
            json=query,
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise WazuhIntegrationError("Wazuh Indexer returned invalid JSON") from exc

        items = {rule_id: {"rule_id": rule_id, "count": 0, "last_triggered": "", "last_agent": ""} for rule_id in selected_rules}
        buckets = (((payload.get("aggregations") or {}).get("by_rule") or {}).get("buckets") or [])
        for bucket in buckets:
            rule_id = str(bucket.get("key") or "")
            if rule_id not in items:
                continue
            latest_hits = (((bucket.get("latest") or {}).get("hits") or {}).get("hits") or [])
            latest_source = (latest_hits[0].get("_source") or {}) if latest_hits else {}
            agent = latest_source.get("agent") or {}
            items[rule_id] = {
                "rule_id": rule_id,
                "count": int(bucket.get("doc_count") or 0),
                "last_triggered": latest_source.get("timestamp") or "",
                "last_agent": agent.get("name") or agent.get("id") or "",
            }

        return {
            "source": "wazuh-indexer",
            "items": [items[rule_id] for rule_id in selected_rules],
            "window_minutes": minutes,
        }
