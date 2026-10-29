"""Unit tests for the read-only Wazuh integration."""

from core.wazuh_client import WazuhClient


class FakeResponse:
    def __init__(self, payload=None, text="", status=200):
        self._payload = payload
        self.text = text
        self.status_code = status

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"status {self.status_code}")


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_list_agents_returns_normalized_live_asset_fields(monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_API_URL", "https://manager:55000")
    session = FakeSession(
        [
            FakeResponse(text="jwt-token"),
            FakeResponse(
                {
                    "data": {
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "ebi-VMware",
                                "ip": "100.64.0.20",
                                "status": "active",
                                "os": {"name": "Ubuntu", "version": "24.04", "platform": "ubuntu"},
                                "version": "Wazuh v4.9.0",
                                "lastKeepAlive": "2026-09-12T12:00:00Z",
                            }
                        ],
                        "total_affected_items": 1,
                    }
                }
            ),
        ]
    )
    client = WazuhClient(session=session)
    result = client.list_agents()

    assert result["source"] == "wazuh-server-api"
    assert result["total"] == 1
    assert result["items"][0]["hostname"] == "ebi-VMware"
    assert result["items"][0]["os"] == "Ubuntu"
    assert result["items"][0]["status"] == "active"
    assert session.calls[0][0] == "POST"
    assert session.calls[1][1].endswith("/agents")


def test_recent_alerts_reads_fast_rules_from_indexer(monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_INDEXER_URL", "https://indexer:9200")
    session = FakeSession(
        [
            FakeResponse(
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_id": "alert-1",
                                "_source": {
                                    "timestamp": "2026-09-12T12:05:00Z",
                                    "rule": {"id": "100200", "level": 10, "description": "FAST SSH failed authentication detected"},
                                    "agent": {"id": "001", "name": "ebi-VMware", "ip": "100.64.0.20"},
                                    "data": {"srcip": "100.64.0.30", "dstip": "100.64.0.20", "srcport": "51515", "dstport": "22"},
                                    "audit": {"command": "httpd", "exe": "/tmp/httpd"},
                                    "full_log": "sample raw event",
                                },
                            }
                        ],
                    }
                }
            )
        ]
    )
    client = WazuhClient(session=session)
    result = client.recent_alerts(rule_ids=["100200"], limit=10, minutes=15)

    assert result["source"] == "wazuh-indexer"
    assert result["items"][0]["attack_type"] == "SSH brute-force"
    alert = result["items"][0]
    assert alert["source_ip"] == "100.64.0.30"
    assert alert["source_ip_origin"] == "event"
    assert alert["agent_ip"] == "100.64.0.20"
    assert alert["destination_ip"] == "100.64.0.20"
    assert alert["source_port"] == "51515"
    assert alert["destination_port"] == "22"
    assert alert["process_name"] == "httpd"
    assert alert["process_executable"] == "/tmp/httpd"
    assert alert["full_log"] == "sample raw event"
    body = session.calls[0][2]["json"]
    assert body["query"]["bool"]["filter"][1] == {"terms": {"rule.id": ["100200"]}}
    assert session.calls[0][1].endswith("/wazuh-alerts-*/_search")


def test_local_lolbin_uses_agent_ip_as_source_context(monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_INDEXER_URL", "https://indexer:9200")
    session = FakeSession(
        [
            FakeResponse(
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_id": "lolbin-1",
                                "_source": {
                                    "timestamp": "2026-09-24T10:00:00Z",
                                    "rule": {"id": "100221", "level": 12, "description": "LOLBin confirmed"},
                                    "agent": {"id": "002", "name": "kali", "ip": "100.90.0.15"},
                                    "audit": {"command": "httpd", "exe": "/tmp/httpd"},
                                },
                            }
                        ],
                    }
                }
            )
        ]
    )
    client = WazuhClient(session=session)
    result = client.recent_alerts(rule_ids=["100221"], limit=10, minutes=15)

    alert = result["items"][0]
    assert alert["source_ip"] == "100.90.0.15"
    assert alert["source_ip_origin"] == "agent"
    assert alert["agent_ip"] == "100.90.0.15"



def test_recent_alerts_can_query_all_wazuh_rules_with_filters(monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_INDEXER_URL", "https://indexer:9200")
    session = FakeSession(
        [
            FakeResponse(
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_id": "windows-alert-1",
                                "_source": {
                                    "timestamp": "2026-10-29T12:05:00Z",
                                    "rule": {
                                        "id": "61603",
                                        "level": 10,
                                        "description": "Sysmon: Suspicious PowerShell execution",
                                        "groups": ["windows", "sysmon"],
                                        "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]},
                                    },
                                    "agent": {"id": "001", "name": "workstation", "ip": "192.0.2.10"},
                                    "data": {
                                        "win": {
                                            "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"},
                                            "eventdata": {"commandLine": "powershell -enc ...", "image": "powershell.exe", "parentImage": "winword.exe", "targetUserName": "analyst"},
                                        }
                                    },
                                    "full_log": "Process creation event",
                                },
                            }
                        ],
                    }
                }
            )
        ]
    )
    client = WazuhClient(session=session)
    result = client.recent_alerts(
        rule_ids=None, limit=20, minutes=60, min_level=7, agent_id="001", rule_id="61603", group="sysmon", search="powershell"
    )

    query = session.calls[0][2]["json"]
    filters = query["query"]["bool"]["filter"]
    assert len(filters) == 6
    assert filters[0] == {"range": {"timestamp": {"gte": "now-60m"}}}
    assert filters[1] == {"range": {"rule.level": {"gte": 7}}}
    assert filters[2] == {"term": {"agent.id": "001"}}
    assert filters[3] == {"term": {"rule.id": "61603"}}
    assert filters[4] == {"term": {"rule.groups": "sysmon"}}
    assert filters[5]["simple_query_string"]["query"] == "powershell"
    assert not any("terms" in clause for clause in filters)
    item = result["items"][0]
    assert item["attack_type"] == "Sysmon: Suspicious PowerShell execution"
    assert item["rule_source"] == "Wazuh rule"
    assert item["event_context"]["Windows Event ID"] == "1"
    assert item["event_context"]["Command Line"] == "powershell -enc ..."
