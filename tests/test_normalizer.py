"""Tests for FAST IOC normalization."""

from datetime import datetime

from core import normalizer


def _is_utc_iso(value: str) -> bool:
    parsed = datetime.fromisoformat(value)
    return parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0


def test_parse_date_is_consistently_utc():
    assert _is_utc_iso(normalizer._parse_date("2024-01-15"))
    assert _is_utc_iso(normalizer._parse_date("2024-01-15 10:30:00"))
    assert _is_utc_iso(normalizer._parse_date("2024-01-15T10:30:00Z"))
    assert _is_utc_iso(normalizer._parse_date(None))


def test_normalize_feodo():
    raw = [
        {"ip_address": "1.2.3.4", "botnet": "dridex", "last_dns_query": "2024-01-15"},
        {"ip_address": "5.6.7.8", "botnet": "emotet", "last_dns_query": "2024-01-16"},
    ]
    result = normalizer.normalize_feodo(raw)
    assert len(result) == 2
    assert result[0]["ioc_value"] == "1.2.3.4"
    assert result[0]["ioc_type"] == "ip"
    assert result[0]["source_feed"] == "feodo"
    assert "dridex" in result[0]["tags"]
    assert result[0]["first_seen"] == result[0]["last_seen"]
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_blocklist_de():
    result = normalizer.normalize_blocklist_de(
        [{"ip_address": "1.2.3.4"}, {"ip_address": "bad-ip"}, {}]
    )
    assert len(result) == 1
    assert result[0]["ioc_value"] == "1.2.3.4"
    assert result[0]["ioc_type"] == "ip"
    assert result[0]["source_feed"] == "blocklist_de"
    assert "blocklist.de" in result[0]["tags"]
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_openphish():
    result = normalizer.normalize_openphish(
        [{"url": "https://phish.example/login"}, {"url": "javascript:alert(1)"}, {}]
    )
    assert len(result) == 1
    assert result[0]["ioc_value"] == "https://phish.example/login"
    assert result[0]["ioc_type"] == "url"
    assert result[0]["source_feed"] == "openphish"
    assert "phishing" in result[0]["tags"]
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_spamhaus():
    result = normalizer.normalize_spamhaus(
        [
            {"cidr": "192.168.1.0/24", "reason": "SBL12345"},
            {"cidr": "10.0.0.0/8", "reason": ""},
        ]
    )
    assert len(result) == 2
    assert result[0]["ioc_type"] == "ip"
    assert "SBL12345" in result[0]["tags"]
    assert result[1]["tags"] == []
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_all():
    raw_feeds = {
        "feodo": [{"ip_address": "1.2.3.4", "last_dns_query": "2024-01-15"}],
        "blocklist_de": [{"ip_address": "5.6.7.8"}],
        "openphish": [{"url": "https://phish.example/login"}],
        "spamhaus": [{"cidr": "192.168.1.0/24", "reason": "test"}],
    }
    result = normalizer.normalize_all(raw_feeds)
    assert len(result) == 4
    assert {item["ioc_type"] for item in result} == {"ip", "url"}
    assert {item["source_feed"] for item in result} == {
        "feodo",
        "blocklist_de",
        "openphish",
        "spamhaus",
    }


def test_normalize_all_unknown_feed_skipped():
    result = normalizer.normalize_all(
        {
            "unknown_feed": [{"some_field": "some_value"}],
            "feodo": [{"ip_address": "1.2.3.4", "last_dns_query": "2024-01-15"}],
        }
    )
    assert len(result) == 1
    assert result[0]["source_feed"] == "feodo"


def test_normalize_all_empty_input():
    assert normalizer.normalize_all({}) == []
