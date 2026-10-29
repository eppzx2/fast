"""Tests for FAST threat-intelligence feed fetchers."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from core import fetchers

live_feed = pytest.mark.skipif(
    os.getenv("FAST_LIVE_FEEDS") != "1",
    reason="set FAST_LIVE_FEEDS=1 to exercise external providers",
)


@live_feed
def test_fetch_feodo_returns_list():
    assert isinstance(fetchers.fetch_feodo(), list)


@live_feed
def test_fetch_blocklist_de_returns_list():
    assert isinstance(fetchers.fetch_blocklist_de(), list)


@live_feed
def test_fetch_openphish_returns_list():
    assert isinstance(fetchers.fetch_openphish(), list)


@live_feed
def test_fetch_spamhaus_returns_list():
    assert isinstance(fetchers.fetch_spamhaus(), list)


def test_fetch_feodo_success_mocked():
    response = MagicMock()
    response.json.return_value = [
        {"ip_address": "1.2.3.4", "botnet": "dridex", "last_dns_query": "2024-01-15"}
    ]
    response.raise_for_status = MagicMock()
    with patch("core.fetchers.requests.get", return_value=response):
        result = fetchers.fetch_feodo()
    assert result[0]["ip_address"] == "1.2.3.4"


def test_fetch_blocklist_de_success_deduplicates_and_skips_invalid():
    response = MagicMock()
    response.text = "# public blocklist\n1.2.3.4\n1.2.3.4\nnot-an-ip\n2001:db8::1\n"
    response.raise_for_status = MagicMock()
    with patch("core.fetchers.requests.get", return_value=response) as request_get:
        result = fetchers.fetch_blocklist_de()
    assert result == [{"ip_address": "1.2.3.4"}, {"ip_address": "2001:db8::1"}]
    assert request_get.call_args.args[0] == fetchers.FEED_URLS["blocklist_de"]


def test_fetch_openphish_success_deduplicates_and_skips_invalid():
    response = MagicMock()
    response.text = (
        "# phishing URLs\nhttps://example.test/login\n"
        "https://example.test/login\nnot-a-url\nftp://example.test/file\n"
    )
    response.raise_for_status = MagicMock()
    with patch("core.fetchers.requests.get", return_value=response) as request_get:
        result = fetchers.fetch_openphish()
    assert result == [{"url": "https://example.test/login"}]
    assert request_get.call_args.args[0] == fetchers.FEED_URLS["openphish"]


def test_fetch_spamhaus_current_ndjson_mocked():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.text = "\n".join(
        [
            json.dumps({"cidr": "1.10.16.0/20", "sblid": "SBL123"}),
            json.dumps({"cidr": "2.56.192.0/22", "sblid": "SBL456"}),
            json.dumps({"type": "metadata", "timestamp": 123456789}),
        ]
    )
    with patch("core.fetchers.requests.get", return_value=response):
        result = fetchers.fetch_spamhaus()
    assert result == [
        {"cidr": "1.10.16.0/20", "reason": "SBL123"},
        {"cidr": "2.56.192.0/22", "reason": "SBL456"},
    ]


def test_fetch_spamhaus_skips_bad_json_line():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.text = 'not-json\n{"cidr":"1.2.3.0/24","sblid":"SBL1"}\n'
    with patch("core.fetchers.requests.get", return_value=response):
        result = fetchers.fetch_spamhaus()
    assert result == [{"cidr": "1.2.3.0/24", "reason": "SBL1"}]


def test_fetch_all_feeds_returns_all_names():
    with patch.object(fetchers, "fetch_feodo", return_value=[]), \
         patch.object(fetchers, "fetch_blocklist_de", return_value=[]), \
         patch.object(fetchers, "fetch_openphish", return_value=[]), \
         patch.object(fetchers, "fetch_spamhaus", return_value=[]),
         patch.object(fetchers, "fetch_malwarebazaar", return_value=[]):
        result = fetchers.fetch_all_feeds()
    assert set(result) == {"feodo", "blocklist_de", "openphish", "spamhaus", "malwarebazaar"}
    assert all(isinstance(items, list) for items in result.values())


def test_fetch_all_feeds_partial_failure_isolated():
    with patch.object(fetchers, "fetch_feodo", return_value=[]), \
         patch.object(fetchers, "fetch_blocklist_de", return_value=[{"ip_address": "1.2.3.4"}]), \
         patch.object(fetchers, "fetch_openphish", return_value=[]), \
         patch.object(fetchers, "fetch_spamhaus", return_value=[{"cidr": "1.2.3.0/24"}]), \
         patch.object(fetchers, "fetch_malwarebazaar", return_value=[]):
        result = fetchers.fetch_all_feeds()
    assert result["feodo"] == []
    assert len(result["blocklist_de"]) == 1
    assert len(result["spamhaus"]) == 1


def test_fetchers_handle_network_errors_independently():
    with patch("core.fetchers.requests.get", side_effect=requests.ConnectionError()):
        assert fetchers.fetch_blocklist_de() == []
        assert fetchers.fetch_openphish() == []
