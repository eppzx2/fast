"""Threat-intelligence feed fetchers used by FAST.

The collector intentionally treats individual feed failures as non-fatal so one
provider outage cannot stop the remaining feeds. Callers can inspect the
returned per-feed lists and decide whether an all-feed failure is fatal.
"""

import ipaddress
import json
import logging
from typing import Any, Dict, List
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "FAST-IOC-Collector/1.0 (+https://github.com/eppzx2/fast)"
REQUEST_TIMEOUT = 20

FEED_URLS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
    "openphish": "https://openphish.com/feed.txt",
    "spamhaus": "https://www.spamhaus.org/drop/drop_v4.json",
}


def _headers() -> Dict[str, str]:
    return {"User-Agent": USER_AGENT}


def fetch_feodo() -> List[Dict[str, Any]]:
    """Fetch Feodo Tracker botnet C2 IPs."""
    url = FEED_URLS["feodo"]
    try:
        logger.info("Fetching Feodo Tracker: %s", url)
        response = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            result = payload["data"]
        elif isinstance(payload, list):
            result = payload
        else:
            logger.warning("Feodo: unexpected JSON structure")
            return []
        logger.info("Feodo: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("Feodo Tracker request failed: %s", exc)
    except (ValueError, TypeError) as exc:
        logger.error("Feodo Tracker parse failed: %s", exc)
    return []


def fetch_blocklist_de() -> List[Dict[str, Any]]:
    """Fetch Blocklist.de's public plain-text list of reported attacking IPs."""
    url = FEED_URLS["blocklist_de"]
    try:
        logger.info("Fetching Blocklist.de: %s", url)
        response = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result: List[Dict[str, Any]] = []
        seen = set()
        for line in response.text.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                logger.warning("Blocklist.de: skipping invalid IP address %r", value)
                continue
            if address not in seen:
                seen.add(address)
                result.append({"ip_address": address})
        logger.info("Blocklist.de: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("Blocklist.de request failed: %s", exc)
    return []


def fetch_openphish() -> List[Dict[str, Any]]:
    """Fetch OpenPhish's public community phishing URL feed."""
    url = FEED_URLS["openphish"]
    try:
        logger.info("Fetching OpenPhish: %s", url)
        response = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result: List[Dict[str, Any]] = []
        seen = set()
        for line in response.text.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                parsed = urlsplit(value)
                if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                    logger.warning("OpenPhish: skipping invalid URL %r", value)
                    continue
            except ValueError:
                logger.warning("OpenPhish: skipping malformed URL %r", value)
                continue
            if value not in seen:
                seen.add(value)
                result.append({"url": value})
        logger.info("OpenPhish: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("OpenPhish request failed: %s", exc)
    return []


def fetch_spamhaus() -> List[Dict[str, Any]]:
    """Fetch Spamhaus DROP IPv4 ranges from the current NDJSON dataset."""
    url = FEED_URLS["spamhaus"]
    try:
        logger.info("Fetching Spamhaus DROP: %s", url)
        response = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result: List[Dict[str, Any]] = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Spamhaus: skipping malformed JSON line: %s", exc)
                continue
            if not isinstance(item, dict) or not item.get("cidr"):
                continue
            result.append(
                {
                    "cidr": str(item["cidr"]).strip(),
                    "reason": str(item.get("sblid") or item.get("reason") or "").strip(),
                }
            )
        logger.info("Spamhaus: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("Spamhaus request failed: %s", exc)
    except (ValueError, TypeError) as exc:
        logger.error("Spamhaus parse failed: %s", exc)
    return []


def fetch_all_feeds() -> Dict[str, List[Dict[str, Any]]]:
    """Fetch every configured feed independently and return all results."""
    fetch_functions = {
        "feodo": fetch_feodo,
        "blocklist_de": fetch_blocklist_de,
        "openphish": fetch_openphish,
        "spamhaus": fetch_spamhaus,
    }
    results: Dict[str, List[Dict[str, Any]]] = {}
    for feed_name, fetch_func in fetch_functions.items():
        try:
            results[feed_name] = fetch_func()
        except Exception as exc:
            logger.exception("Unexpected failure in feed '%s': %s", feed_name, exc)
            results[feed_name] = []

    total = sum(len(items) for items in results.values())
    failed = [name for name, items in results.items() if not items]
    logger.info("All feeds complete: %d raw records", total)
    if failed:
        logger.warning("Feeds with zero records: %s", ", ".join(failed))
    return results
