"""Normalize provider-specific threat-intelligence records into FAST's schema."""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


def _parse_date(value: Optional[str]) -> str:
    """Return an ISO-8601 UTC timestamp for common provider date formats."""
    if not value:
        return datetime.now(timezone.utc).isoformat()

    value = str(value).strip()
    # Handle already-ISO timestamps, including Z/offset forms, first.
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat()
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    logger.warning("Could not parse date %r; using current UTC time", value)
    return datetime.now(timezone.utc).isoformat()


def normalize_feodo(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for raw in raw_iocs:
        try:
            value = str(raw.get("ip_address") or "").strip()
            if not value:
                logger.warning("Feodo: skipped record without ip_address")
                continue
            tags = [
                str(item)
                for item in (raw.get("botnet"), raw.get("malware"))
                if item
            ]
            seen = _parse_date(raw.get("last_dns_query") or raw.get("last_online"))
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "ip",
                    "source_feed": "feodo",
                    "first_seen": seen,
                    "last_seen": seen,
                    "tags": tags,
                }
            )
        except Exception as exc:
            logger.error("Feodo normalization error (record skipped): %s", exc)
    logger.info("Feodo: %d/%d records normalized", len(normalized), len(raw_iocs))
    return normalized


def normalize_blocklist_de(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize Blocklist.de IP indicators."""
    normalized: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for raw in raw_iocs:
        try:
            value = str(raw.get("ip_address") or "").strip()
            if not value:
                logger.warning("Blocklist.de: skipped record without ip_address")
                continue
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                logger.warning("Blocklist.de: skipped invalid IP %r", value)
                continue
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "ip",
                    "source_feed": "blocklist_de",
                    "first_seen": now,
                    "last_seen": now,
                    "tags": ["blocklist.de"],
                }
            )
        except Exception as exc:
            logger.error("Blocklist.de normalization error (record skipped): %s", exc)
    logger.info("Blocklist.de: %d/%d records normalized", len(normalized), len(raw_iocs))
    return normalized


def normalize_openphish(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize OpenPhish phishing URL indicators."""
    normalized: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for raw in raw_iocs:
        try:
            value = str(raw.get("url") or "").strip()
            if not value:
                logger.warning("OpenPhish: skipped record without url")
                continue
            try:
                parsed = urlsplit(value)
                if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                    raise ValueError("URL must use http(s) and include a hostname")
            except ValueError:
                logger.warning("OpenPhish: skipped invalid URL %r", value)
                continue
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "url",
                    "source_feed": "openphish",
                    "first_seen": now,
                    "last_seen": now,
                    "tags": ["phishing"],
                }
            )
        except Exception as exc:
            logger.error("OpenPhish normalization error (record skipped): %s", exc)
    logger.info("OpenPhish: %d/%d records normalized", len(normalized), len(raw_iocs))
    return normalized


def normalize_spamhaus(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for raw in raw_iocs:
        try:
            value = str(raw.get("cidr") or "").strip()
            if not value:
                logger.warning("Spamhaus: skipped record without cidr")
                continue
            tags = [str(raw["reason"])] if raw.get("reason") else []
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "ip",
                    "source_feed": "spamhaus",
                    "first_seen": now,
                    "last_seen": now,
                    "tags": tags,
                }
            )
        except Exception as exc:
            logger.error("Spamhaus normalization error (record skipped): %s", exc)
    logger.info("Spamhaus: %d/%d records normalized", len(normalized), len(raw_iocs))
    return normalized


def normalize_malwarebazaar(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize MalwareBazaar sample hashes as separate FAST hash IOCs."""
    normalized: List[Dict[str, Any]] = []
    hash_fields = (("md5_hash", 32), ("sha1_hash", 40), ("sha256_hash", 64))
    for raw in raw_iocs:
        try:
            tags: List[str] = []
            raw_tags = raw.get("tags") or []
            if isinstance(raw_tags, str):
                raw_tags = [raw_tags]
            if isinstance(raw_tags, list):
                tags.extend(str(tag).strip() for tag in raw_tags if str(tag).strip())
            for field in ("signature", "file_type", "file_format"):
                value = str(raw.get(field) or "").strip()
                if value and value not in tags:
                    tags.append(value)

            first_seen = _parse_date(raw.get("first_seen"))
            last_seen = _parse_date(raw.get("last_seen") or raw.get("first_seen"))
            for field, expected_length in hash_fields:
                value = str(raw.get(field) or "").strip().lower()
                if len(value) != expected_length or any(ch not in "0123456789abcdef" for ch in value):
                    continue
                normalized.append(
                    {
                        "ioc_value": value,
                        "ioc_type": "hash",
                        "source_feed": "malwarebazaar",
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "tags": tags,
                    }
                )
        except Exception as exc:
            logger.error("MalwareBazaar normalization error (record skipped): %s", exc)
    logger.info("MalwareBazaar: %d/%d hashes normalized", len(normalized), len(raw_iocs))
    return normalized

def normalize_all(raw_feeds: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    functions = {
        "feodo": normalize_feodo,
        "blocklist_de": normalize_blocklist_de,
        "openphish": normalize_openphish,
        "spamhaus": normalize_spamhaus,
        "malwarebazaar": normalize_malwarebazaar,
    }
    all_normalized: List[Dict[str, Any]] = []
    for feed_name, raw_iocs in raw_feeds.items():
        normalizer = functions.get(feed_name)
        if normalizer is None:
            logger.warning("Unknown feed %r; skipped", feed_name)
            continue
        try:
            all_normalized.extend(normalizer(raw_iocs))
        except Exception as exc:
            logger.exception("Normalizer failed for %s: %s", feed_name, exc)
    logger.info("Normalized %d IOCs from %d feeds", len(all_normalized), len(raw_feeds))
    return all_normalized
