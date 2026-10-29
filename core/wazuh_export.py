
"""Export validated IPv4 and IPv6 IOCs to the Wazuh CDB list format."""

import ipaddress
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
DEFAULT_CDB_FILENAME = "ioc-ips"


def _extract_ip_value(ioc_value: str) -> Optional[str]:
    """Return a canonical IPv4/CIDR or quoted IPv6 host key."""
    value = str(ioc_value).strip()
    if not value:
        return None

    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)

            # Preserve existing IPv4 CIDR support.
            # Wazuh CDB does not support IPv6 prefix matching.
            if network.version != 4:
                return None

            return str(network)

        address = ipaddress.ip_address(value)

        if address.version == 4:
            return str(address)

        # IPv6 addresses must be quoted because they contain colons.
        # Exact IPv6 host matching only; no IPv6 range matching.
        return f'"{address}"'

    except ValueError:
        return None


def export_to_cdb_list(
    iocs: List[Dict[str, Any]],
    output_dir: str = "sample_output",
    filename: str = DEFAULT_CDB_FILENAME,
    min_confidence: int = 0,
) -> bool:
    """Write unique, validated IPv4/CIDR and IPv6 host records."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        seen = set()
        lines = []
        invalid = 0
        ipv4_count = 0
        ipv6_count = 0

        for ioc in iocs:
            if ioc.get("ioc_type") != "ip":
                continue
            if int(ioc.get("confidence_score", 0) or 0) < min_confidence:
                continue

            value = _extract_ip_value(ioc.get("ioc_value", ""))

            if value is None:
                invalid += 1
                logger.warning(
                    "CDB export: skipped invalid/unsupported IP IOC %r",
                    ioc.get("ioc_value"),
                )
                continue

            if value not in seen:
                seen.add(value)
                lines.append(f"{value}:1")

                if value.startswith('"'):
                    ipv6_count += 1
                else:
                    ipv4_count += 1

        # Deterministic output makes refresh diffs and tests reliable.
        lines.sort()

        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            if lines:
                handle.write("\n")

        if invalid:
            logger.warning(
                "CDB export skipped %d invalid/unsupported IP values",
                invalid,
            )

        if not lines:
            logger.warning("CDB export produced no valid IP entries")

        logger.info(
            "Wazuh CDB export complete: %s "
            "(%d IPv4/CIDR keys, %d IPv6 host keys)",
            filepath,
            ipv4_count,
            ipv6_count,
        )
        return True

    except (OSError, TypeError, ValueError) as exc:
        logger.error("Wazuh CDB export error: %s", exc)
        return False


def get_export_stats(
    iocs: List[Dict[str, Any]],
    min_confidence: int = 0,
) -> Dict[str, int]:
    total = len(iocs)
    ip_type = sum(1 for ioc in iocs if ioc.get("ioc_type") == "ip")

    exported = sum(
        1
        for ioc in iocs
        if ioc.get("ioc_type") == "ip"
        and int(ioc.get("confidence_score", 0) or 0) >= min_confidence
        and _extract_ip_value(ioc.get("ioc_value", "")) is not None
    )

    return {
        "total": total,
        "ip_type": ip_type,
        "exported": exported,
        "filtered_out": ip_type - exported,
    }
