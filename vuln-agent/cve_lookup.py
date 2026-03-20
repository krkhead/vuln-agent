"""
cve_lookup.py - NIST NVD API v2 Client
Maps open ports/services to known CVEs. No API key required for basic use.
API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import requests

import config
from scanner import ScanResult, PortInfo

logger = logging.getLogger(__name__)

# How long to sleep between NVD requests (rate limiting)
# No key: 5 req/30s -> ~6s gap. With key: 50 req/30s -> ~0.6s gap
_RATE_SLEEP = 0.7 if config.NVD_API_KEY else 6.5


@dataclass
class CVERecord:
    cve_id: str
    description: str
    cvss_score: float
    cvss_severity: str          # critical / high / medium / low / none
    cvss_version: str           # "3.1", "3.0", "2.0"
    public_exploit: bool
    references: list[str] = field(default_factory=list)
    published: datetime = field(default_factory=datetime.now)
    # Back-reference
    related_port: int = 0
    related_service: str = ""


# ── Platform-specific search keywords per port ────────────────────────────────
# Using precise terms returns far fewer false positives than generic service names.
# "smb" returns Linux Samba CVEs; "windows smb" returns Windows-specific ones.

_WINDOWS_PORT_KEYWORDS: dict[int, str] = {
    21:   "windows ftp",
    22:   "openssh",
    25:   "windows smtp",
    53:   "windows dns",
    80:   "microsoft iis",
    110:  "windows pop3",
    135:  "windows rpc",
    139:  "windows netbios",
    143:  "windows imap",
    443:  "microsoft iis",
    445:  "windows smb",
    587:  "windows smtp",
    1433: "microsoft sql server",
    1521: "oracle database windows",
    3306: "mysql windows",
    3389: "windows remote desktop",
    5432: "postgresql windows",
    5900: "vnc windows",
    6379: "redis windows",
    8080: "windows iis http",
    8443: "windows iis https",
    27017: "mongodb windows",
}

_LINUX_PORT_KEYWORDS: dict[int, str] = {
    22:   "openssh",
    25:   "postfix sendmail exim",
    53:   "bind dns",
    80:   "apache nginx",
    110:  "dovecot pop3",
    143:  "dovecot imap",
    443:  "apache nginx ssl",
    445:  "samba smb",
    3306: "mysql mariadb",
    5432: "postgresql",
    6379: "redis",
    8080: "tomcat apache",
    27017: "mongodb",
}

# Generic fallback keywords for unknown platforms
_GENERIC_PORT_KEYWORDS: dict[int, str] = {
    21:   "ftp",
    22:   "openssh",
    25:   "smtp",
    53:   "dns",
    80:   "http web server",
    110:  "pop3",
    135:  "rpc",
    139:  "netbios",
    143:  "imap",
    443:  "https ssl tls",
    445:  "smb cifs",
    1433: "sql server mssql",
    3306: "mysql",
    3389: "rdp remote desktop",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http proxy",
    27017: "mongodb",
}


def _detect_platform(os_str: str) -> str:
    """Convert scanner OS string to a platform identifier for CVE filtering."""
    os_lower = os_str.lower()
    if "windows" in os_lower:
        return "windows"
    if any(k in os_lower for k in ("linux", "ubuntu", "debian", "centos", "red hat", "fedora")):
        return "linux"
    if any(k in os_lower for k in ("mac", "darwin", "macos")):
        return "macos"
    return "unknown"


def _search_keyword_for_port(port: int, service: str, platform: str) -> str:
    """Return the best NVD search keyword for a given port + platform."""
    if platform == "windows":
        keyword = _WINDOWS_PORT_KEYWORDS.get(port)
    elif platform == "linux":
        keyword = _LINUX_PORT_KEYWORDS.get(port)
    else:
        keyword = _GENERIC_PORT_KEYWORDS.get(port)

    # Fall back to service name if no mapping exists for this port
    return keyword or service


def _cpe_matches_platform(item: dict, platform: str) -> bool:
    """
    Check if a CVE's CPE configurations match the target platform.
    Uses the NVD 'configurations' block which contains the exact CPE strings
    for every affected product/OS/version combination.

    Returns True  -> CVE applies to this platform (include it)
    Returns False -> CVE is for a different platform (skip it)
    Returns True  -> no CPE data in response (can't determine, include it safely)
    """
    if platform == "unknown":
        return True  # Can't filter without platform knowledge

    configurations = item.get("configurations", [])
    if not configurations:
        # NVD didn't include CPE configuration data for this CVE.
        # Include it rather than silently dropping valid findings.
        return True

    # Collect every CPE string from all configuration nodes
    all_cpes: list[str] = []
    for cfg in configurations:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "").lower()
                if cpe:
                    all_cpes.append(cpe)

    if not all_cpes:
        return True  # No CPE match strings found — include it

    if platform == "windows":
        # Require Microsoft as vendor — avoids false positives from third-party software
        # whose CPEs include "windows" only as a target-platform field
        # e.g. cpe:2.3:a:esri:arcgis_server:*:*:*:*:*:windows:*:* would wrongly pass
        # the old check but correctly fails now since :microsoft: is not the vendor.
        return any(":microsoft:" in cpe for cpe in all_cpes)

    if platform == "linux":
        linux_vendors = (":linux:", ":canonical:", ":debian:", ":redhat:",
                         ":centos:", ":fedoraproject:", ":suse:")
        return any(any(v in cpe for v in linux_vendors) for cpe in all_cpes)

    if platform == "macos":
        return any(":apple:" in cpe for cpe in all_cpes)

    return True  # Unknown platform — include all


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0:
        return "low"
    return "none"


def _extract_cvss(metrics: dict) -> tuple[float, str, str]:
    """Extract CVSS score, severity and version from NVD metrics block."""
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version_key, [])
        if entries:
            entry = entries[0]
            data = entry.get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            severity = data.get("baseSeverity", _severity_from_score(score)).lower()
            ver = data.get("version", version_key[-3:].replace("V", ""))
            return score, severity, ver
    return 0.0, "none", "N/A"


def _has_public_exploit(cve_item: dict) -> bool:
    """Check NVD data for known exploitation indicators."""
    # CISA KEV (Known Exploited Vulnerabilities catalog) is the authoritative source.
    # If cisaExploitAdd is present, the CVE is confirmed actively exploited in the wild.
    if cve_item.get("cisaExploitAdd"):
        return True

    descriptions = cve_item.get("descriptions", [])
    refs = cve_item.get("references", [])

    exploit_keywords = ("exploit", "actively exploited", "proof-of-concept", "poc", "metasploit")
    for ref in refs:
        url = ref.get("url", "").lower()
        tags = [t.lower() for t in ref.get("tags", [])]
        if any(k in url or k in " ".join(tags) for k in exploit_keywords):
            return True

    for desc in descriptions:
        if any(k in desc.get("value", "").lower() for k in exploit_keywords):
            return True

    return False


def _version_matches_range(
    installed_version: str,
    match_data: dict,
) -> bool:
    """
    Check if an installed version falls within a CVE's vulnerable version range.
    Returns True if the installed version is vulnerable (within range).

    Version matching uses basic semantic versioning comparison.
    Returns True if no version constraints found (can't determine, assume vulnerable).
    """
    if not installed_version or not installed_version.strip():
        return True  # No version info — assume vulnerable

    try:
        installed = _parse_version(installed_version)
    except Exception:
        return True  # Can't parse installed version — assume vulnerable

    # Extract version constraints from CPE match
    v_start_inc = match_data.get("versionStartIncluding")
    v_start_exc = match_data.get("versionStartExcluding")
    v_end_inc = match_data.get("versionEndIncluding")
    v_end_exc = match_data.get("versionEndExcluding")

    # If no version constraints, CVE affects all versions
    if not any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
        return True

    try:
        # Check lower bound
        if v_start_inc and installed < _parse_version(v_start_inc):
            return False  # Below minimum
        if v_start_exc and installed <= _parse_version(v_start_exc):
            return False  # At or below exclusive minimum

        # Check upper bound
        if v_end_inc and installed > _parse_version(v_end_inc):
            return False  # Above maximum
        if v_end_exc and installed >= _parse_version(v_end_exc):
            return False  # At or above exclusive maximum

        return True  # Within vulnerable range
    except Exception:
        return True  # Can't parse version constraint — assume vulnerable


def _parse_version(version_str: str) -> tuple:
    """Parse semantic version string into comparable tuple.

    Pre-release versions (e.g., 1.2.3-beta) sort before their release (1.2.3),
    matching semantic versioning conventions.
    """
    import re

    version_str = version_str.strip().lower()
    parts = re.split(r'[.-]', version_str)
    result = []
    for part in parts:
        try:
            result.append((0, int(part)))  # (0, number) sorts before (1, string)
        except ValueError:
            result.append((1, part))  # (1, string) sorts after numbers

    # If the version ends with a numeric part (no pre-release suffix), add a
    # sentinel (2, "") that sorts after any pre-release string. This ensures
    # 1.2.3-beta < 1.2.3 per semantic versioning conventions.
    if result and result[-1][0] == 0:
        result.append((2, ""))

    return tuple(result)


def _parse_cve_item(
    item: dict,
    port: int = 0,
    service: str = "",
    platform: str = "unknown",
    installed_version: str = "",
) -> CVERecord | None:
    """Parse a single NVD CVE item into a CVERecord, applying platform filter."""
    try:
        cve_id = item["id"]

        # ── Platform filter (CPE-based) ────────────────────────────────────────
        if not _cpe_matches_platform(item, platform):
            return None  # CVE doesn't apply to this platform

        descriptions = item.get("descriptions", [])
        desc_text = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        metrics = item.get("metrics", {})
        score, severity, version = _extract_cvss(metrics)

        # ── Version filter (if installed_version provided) ─────────────────────────
        if installed_version:
            # Check if installed version is within vulnerable range
            configurations = item.get("configurations", [])
            version_vulnerable = False
            for cfg in configurations:
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if _version_matches_range(installed_version, match):
                            version_vulnerable = True
                            break
                    if version_vulnerable:
                        break
                if version_vulnerable:
                    break
            if not version_vulnerable:
                return None  # Installed version is not vulnerable

    # ── Age filter ────────────────────────────────────────────────────────
        published_str = item.get("published", "")
        published = datetime.now(timezone.utc)
        if published_str:
            try:
                published = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        cutoff = datetime.now(timezone.utc) - timedelta(days=config.MAX_CVE_AGE_DAYS)
        if published < cutoff:
            return None

        refs = [r.get("url", "") for r in item.get("references", []) if r.get("url")]

        return CVERecord(
            cve_id=cve_id,
            description=desc_text,
            cvss_score=score,
            cvss_severity=severity,
            cvss_version=version,
            public_exploit=_has_public_exploit(item),
            references=refs[:5],
            published=published,
            related_port=port,
            related_service=service,
        )
    except (KeyError, TypeError) as e:
        logger.warning(f"Failed to parse CVE item: {e}")
        return None


def fetch_cves_for_keyword(
    keyword: str,
    port: int = 0,
    service: str = "",
    platform: str = "unknown",
    installed_version: str = "",
) -> list[CVERecord]:
    """
    Query NVD for CVEs matching a keyword, filtered to the target platform.
    Uses CPE configuration data in the NVD response to verify the CVE
    actually applies to the detected OS before including it.
    """
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": config.NVD_RESULTS_PER_PAGE,
    }

    try:
        time.sleep(_RATE_SLEEP)
        response = requests.get(
            config.NVD_BASE_URL,
            params=params,
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

        records = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            record = _parse_cve_item(
                cve_data,
                port=port,
                service=service,
                platform=platform,
                installed_version=installed_version,
            )
            if record and record.cvss_score > 0:
                records.append(record)

        records.sort(key=lambda r: r.cvss_score, reverse=True)
        return records[:config.MAX_CVES_PER_SERVICE]

    except requests.RequestException as e:
        logger.error(f"NVD API error for '{keyword}': {e}")
        return []


def lookup_vulnerabilities(scan_result: ScanResult) -> list[CVERecord]:
    """
    Map all open ports/services from a ScanResult to CVE records.
    Uses platform-aware keywords and CPE filtering for accurate results.
    """
    platform = _detect_platform(scan_result.os)
    logger.info(f"  Detected platform: {platform} (OS: {scan_result.os})")

    all_cves: list[CVERecord] = []
    seen_ids: set[str] = set()

    for port_info in scan_result.open_ports:
        keyword = _search_keyword_for_port(port_info.port, port_info.service, platform)

        # Skip ports with no meaningful keyword mapping — "port-NNN" returns NVD garbage
        if not keyword or keyword.startswith("port-"):
            logger.debug(f"No CVE keyword mapping for port {port_info.port} ({port_info.service}), skipping")
            continue

        logger.info(f"Looking up CVEs for port {port_info.port} ({port_info.service}) "
                    f"using keyword: '{keyword}'...")

        cves = fetch_cves_for_keyword(
            keyword,
            port=port_info.port,
            service=port_info.service,
            platform=platform,
        )

        for cve in cves:
            if cve.cve_id not in seen_ids:
                seen_ids.add(cve.cve_id)
                all_cves.append(cve)

    # Search CVEs for software confirmed installed on the host.
    # This replaces the old generic OS keyword search ("windows 11") which returned
    # CVEs for any software that mentions Windows in its CPE — regardless of whether
    # that software is actually present on the machine.
    if scan_result.installed_software:
        # Prioritise Microsoft-published software first (most likely to have
        # Windows platform CVEs), then alphabetically by name.
        software = sorted(
            scan_result.installed_software,
            key=lambda s: (0 if "microsoft" in s.publisher.lower() else 1, s.name.lower()),
        )
        searched = 0
        for sw in software:
            if searched >= config.MAX_SOFTWARE_SEARCHES:
                break
            logger.info(f"Looking up CVEs for installed software: '{sw.name}' (v{sw.version or '?'})")
            # Use platform="unknown" — the software name is specific enough;
            # vendor CPE filtering is not needed here and would drop non-Microsoft apps.
            # Pass installed_version for accurate version-based filtering.
            cves = fetch_cves_for_keyword(
                sw.name,
                platform="unknown",
                installed_version=sw.version,
            )
            searched += 1
            for cve in cves:
                if cve.cve_id not in seen_ids:
                    seen_ids.add(cve.cve_id)
                    all_cves.append(cve)

    # Prioritize by: (1) publicly exploited CVEs first, (2) then CVSS score descending
    # This ensures active exploits are addressed before theoretical vulnerabilities
    all_cves.sort(key=lambda r: (not r.public_exploit, -r.cvss_score))

    # Log prioritization summary
    exploited = sum(1 for c in all_cves if c.public_exploit)
    critical = sum(1 for c in all_cves if c.cvss_severity == "critical")
    logger.info(
        f"Total CVEs found for {scan_result.ip}: {len(all_cves)} "
        f"({exploited} exploited, {critical} critical)"
    )
    return all_cves


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print("Testing platform-aware CVE lookup for Windows SMB (port 445)...\n")
    cves = fetch_cves_for_keyword("windows smb server message block", port=445, service="smb", platform="windows")
    for cve in cves:
        print(f"  {cve.cve_id}  CVSS={cve.cvss_score}  {cve.cvss_severity.upper()}")
        print(f"    {cve.description[:100]}...")
        print(f"    Public exploit: {cve.public_exploit}")
        print()
