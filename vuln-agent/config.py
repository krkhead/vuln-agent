"""
VulnAgent Configuration
Edit this file to customize scan targets, scheduling, and thresholds.
"""

import os
from pathlib import Path

# ── Scan Targets ──────────────────────────────────────────────────────────────
TARGETS: list[str] = [
    "127.0.0.1",          # Localhost (your own machine)
    # "192.168.1.1",      # Uncomment to add router/gateway
    # "192.168.1.0/24",   # Uncomment to scan entire subnet
]

SCAN_PORTS: range = range(1, 1025)   # Common ports 1-1024
BANNER_GRAB_TIMEOUT: float = 1.0     # Seconds to wait for service banner
CONNECT_TIMEOUT: float = 0.3         # Seconds for TCP connect attempt (0.3 = fast for local; increase for remote)

# ── Scheduling ────────────────────────────────────────────────────────────────
# Options: "daily", "weekly", "12h", "6h", "30m"
SCHEDULE_INTERVAL: str = "daily"
SCHEDULE_TIME: str = "09:00"         # 24h format, used for daily/weekly
SCHEDULE_DAY: str = "monday"         # Used for weekly only

# ── Remediation SLA (days to fix by CVSS band) ────────────────────────────────
REMEDIATION_SLA: dict[str, int] = {
    "critical": 7,    # CVSS 9.0-10.0
    "high":     30,   # CVSS 7.0-8.9
    "medium":   90,   # CVSS 4.0-6.9
    "low":      180,  # CVSS 0.1-3.9
}

# ── NVD API ───────────────────────────────────────────────────────────────────
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")   # Optional — increases rate limit
NVD_RESULTS_PER_PAGE: int = 2000     # Fetch max so age filter has enough to work with
MAX_CVES_PER_SERVICE: int = 5        # Max CVEs to return per open port/service
MAX_CVE_AGE_DAYS: int = 730          # Skip CVEs older than this (2 years)
MAX_SOFTWARE_SEARCHES: int = 15      # Max installed-software NVD searches per scan (rate-limit budget)

# ── Groq AI ───────────────────────────────────────────────────────────────────
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
AI_MODEL: str = "llama-3.3-70b-versatile"   # Free tier: 500 req/day
AI_MAX_TOKENS: int = 512               # Per CVE analysis

# ── Output ────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).parent
REPORTS_DIR: Path = BASE_DIR / "reports"
CACHE_DIR: Path = BASE_DIR / "cache"
STATE_FILE: Path = BASE_DIR / "STATE.md"

REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)

# ── Excel Styling ─────────────────────────────────────────────────────────────
EXCEL_HEADER_COLOR: str = "1F3864"   # Dark navy
EXCEL_CRITICAL_COLOR: str = "FF0000" # Red
EXCEL_HIGH_COLOR: str = "FF6600"     # Orange
EXCEL_MEDIUM_COLOR: str = "FFD700"   # Yellow
EXCEL_LOW_COLOR: str = "00B050"      # Green
