"""
test_trend.py - Unit tests for trend tracking
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import ScanResult, SoftwareInfo
from cve_lookup import CVERecord
from trend import init_db, log_scan, get_trend_summary
from datetime import datetime


def test_trend_db_init():
    """Test database initialization."""
    try:
        init_db()
        print("[PASS] Database initialization successful")
    except Exception as e:
        print(f"[FAIL] Database init failed: {e}")
        raise


def test_log_and_query():
    """Test logging scan and querying trends."""
    # Create a mock scan
    scan = ScanResult(
        ip="127.0.0.1",
        dns_name="localhost",
        os="Windows 11",
        installed_software=[
            SoftwareInfo(name="Test App", version="1.0.0", publisher="Test Publisher"),
        ],
    )

    # Create mock CVEs
    cves = [
        CVERecord(
            cve_id="CVE-2024-0001",
            description="Test critical CVE",
            cvss_score=9.8,
            cvss_severity="critical",
            cvss_version="3.1",
            public_exploit=True,
            published=datetime.now(),
        ),
        CVERecord(
            cve_id="CVE-2024-0002",
            description="Test high CVE",
            cvss_score=7.5,
            cvss_severity="high",
            cvss_version="3.1",
            public_exploit=False,
            published=datetime.now(),
        ),
    ]

    try:
        # Log the scan
        log_scan(scan, cves)
        print("[PASS] Scan logging successful")

        # Query trends
        trend = get_trend_summary(days=1)
        assert trend["scans"] >= 1, "Should have at least one scan"
        assert trend["critical_cves"] >= 1, "Should have at least one critical CVE"
        assert trend["exploited_cves"] >= 1, "Should have at least one exploited CVE"
        print(f"[PASS] Trend query successful: {trend}")
    except Exception as e:
        print(f"[FAIL] Trend logging/query failed: {e}")
        raise


if __name__ == "__main__":
    test_trend_db_init()
    test_log_and_query()
    print("\n[PASS] All trend tracking tests passed!")
