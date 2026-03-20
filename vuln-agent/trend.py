"""
trend.py - Trend tracking with SQLite
Stores historical scan results to show remediation progress over time.
"""

import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import config
from cve_lookup import CVERecord
from scanner import ScanResult

logger = logging.getLogger(__name__)

DB_PATH = config.BASE_DIR / "vuln-agent.db"


def init_db() -> None:
    """Create database schema if it doesn't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                scan_date TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                total_cves INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                exploited_count INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_history (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                cvss_score REAL,
                cvss_severity TEXT,
                public_exploit BOOLEAN,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
            """
        )
        conn.commit()
        logger.debug("Database schema initialized")


def log_scan(scan: ScanResult, cves: list[CVERecord]) -> None:
    """
    Log a completed scan to the database for trend tracking.
    """
    try:
        init_db()

        critical = sum(1 for c in cves if c.cvss_severity == "critical")
        high = sum(1 for c in cves if c.cvss_severity == "high")
        exploited = sum(1 for c in cves if c.public_exploit)

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (scan_date, target_ip, total_cves, critical_count, high_count, exploited_count)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().isoformat(),
                    scan.ip,
                    len(cves),
                    critical,
                    high,
                    exploited,
                ),
            )
            scan_id = cursor.lastrowid

            # Log individual CVEs
            for cve in cves:
                cursor.execute(
                    """
                    INSERT INTO cve_history (scan_id, cve_id, cvss_score, cvss_severity, public_exploit)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (scan_id, cve.cve_id, cve.cvss_score, cve.cvss_severity, cve.public_exploit),
                )
            conn.commit()
            logger.debug(f"Logged scan {scan_id} for {scan.ip}: {len(cves)} CVEs")
    except Exception as e:
        logger.warning(f"Trend logging failed: {e}")


def get_trend_summary(days: int = 30) -> dict:
    """
    Get summary of CVE trends over the last N days.
    Returns dict with: total_scans, avg_cves, critical_trend, exploited_trend
    """
    try:
        init_db()

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            # Overall stats
            cursor.execute(
                """
                SELECT COUNT(*) as scans, AVG(total_cves) as avg_cves
                FROM scans
                WHERE scan_date >= ?
                """,
                (cutoff,),
            )
            scans, avg_cves = cursor.fetchone()

            # Critical trend (count over time)
            cursor.execute(
                """
                SELECT COUNT(*) as critical_cves
                FROM cve_history
                WHERE cvss_severity = 'critical'
                AND scan_id IN (SELECT id FROM scans WHERE scan_date >= ?)
                """,
                (cutoff,),
            )
            critical_cves = cursor.fetchone()[0]

            # Exploited trend
            cursor.execute(
                """
                SELECT COUNT(*) as exploited_cves
                FROM cve_history
                WHERE public_exploit = 1
                AND scan_id IN (SELECT id FROM scans WHERE scan_date >= ?)
                """,
                (cutoff,),
            )
            exploited_cves = cursor.fetchone()[0]

            return {
                "period_days": days,
                "scans": scans,
                "avg_cves_per_scan": round(avg_cves or 0, 1),
                "critical_cves": critical_cves,
                "exploited_cves": exploited_cves,
            }
    except Exception as e:
        logger.warning(f"Trend query failed: {e}")
        return {}


def cleanup_old_scans(days: int = 90) -> None:
    """Delete scan records older than N days to keep DB size manageable."""
    try:
        init_db()

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cve_history WHERE scan_id IN (SELECT id FROM scans WHERE scan_date < ?)", (cutoff,))
            cursor.execute("DELETE FROM scans WHERE scan_date < ?", (cutoff,))
            conn.commit()
            logger.debug(f"Cleaned up scans older than {days} days")
    except Exception as e:
        logger.warning(f"Cleanup failed: {e}")
