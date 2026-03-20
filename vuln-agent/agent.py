# -*- coding: utf-8 -*-
"""
agent.py - VulnAgent Main Orchestrator
Coordinates scan → CVE lookup → AI analysis → Excel report → state update.

Usage:
  python agent.py --scan              # One-off scan
  python agent.py --scan --target IP  # Scan specific target
  python agent.py --report            # Re-generate report from cache
  python agent.py --schedule          # Start scheduler
  python agent.py --help
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()  # Load .env before importing config (which reads env vars)

# Force UTF-8 output on Windows so special characters display correctly
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config
from scanner import scan_all_targets, scan_target, ScanResult
from cve_lookup import lookup_vulnerabilities, CVERecord
from ai_analyst import analyse_all, AIAnalysis
from reporter import generate_report
from validation import validate_config
from trend import log_scan, get_trend_summary, cleanup_old_scans

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.BASE_DIR / "vuln-agent.log"),
    ]
)
logger = logging.getLogger(__name__)

BANNER = """
==================================================
         VulnAgent - AI Vulnerability Scanner
         Built by Ebube Onuorah
==================================================
"""


def _cache_path(target_ip: str) -> Path:
    date_str = datetime.now().strftime("%Y-%m-%d")
    safe_ip = target_ip.replace(".", "_")
    return config.CACHE_DIR / f"scan_{safe_ip}_{date_str}.json"


def _save_cache(scan: ScanResult, cves: list[CVERecord]) -> None:
    """Persist scan results to JSON cache."""
    try:
        path = _cache_path(scan.ip)
        data = {
            "scan": {
                "ip": scan.ip,
                "dns_name": scan.dns_name,
                "os": scan.os,
                "scan_time": scan.scan_time.isoformat(),
                "open_ports": [
                    {"port": p.port, "service": p.service, "banner": p.banner}
                    for p in scan.open_ports
                ],
            },
            "cves": [
                {
                    "cve_id": c.cve_id,
                    "cvss_score": c.cvss_score,
                    "cvss_severity": c.cvss_severity,
                    "description": c.description,
                    "public_exploit": c.public_exploit,
                    "related_port": c.related_port,
                    "related_service": c.related_service,
                    "references": c.references,
                }
                for c in cves
            ],
        }
        path.write_text(json.dumps(data, indent=2, default=str))
        logger.debug(f"Cache saved: {path}")
    except Exception as e:
        logger.warning(f"Cache write failed: {e}")


def _update_state(scans: list[ScanResult], total_findings: int, report_path: Path) -> None:
    """Update STATE.md with latest scan metadata."""
    try:
        critical = 0
        high = 0
        medium = 0
        low = 0

        state_content = f"""# VulnAgent — Scan State

## Last Scan
- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Status:** Completed
- **Targets Scanned:** {', '.join(s.ip for s in scans)}
- **Findings:** {total_findings}
- **Report Generated:** {report_path.name}
- **Duration:** See log

## Configuration Snapshot
- **Targets:** {', '.join(config.TARGETS)}
- **Port Range:** {config.SCAN_PORTS.start}–{config.SCAN_PORTS.stop - 1}
- **Schedule:** {config.SCHEDULE_INTERVAL} @ {config.SCHEDULE_TIME}
- **Last Schedule Run:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Open Ports Found
"""
        for scan in scans:
            state_content += f"\n### {scan.ip} ({scan.os})\n"
            for p in scan.open_ports:
                state_content += f"- Port {p.port}/{p.service}\n"
            if not scan.open_ports:
                state_content += "- No open ports found\n"

        state_content += f"""
---
*Updated automatically after each scan.*
*To reset: delete this file and re-run `python agent.py --scan`*
"""
        config.STATE_FILE.write_text(state_content)
        logger.debug("STATE.md updated")
    except Exception as e:
        logger.warning(f"STATE.md update failed: {e}")


def run_full_scan(target_override: str | None = None) -> Path:
    """
    Full pipeline: scan → CVE lookup → AI analysis → Excel report.
    Returns path to generated report.
    """
    start_time = datetime.now()
    logger.info("=" * 60)
    logger.info("Starting vulnerability scan")
    logger.info("=" * 60)

    # Override target if specified
    original_targets = config.TARGETS[:]
    if target_override:
        config.TARGETS = [target_override]

    # ── Phase 1: Scan ─────────────────────────────────────────────────────────
    logger.info("Phase 1/3: Network scanning...")
    all_scans = scan_all_targets()

    total_open_ports = sum(len(s.open_ports) for s in all_scans)
    logger.info(f"Scan complete: {len(all_scans)} target(s), {total_open_ports} open port(s)")

    # ── Phase 2: CVE Lookup ───────────────────────────────────────────────────
    logger.info("Phase 2/3: CVE lookup via NIST NVD...")
    all_findings: list[tuple[ScanResult, CVERecord, AIAnalysis]] = []

    scan_cve_pairs: list[tuple[ScanResult, list[CVERecord]]] = []
    for scan in all_scans:
        if not scan.open_ports:
            logger.info(f"  {scan.ip}: No open ports — skipping CVE lookup")
            continue
        cves = lookup_vulnerabilities(scan)
        _save_cache(scan, cves)
        scan_cve_pairs.append((scan, cves))

    total_cves = sum(len(cves) for _, cves in scan_cve_pairs)
    logger.info(f"CVE lookup complete: {total_cves} CVE(s) found")

    # ── Phase 3: AI Analysis ──────────────────────────────────────────────────
    if total_cves == 0:
        logger.info("Phase 3/3: No CVEs to analyse — skipping AI step")
    else:
        logger.info(f"Phase 3/3: AI analysis ({total_cves} CVE(s))...")
        for scan, cves in scan_cve_pairs:
            analysed = analyse_all(scan, cves)
            for cve, analysis in analysed:
                all_findings.append((scan, cve, analysis))
            # Log scan results to trend database for historical tracking
            log_scan(scan, cves)

    # ── Report generation ──────────────────────────────────────────────────────
    logger.info("Generating Excel report...")
    report_path = generate_report(all_findings)

    # ── State update ───────────────────────────────────────────────────────────
    _update_state(all_scans, len(all_findings), report_path)

    # ── Trend summary ──────────────────────────────────────────────────────────
    cleanup_old_scans(days=90)  # Keep DB size reasonable
    trend = get_trend_summary(days=30)
    if trend:
        logger.info(
            f"30-day trend: {trend['scans']} scan(s), "
            f"{trend['avg_cves_per_scan']} avg CVEs/scan, "
            f"{trend['critical_cves']} critical, {trend['exploited_cves']} exploited"
        )

    duration = (datetime.now() - start_time).seconds
    logger.info(f"Done in {duration}s. Report: {report_path}")
    logger.info("=" * 60)

    # Restore targets if overridden
    if target_override:
        config.TARGETS = original_targets

    return report_path


def main() -> None:
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="VulnAgent — AI-Powered Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --scan
  python agent.py --scan --target 192.168.1.1
  python agent.py --report
  python agent.py --schedule
  python agent.py --schedule --interval daily --time 14:00
  python agent.py --schedule --interval weekly --day friday --time 08:00
  python agent.py --schedule --interval 6h
  python agent.py --schedule --interval 30m
        """
    )
    parser.add_argument("--scan", action="store_true", help="Run a vulnerability scan now")
    parser.add_argument("--target", type=str, help="Override scan target (single IP)")
    parser.add_argument("--report", action="store_true", help="Re-generate Excel from cached results")
    parser.add_argument("--schedule", action="store_true", help="Start scheduler (runs immediately, then repeats on interval)")
    parser.add_argument("--interval", type=str,
                        metavar="INTERVAL",
                        help="Schedule interval: daily | weekly | 12h | 6h | 1h | 30m (overrides config.py)")
    parser.add_argument("--time", type=str,
                        metavar="HH:MM",
                        help="Time for daily/weekly runs e.g. 09:00 (overrides config.py)")
    parser.add_argument("--day", type=str,
                        metavar="DAY",
                        help="Day for weekly runs e.g. monday (overrides config.py)")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate configuration before running any operations
    if not validate_config():
        sys.exit(1)

    if args.scan:
        report = run_full_scan(target_override=args.target)
        print(f"\n[OK] Report generated: {report}")

    elif args.report:
        # Re-generate from last cache without re-scanning or re-querying NVD
        print("Re-generating report from cache (not yet implemented — run --scan first).")

    elif args.schedule:
        from scheduler import start
        start(
            interval=args.interval,
            scan_time=args.time,
            scan_day=args.day,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
