"""
scheduler.py — Interval-based Scan Scheduler
Wraps agent.py's scan function on a configurable schedule.
Uses the `schedule` library (single-threaded, intentional).
"""

import logging
import time
from datetime import datetime

import schedule

import config

logger = logging.getLogger(__name__)


def _run_scan_job() -> None:
    """Job function called by the scheduler on each interval."""
    logger.info(f"[Scheduler] Starting scheduled scan at {datetime.now()}")
    try:
        # Import here to avoid circular imports
        from agent import run_full_scan
        run_full_scan()
        logger.info("[Scheduler] Scan completed successfully.")
    except Exception as e:
        logger.error(f"[Scheduler] Scan failed: {e}", exc_info=True)


def configure_schedule(
    interval: str | None = None,
    scan_time: str | None = None,
    scan_day: str | None = None,
) -> None:
    """
    Configure the schedule. CLI args take priority over config.py values.

    Supported interval values:
      "daily"    → runs every day at scan_time (default: config.SCHEDULE_TIME)
      "weekly"   → runs every scan_day at scan_time
      "12h"      → runs every 12 hours
      "6h"       → runs every 6 hours
      "1h"       → runs every hour
      "30m"      → runs every 30 minutes
    """
    interval  = (interval  or config.SCHEDULE_INTERVAL).lower()
    scan_time = (scan_time or config.SCHEDULE_TIME)
    scan_day  = (scan_day  or config.SCHEDULE_DAY).lower()

    if interval == "daily":
        schedule.every().day.at(scan_time).do(_run_scan_job)
        logger.info(f"Scheduled: daily at {scan_time}")

    elif interval == "weekly":
        getattr(schedule.every(), scan_day).at(scan_time).do(_run_scan_job)
        logger.info(f"Scheduled: every {scan_day} at {scan_time}")

    elif interval.endswith("h"):
        hours = int(interval[:-1])
        schedule.every(hours).hours.do(_run_scan_job)
        logger.info(f"Scheduled: every {hours} hour(s)")

    elif interval.endswith("m"):
        minutes = int(interval[:-1])
        schedule.every(minutes).minutes.do(_run_scan_job)
        logger.info(f"Scheduled: every {minutes} minute(s)")

    else:
        logger.error(f"Unknown schedule interval: '{interval}'. Defaulting to daily at {scan_time}.")
        schedule.every().day.at(scan_time).do(_run_scan_job)


def _prompt_schedule() -> tuple[str, str, str]:
    """
    Interactively ask the user how they want to schedule scans.
    Returns (interval, scan_time, scan_day).
    """
    print("\n=== Schedule Setup ===")
    print("How often should VulnAgent scan?")
    print("  1) Daily")
    print("  2) Weekly")
    print("  3) Every 12 hours")
    print("  4) Every 6 hours")
    print("  5) Every hour")
    print("  6) Every 30 minutes")

    choice_map = {
        "1": "daily",
        "2": "weekly",
        "3": "12h",
        "4": "6h",
        "5": "1h",
        "6": "30m",
    }

    while True:
        choice = input("Enter choice [1-6] (default: 1): ").strip() or "1"
        if choice in choice_map:
            interval = choice_map[choice]
            break
        print("  Invalid choice. Enter a number from 1 to 6.")

    scan_time = config.SCHEDULE_TIME
    scan_day = config.SCHEDULE_DAY

    if interval in ("daily", "weekly"):
        while True:
            raw = input(f"What time should it run? (HH:MM, default: {config.SCHEDULE_TIME}): ").strip()
            if not raw:
                scan_time = config.SCHEDULE_TIME
                break
            # Basic HH:MM validation
            parts = raw.split(":")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                h, m = int(parts[0]), int(parts[1])
                if 0 <= h <= 23 and 0 <= m <= 59:
                    scan_time = f"{h:02d}:{m:02d}"
                    break
            print("  Invalid time. Use HH:MM format e.g. 09:00 or 14:30.")

    if interval == "weekly":
        days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
        print("Which day?")
        for i, d in enumerate(days, 1):
            print(f"  {i}) {d.capitalize()}")
        while True:
            raw = input(f"Enter choice [1-7] (default: {config.SCHEDULE_DAY}): ").strip()
            if not raw:
                scan_day = config.SCHEDULE_DAY
                break
            if raw.isdigit() and 1 <= int(raw) <= 7:
                scan_day = days[int(raw) - 1]
                break
            print("  Invalid choice. Enter a number from 1 to 7.")

    # Summary
    if interval == "daily":
        print(f"\n  Scans will run daily at {scan_time}.")
    elif interval == "weekly":
        print(f"\n  Scans will run every {scan_day.capitalize()} at {scan_time}.")
    else:
        print(f"\n  Scans will run every {interval}.")
    print("  A scan will also run immediately when the scheduler starts.\n")

    return interval, scan_time, scan_day


def start(
    interval: str | None = None,
    scan_time: str | None = None,
    scan_day: str | None = None,
) -> None:
    """Start the scheduler loop. Prompts for preferences if not supplied via CLI args."""

    # If no CLI args provided, ask the user interactively
    if not interval and not scan_time and not scan_day:
        interval, scan_time, scan_day = _prompt_schedule()

    logger.info("VulnAgent Scheduler started. Press Ctrl+C to stop.")
    configure_schedule(interval=interval, scan_time=scan_time, scan_day=scan_day)

    # Show next recurring run time
    next_run = schedule.next_run()
    if next_run:
        logger.info(f"Recurring scan scheduled for: {next_run}")

    # Always run a scan immediately on startup so the user sees it working
    logger.info("[Scheduler] Running initial scan now...")
    _run_scan_job()

    try:
        while True:
            schedule.run_pending()
            time.sleep(30)  # Check every 30 seconds
    except KeyboardInterrupt:
        logger.info("Scheduler stopped by user.")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    start()
