"""
validation.py - Configuration and API key validation
Runs on startup to catch missing/invalid credentials before scanning.
"""

import logging
import sys

import config

logger = logging.getLogger(__name__)


def validate_config() -> bool:
    """
    Validate required configuration and API keys.
    Returns True if all checks pass, False if critical config is missing.
    """
    errors = []
    warnings = []

    # NVD API key — optional but recommended
    if not config.NVD_API_KEY:
        warnings.append(
            "[WARN] NVD_API_KEY not set. Using free tier (5 req/30s). "
            "Set NVD_API_KEY in .env to unlock 50 req/30s."
        )

    # Groq API key — required for AI analysis
    if not config.GROQ_API_KEY:
        errors.append(
            "[ERROR] GROQ_API_KEY not set. AI analysis requires Groq API key. "
            "Set GROQ_API_KEY in .env (https://console.groq.com)"
        )

    # Config sanity checks
    if not config.TARGETS:
        errors.append("[ERROR] TARGETS list is empty in config.py")

    if config.MAX_SOFTWARE_SEARCHES < 1:
        errors.append("[ERROR] MAX_SOFTWARE_SEARCHES must be >= 1")

    if not config.REPORTS_DIR.exists():
        try:
            config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"[ERROR] Cannot create REPORTS_DIR: {e}")

    # Report results
    if errors:
        logger.error("Configuration validation failed:")
        for err in errors:
            logger.error(f"  {err}")
        return False

    if warnings:
        for warn in warnings:
            logger.warning(f"  {warn}")

    logger.info("[OK] Configuration validated")
    return True
