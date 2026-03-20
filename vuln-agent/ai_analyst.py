"""
ai_analyst.py — Groq AI Vulnerability Analyst
Generates plain-English summaries, remediation steps, and priority dates.
Uses llama-3.3-70b-versatile via Groq (free tier: 500 req/day, no credit card required).
"""

import logging
from dataclasses import dataclass
from datetime import date, timedelta

from groq import Groq

import config
from scanner import ScanResult
from cve_lookup import CVERecord

logger = logging.getLogger(__name__)

_client: Groq | None = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        import os
        api_key = os.getenv("GROQ_API_KEY") or config.GROQ_API_KEY
        if not api_key:
            raise ValueError(
                "GROQ_API_KEY not set. Add it to .env or set as environment variable."
            )
        _client = Groq(api_key=api_key)
    return _client


@dataclass
class AIAnalysis:
    summary: str               # 2-3 sentence plain-English explanation
    solution: str              # Step-by-step remediation
    remediation_target: date   # Deadline calculated from CVSS + SLA
    confidence: str            # high / medium / low


def _calculate_remediation_date(cvss_severity: str) -> date:
    """Calculate remediation deadline based on CVSS severity and SLA config."""
    days = config.REMEDIATION_SLA.get(cvss_severity.lower(), 90)
    return date.today() + timedelta(days=days)


def _build_prompt(scan: ScanResult, cve: CVERecord) -> str:
    return f"""You are a cybersecurity analyst writing a vulnerability report for a {scan.os} system.

Vulnerability Details:
- CVE ID: {cve.cve_id}
- CVSS Score: {cve.cvss_score} ({cve.cvss_severity.upper()})
- Affected Port/Service: {cve.related_port}/{cve.related_service}
- Target System: {scan.os} ({scan.ip})
- Public Exploit Available: {cve.public_exploit}
- Description: {cve.description}

Write a concise vulnerability report with exactly two sections:

SUMMARY:
Write 2-3 sentences explaining what this vulnerability is, why it's dangerous, and what an attacker could do if they exploit it. Use plain English that a non-technical IT manager can understand.

SOLUTION:
Write 3-5 numbered steps to remediate this vulnerability. Be specific and actionable. Include patch commands or configuration changes where possible."""


def analyse_vulnerability(scan: ScanResult, cve: CVERecord) -> AIAnalysis:
    """Use Groq AI to generate a human-readable analysis of a CVE."""
    client = _get_client()
    remediation_date = _calculate_remediation_date(cve.cvss_severity)

    try:
        response = client.chat.completions.create(
            model=config.AI_MODEL,
            max_tokens=config.AI_MAX_TOKENS,
            messages=[{"role": "user", "content": _build_prompt(scan, cve)}]
        )

        text = response.choices[0].message.content if response.choices else ""

        # Parse the two sections
        summary = ""
        solution = ""

        if "SUMMARY:" in text and "SOLUTION:" in text:
            parts = text.split("SOLUTION:")
            summary = parts[0].replace("SUMMARY:", "").strip()
            solution = parts[1].strip()
        elif text:
            # Fallback: use the whole response as summary
            summary = text[:300]
            solution = "See CVE reference for remediation steps."

        return AIAnalysis(
            summary=summary,
            solution=solution,
            remediation_target=remediation_date,
            confidence="high" if cve.cvss_score >= 7.0 else "medium",
        )

    except Exception as e:
        logger.error(f"Groq API error for {cve.cve_id}: {e}")
        return AIAnalysis(
            summary=f"AI analysis unavailable. {cve.description[:200]}",
            solution="Refer to NVD reference links for remediation guidance.",
            remediation_target=remediation_date,
            confidence="low",
        )


def analyse_all(scan: ScanResult, cves: list[CVERecord]) -> list[tuple[CVERecord, AIAnalysis]]:
    """
    Run AI analysis on all CVEs for a scan result.
    Returns list of (CVERecord, AIAnalysis) tuples.
    """
    results = []
    for i, cve in enumerate(cves):
        logger.info(f"  [{i+1}/{len(cves)}] Analysing {cve.cve_id} (CVSS {cve.cvss_score})...")
        analysis = analyse_vulnerability(scan, cve)
        results.append((cve, analysis))
    return results


if __name__ == "__main__":
    import os
    from pathlib import Path
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Minimal test
    from scanner import ScanResult, PortInfo
    from cve_lookup import CVERecord
    from datetime import datetime

    test_scan = ScanResult(ip="127.0.0.1", dns_name="localhost", os="Windows 11 Pro")
    test_cve = CVERecord(
        cve_id="CVE-2024-0001",
        description="A remote code execution vulnerability in Microsoft RDP allows unauthenticated attackers to execute arbitrary code.",
        cvss_score=9.8,
        cvss_severity="critical",
        cvss_version="3.1",
        public_exploit=True,
        related_port=3389,
        related_service="rdp",
        published=datetime.now(),
    )

    print("Testing AI analysis...\n")
    analysis = analyse_vulnerability(test_scan, test_cve)
    print(f"SUMMARY:\n{analysis.summary}\n")
    print(f"SOLUTION:\n{analysis.solution}\n")
    print(f"Remediation by: {analysis.remediation_target}")
