# VulnAgent — Claude Code Project Instructions

## What This Is
AI-powered vulnerability scanner with Excel reporting. Scans local/network targets, looks up CVEs from NIST NVD, and uses Claude AI to generate contextual summaries and remediation plans. Output is a scheduled Excel report.

## Quick Commands
```bash
# Run a one-off scan
python agent.py --scan

# Run with custom target
python agent.py --scan --target 192.168.1.1

# Generate report from last scan
python agent.py --report

# Start scheduler (runs on configured interval)
python agent.py --schedule

# Test individual modules
python scanner.py        # Test port scanner
python cve_lookup.py     # Test NVD API
python ai_analyst.py     # Test Claude AI analysis
python reporter.py       # Test Excel generation
```

## Architecture (Don't Re-Explore)
Read `ARCHITECTURE.md` for full system design. Key points:
- `agent.py` = main orchestrator (start here)
- `scanner.py` = pure scanning, no AI; includes PowerShell software inventory
- `cve_lookup.py` = NIST NVD REST API v2; platform + version + CPE filtering
- `ai_analyst.py` = Groq llama-3.3-70b-versatile for summaries (free tier: 500 req/day)
- `reporter.py` = openpyxl Excel with 13 fields (see ARCHITECTURE.md for schema)
- `scheduler.py` = `schedule` library, reads interval from `config.py`
- `validation.py` = startup config/API key validation (runs before every scan)
- `trend.py` = SQLite trend tracking; logs each scan, queries 30-day history
- `STATE.md` = updated after each scan with last-run metadata
- `tests/` = unit tests for version matching and trend tracking

## Config Reference (config.py)
```python
TARGETS = ["127.0.0.1"]          # List of IPs to scan
SCAN_PORTS = range(1, 1025)      # Port range
SCHEDULE_INTERVAL = "daily"       # daily | weekly | "12h" | "30m"
SCHEDULE_TIME = "09:00"           # 24h time for daily/weekly
REPORTS_DIR = Path("./reports")   # Excel output folder (Path object)
MAX_CVE_AGE_DAYS = 730            # Ignore CVEs older than this (2 years)
REMEDIATION_SLA = {               # Days to fix by CVSS band
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180
}
```

## Excel Report Schema (13 Fields)
`ID, IP_Address, Operating_System, DNS_Name, Status, CVE_Name, CVSS_Score, Remediation_Target, Summary, Solution, Public_Exploit, Vulnerability, Reference`

## Key Patterns
- `scanner.py` uses Python `socket` only — no nmap install required
- OS detection via PowerShell `Get-ComputerInfo` for local, TTL analysis for remote
- NVD API base: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Rate limit: 5 req/30s without NVD API key, 50 req/30s with key
- AI model: Groq `llama-3.3-70b-versatile` (free tier: 500 req/day)
- All scan results cached to `./cache/` as JSON before Excel generation
- State persisted in `STATE.md` after every scan

## Gotchas
- Windows: PowerShell must be available for OS detection (`subprocess` calls `powershell.exe`)
- NVD API returns paginated results; `cve_lookup.py` handles pagination automatically
- `schedule` library is single-threaded; long scans block next run — intentional
- Excel file is locked while open in Excel; reporter writes to temp then renames
- `GROQ_API_KEY` must be in `.env` or environment — never hardcode
- Without `NVD_API_KEY` scans take ~2-3 min (6.5s/request rate limit); with key ~12s

## Environment Variables
```
GROQ_API_KEY=gsk_...              # Required for AI analysis (https://console.groq.com)
NVD_API_KEY=...                   # Optional but recommended — reduces scan time from ~2min to ~12s
```

## Do NOT
- Re-read all source files to understand the system (use ARCHITECTURE.md)
- Re-implement port scanning with nmap (socket is intentional — portable)
- Change the Excel schema without updating ARCHITECTURE.md
- Use a non-free Groq model for bulk CVE summarization (hit rate limits fast)
