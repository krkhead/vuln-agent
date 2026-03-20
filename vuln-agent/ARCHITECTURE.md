# VulnAgent — System Architecture

## Why Not Nessus
| Dimension | Nessus | VulnAgent |
|-----------|--------|-----------|
| Cost | $3,990+/year | Free |
| Source | Closed binary | Open Python |
| AI Analysis | None | Claude AI contextual summaries |
| Learning value | Zero | Every module you built |
| Customization | Limited | Full control |
| Remediation | Generic | AI-prioritized with SLA dates |
| Export | PDF/CSV | Custom Excel with your schema |
| Scheduler | Manual or agent install | Built-in Python `schedule` |

## Data Flow
```
config.py (targets, schedule)
       │
       ▼
  agent.py  ──────────────────────────────────────┐
  (orchestrator)                                    │
       │                                            │
       ├──► scanner.py          ──► raw_findings[]  │
       │    (socket port scan,                      │
       │     PowerShell OS detect,                  │
       │     DNS reverse lookup)                    │
       │                                            │
       ├──► cve_lookup.py       ──► cve_data[]      │
       │    (NIST NVD API v2,                       │
       │     maps service/port → CVE list,          │
       │     fetches CVSS, public exploit flag)     │
       │                                            │
       ├──► ai_analyst.py       ──► ai_output[]     │
       │    (Claude claude-haiku-4-5,                      │
       │     generates summary, solution,           │
       │     remediation target date)               │
       │                                            │
       ├──► reporter.py         ──► .xlsx file      │
       │    (merges all data,                       │
       │     writes Excel report)                   │
       │                                            │
       └──► STATE.md updated                        │
                                                    │
  scheduler.py ──────────────────────────────────►─┘
  (wraps agent.py on interval)
```

## Module Contracts

### scanner.py
**Input:** `target: str` (IP or hostname), `ports: range`
**Output:** `ScanResult` dataclass
```python
@dataclass
class ScanResult:
    ip: str
    dns_name: str        # reverse DNS, "" if not found
    os: str              # OS string or "Unknown"
    open_ports: list[PortInfo]

@dataclass
class PortInfo:
    port: int
    service: str         # "http", "ssh", "ftp", etc.
    banner: str          # grabbed banner if available
    state: str           # "open"
```

### cve_lookup.py
**Input:** `service: str`, `port: int`, `os: str`
**Output:** `list[CVERecord]`
```python
@dataclass
class CVERecord:
    cve_id: str           # "CVE-2024-1234"
    description: str      # raw NVD description
    cvss_score: float     # 0.0-10.0
    cvss_severity: str    # critical/high/medium/low
    public_exploit: bool  # from NVD exploitability data
    references: list[str] # NVD URLs
    published: datetime
```

### ai_analyst.py
**Input:** `ScanResult`, `CVERecord`
**Output:** `AIAnalysis`
```python
@dataclass
class AIAnalysis:
    summary: str           # 2-3 sentence plain-English explanation
    solution: str          # step-by-step remediation
    remediation_target: date  # calculated from CVSS + SLA config
```

### reporter.py
**Input:** `list[VulnRow]` (merged data)
**Output:** `./reports/vuln_report_YYYY-MM-DD.xlsx`

**Excel Schema (13 columns):**
| Col | Field | Source |
|-----|-------|--------|
| A | ID | UUID4 short |
| B | IP_Address | scanner |
| C | Operating_System | scanner (PowerShell/TTL) |
| D | DNS_Name | scanner (reverse DNS) |
| E | Status | "Open" default, user-editable |
| F | CVE_Name | NVD |
| G | CVSS_Score | NVD |
| H | Remediation_Target | AI (CVSS × SLA config) |
| I | Summary | Claude AI |
| J | Solution | Claude AI + NVD |
| K | Public_Exploit | NVD boolean → "Yes"/"No" |
| L | Vulnerability | port/service description |
| M | Reference | NVD URL |

### scheduler.py
**Input:** `config.SCHEDULE_INTERVAL`, `config.SCHEDULE_TIME`
**Behavior:** Wraps `agent.py` run on interval using `schedule` library
**Modes:** `daily@HH:MM`, `weekly@DAY@HH:MM`, `every N hours`, `every N minutes`

## Directory Layout
```
vuln-agent/
├── CLAUDE.md              # Claude Code instructions
├── ARCHITECTURE.md        # This file
├── STATE.md               # Scan state (auto-updated)
├── .env                   # ANTHROPIC_API_KEY, NVD_API_KEY
├── .env.example           # Template (committed)
├── .gitignore
├── requirements.txt
├── config.py              # User configuration
├── agent.py               # Orchestrator + CLI entry point
├── scanner.py             # Network scanning
├── cve_lookup.py          # NIST NVD API client
├── ai_analyst.py          # Claude AI integration
├── reporter.py            # Excel report generator
├── scheduler.py           # Interval scheduling
├── cache/                 # JSON cache of scan results
│   └── scan_YYYY-MM-DD.json
└── reports/               # Generated Excel files
    └── vuln_report_YYYY-MM-DD.xlsx
```

## API References
- **NIST NVD API v2:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - Rate: 5 req/30s (no key), 50 req/30s (with key)
  - Filter by keyword: `?keywordSearch=apache`
  - No auth required for basic use
- **Anthropic API:** `claude-haiku-4-5` model, ~$1/1M tokens
  - Used for: summary, solution, remediation date
  - Prompt: system + one CVERecord per call (batch to save tokens)

## Security Notes
- Agent scans only targets listed in `config.TARGETS`
- Default target is `127.0.0.1` (localhost only)
- No credentials stored — `.env` excluded from git
- Socket scanning is non-intrusive (SYN equivalent via connect())
- All output stays local — no external reporting endpoints
