# VulnAgent 

An AI-powered vulnerability scanner that scans your network, looks up real CVEs from NIST, and generates a plain-English Excel report with remediation steps — all for free.

> Built by Ebube Onuorah as a cybersecurity portfolio project.

---

## What it does

1. **Scans** your machine or any IP for open ports and services
2. **Looks up CVEs** from NIST's National Vulnerability Database (NVD)
3. **Analyses each vulnerability** with AI — plain English summary + step-by-step fix
4. **Generates an Excel report** with severity colours, remediation deadlines, and reference links

---

## Requirements

- Python 3.10 or higher
- A free [Groq API key](https://console.groq.com) (takes 30 seconds, no credit card)

---

## Quick Start

### 1. Clone and enter the folder
```bash
git clone https://github.com/your-username/vuln-agent.git
cd vuln-agent
```

### 2. Run the setup wizard
```bash
python setup.py
```
This installs dependencies and walks you through creating your `.env` file.

### 3. Run a scan
```bash
python agent.py --scan
```

Your Excel report will be saved to the `reports/` folder.

---

## Usage

```bash
# Scan your local machine (default)
python agent.py --scan

# Scan a specific IP address
python agent.py --scan --target 192.168.1.100

# Run on a schedule (uses interval set in config.py)
python agent.py --schedule

# Show all options
python agent.py --help
```

---

## Configuration

Open `config.py` to customise:

```python
# Which targets to scan
TARGETS = ["127.0.0.1"]          # Add more IPs here

# Port range
SCAN_PORTS = range(1, 1025)      # 1-1024 covers all well-known ports

# How often to run automatically
SCHEDULE_INTERVAL = "daily"       # daily | weekly | 12h | 30m
SCHEDULE_TIME = "09:00"           # Time to run (24h format)

# How fast you need to fix things (SLA in days)
REMEDIATION_SLA = {
    "critical": 7,   # 1 week
    "high":     30,  # 1 month
    "medium":   90,  # 3 months
    "low":      180  # 6 months
}
```

---

## Output

The Excel report includes 13 columns:

| Column | Description |
|--------|-------------|
| CVE_Name | Official CVE identifier (e.g. CVE-2024-1234) |
| CVSS_Score | Severity score 0–10 |
| Summary | AI-generated plain-English explanation |
| Solution | AI-generated step-by-step fix |
| Remediation_Target | Deadline based on your SLA config |
| Public_Exploit | Whether a working exploit is publicly known |
| Reference | Link to the NVD entry |

Rows are colour-coded: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low

---

## How it works

```
Your machine / network IP
        │
        ▼
  Port scan (Python socket)
        │
        ▼
  CVE lookup (NIST NVD API)
        │
        ▼
  AI analysis (Groq LLaMA 3.3)
        │
        ▼
  Excel report (openpyxl)
```

No nmap required. No paid subscriptions. Everything runs locally — scan results and reports never leave your machine.

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GROQ_API_KEY` | ✅ Yes | Free at [console.groq.com](https://console.groq.com) |
| `NVD_API_KEY` | ❌ Optional | Free at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) — increases rate limit from 5 to 50 req/30s |

Copy `.env.example` to `.env` and fill in your keys, or just run `python setup.py`.

---

## Legal

Scan only systems you own or have explicit permission to test. Unauthorised scanning may be illegal in your jurisdiction.
