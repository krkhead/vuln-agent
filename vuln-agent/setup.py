# -*- coding: utf-8 -*-
"""
setup.py - VulnAgent Interactive Setup Wizard
Run this once to install dependencies and configure your environment.

Usage:
    python setup.py
"""

import os
import sys
import subprocess
from pathlib import Path

# Force UTF-8 output on Windows so box/tick characters display correctly
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).parent
ENV_FILE = BASE_DIR / ".env"
ENV_EXAMPLE = BASE_DIR / ".env.example"
REQUIREMENTS = BASE_DIR / "requirements.txt"

BANNER = """
==================================================
         VulnAgent - Setup Wizard
         This will take about 60 seconds
==================================================
"""

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def ok(msg):    print(f"  {GREEN}✓{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}⚠{RESET}  {msg}")
def err(msg):   print(f"  {RED}✗{RESET} {msg}")
def info(msg):  print(f"  {CYAN}→{RESET} {msg}")
def step(msg):  print(f"\n{BOLD}{msg}{RESET}")


# ── Step 1: Python version check ──────────────────────────────────────────────

def check_python():
    step("1/4  Checking Python version")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 10):
        err(f"Python 3.10+ required. You have {major}.{minor}.")
        err("Download from https://python.org/downloads")
        sys.exit(1)
    ok(f"Python {major}.{minor} — good to go")


# ── Step 2: Install dependencies ──────────────────────────────────────────────

def install_requirements():
    step("2/4  Installing dependencies")
    info("Running: pip install -r requirements.txt")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS), "--quiet"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        err("pip install failed. Error output:")
        print(result.stderr)
        sys.exit(1)
    ok("All dependencies installed")


# ── Step 3: Configure .env ────────────────────────────────────────────────────

def configure_env():
    step("3/4  Configuring environment")

    existing_key = ""

    # Load existing .env if present
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("GROQ_API_KEY="):
                existing_key = line.split("=", 1)[1].strip()
                break

    if existing_key and existing_key != "gsk_your-key-here":
        ok(f".env already configured (key ending ...{existing_key[-6:]})")
        return

    # Guide the user to get a key
    print()
    print(f"  {BOLD}You need a free Groq API key for AI analysis.{RESET}")
    print(f"  1. Go to {CYAN}https://console.groq.com{RESET}")
    print(f"  2. Sign up (free, no credit card)")
    print(f"  3. Click 'API Keys' → 'Create API Key'")
    print(f"  4. Copy the key (starts with {CYAN}gsk_{RESET})")
    print()

    while True:
        key = input("  Paste your Groq API key here: ").strip()
        if key.startswith("gsk_") and len(key) > 20:
            break
        warn("That doesn't look like a valid Groq key (should start with gsk_). Try again.")

    nvd_key = input("\n  NVD API key (optional, press Enter to skip): ").strip()

    # Write .env
    env_content = f"GROQ_API_KEY={key}\nNVD_API_KEY={nvd_key}\n"
    ENV_FILE.write_text(env_content)
    ok(".env created")


# ── Step 4: Smoke test ────────────────────────────────────────────────────────

def smoke_test():
    step("4/4  Running quick test")
    info("Sending one test CVE to Groq AI...")

    # Load .env before importing anything
    from dotenv import load_dotenv
    load_dotenv(ENV_FILE)

    try:
        from groq import Groq
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=50,
            messages=[{"role": "user", "content": "Reply with only: OK"}]
        )
        reply = response.choices[0].message.content.strip()
        if reply:
            ok(f"Groq API working — response: \"{reply}\"")
        else:
            warn("Got empty response from Groq — key may be invalid")
    except Exception as e:
        err(f"Groq test failed: {e}")
        err("Check your API key at https://console.groq.com")
        sys.exit(1)


# ── Done ──────────────────────────────────────────────────────────────────────

def print_next_steps():
    sep = "=" * 52
    print(f"""
{GREEN}{sep}
  Setup complete! Here is how to run VulnAgent:
{sep}{RESET}

  {BOLD}Scan your local machine:{RESET}
  {CYAN}python agent.py --scan{RESET}

  {BOLD}Scan a specific IP:{RESET}
  {CYAN}python agent.py --scan --target 192.168.1.100{RESET}

  {BOLD}Run on a daily schedule:{RESET}
  {CYAN}python agent.py --schedule{RESET}

  Reports are saved to: {CYAN}reports/{RESET}
  Logs are saved to:    {CYAN}vuln-agent.log{RESET}

  Edit {CYAN}config.py{RESET} to change targets, port range, or SLA.
""")


if __name__ == "__main__":
    print(BANNER)
    check_python()
    install_requirements()
    configure_env()
    smoke_test()
    print_next_steps()
