<div align="center">

```
 ████████╗██╗  ██╗ ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ╚══██╔══╝██║  ██║██╔═████╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║   ███████║██║██╔██║██████╔╝███████╗██║     ███████║██╔██╗ ██║
    ██║   ██╔══██║████╔╝██║██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
    ██║   ██║  ██║╚██████╔╝██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

# TH0RSC4N

**Brutal OWASP Top 10 Security Scanner**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red?style=for-the-badge)](https://owasp.org/Top10/)
[![Async](https://img.shields.io/badge/async-asyncio%20%2B%20aiohttp-purple?style=for-the-badge)](https://docs.python.org/3/library/asyncio.html)

*Automated vulnerability assessment tool for web applications*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Screenshots](#-screenshots) • [Architecture](#-architecture) • [Contributing](#-contributing)

</div>

---

## 📖 Overview

**TH0RSC4N** is a Python-based CLI security scanner designed for automated vulnerability assessment of web applications. Built with an **async engine** (`asyncio` + `aiohttp`), it performs 80+ security checks based on the **OWASP Top 10 2021** framework, with built-in **technology fingerprinting** (150+ technologies) and **multi-format reporting**.

Whether you're a penetration tester, security engineer, or developer wanting to audit your own application, TH0RSC4N provides fast, accurate, and actionable security insights — all from the command line.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Security Scanning
- **80+ OWASP Top 10 scenarios**
- **A01** — Broken Access Control (IDOR, CORS, admin paths)
- **A02** — Cryptographic Failures (TLS, cookies)
- **A03** — Injection (SQLi, XSS, CMDi, SSTI, NoSQLi, LDAP, XPath)
- **A04** — Insecure Design (rate limiting, race condition)
- **A05** — Security Misconfiguration (headers, verbose errors)
- **A06** — Vulnerable Components (CVE database)
- **A07** — Auth Failures (JWT, session)
- **A08** — Integrity Failures (SRI, deserialization)
- **A09** — Logging Failures (security.txt, log exposure)
- **A10** — SSRF (loopback, AWS metadata)

</td>
<td width="50%">

### ⚡ Performance
- **Async engine** — `asyncio` + `aiohttp`
- **Persistent session pool** — efficient TCP reuse
- **Bounded concurrency** — safe for target
- **Baseline comparison** — minimal false positives

### 🎯 Advanced
- **Technology detection** — 150+ tech (React, Next.js, Vite, Astro, dll)
- **3 scan modes** — Quick (~5s), Normal (~15s), Deep (~60s)
- **Multi-format reports** — HTML, JSON, Markdown, PDF
- **Config auto-generator** — Vercel, Netlify, Nginx, Apache, Cloudflare, Express
- **Web UI** — Flask-based interactive dashboard
- **Interactive mode** — guided scan for beginners

</td>
</tr>
</table>

---

## 🚀 Installation

### Prerequisites
- **Python 3.9+**
- **pip** (usually bundled with Python)

### Quick Install (from source)

```bash
# Clone repository
git clone https://github.com/3LB4R/TH0RSC4N.git
cd TH0RSC4N

# Create virtual environment
python -m venv .venv

# Activate
source .venv/bin/activate          # Linux / Mac
# .venv\Scripts\activate           # Windows

# Install dependencies
pip install -e .
```

### Verify Installation

```bash
th0rsc4n --help
```

If you see the ASCII banner + help menu, you're ready to go. ✅

---

## 🎯 Usage

### Basic Scan

```bash
# Normal scan (recommended)
th0rsc4n scan https://target.com

# Deep scan (all modules)
th0rsc4n scan https://target.com -m deep

# Quick scan (headers only, ~5s)
th0rsc4n scan https://target.com -m quick
```

### Save Report

```bash
# HTML report
th0rsc4n scan https://target.com -o report --format html

# All formats (HTML + JSON + MD + PDF)
th0rsc4n scan https://target.com -m deep -o report --format all
```

### Technology Detection

```bash
th0rsc4n tech https://target.com
```

### Security Headers Only

```bash
th0rsc4n headers https://target.com
```

### Interactive Mode (Beginner-friendly)

```bash
th0rsc4n interactive
```

### Web UI

```bash
th0rsc4n web
# Open browser → http://127.0.0.1:5000
```

### Export Config for Platform

```bash
th0rsc4n scan https://target.com --export-config nginx
th0rsc4n scan https://target.com --export-config vercel
th0rsc4n scan https://target.com --export-config express
```

---

## 📋 Command Reference

| Command | Description |
|---------|-------------|
| `th0rsc4n scan <url>` | Full security scan (OWASP Top 10) |
| `th0rsc4n scan <url> -m quick` | Fast scan (~5s) |
| `th0rsc4n scan <url> -m normal` | Balanced scan (~15s) |
| `th0rsc4n scan <url> -m deep` | Full scan (~60s) |
| `th0rsc4n scan <url> -o report --format all` | Save HTML/JSON/MD/PDF |
| `th0rsc4n tech <url>` | Detect technologies |
| `th0rsc4n headers <url>` | Check security headers only |
| `th0rsc4n interactive` | Guided scan mode |
| `th0rsc4n web` | Launch Web UI |
| `th0rsc4n modes` | List available scan modes |
| `th0rsc4n init` | Initialize config |

### Scan Options

| Flag | Description |
|------|-------------|
| `-m, --mode` | Scan mode: `quick` / `normal` / `deep` |
| `-o, --output` | Save report to path |
| `-f, --format` | Report format: `html` / `json` / `md` / `pdf` / `all` |
| `-t, --timeout` | HTTP timeout in seconds |
| `--severity` | Minimum severity to display |
| `--export-config` | Generate config: `vercel` / `netlify` / `nginx` / `apache` / `cloudflare` / `express` |
| `-v, --verbose` | Show all details |
| `-q, --quiet` | Only show summary |

---

## 📸 Screenshots

### Terminal — Deep Scan
![Banner & Scan](docs/screenshots/banner.png)

### Technology Detection
![Tech Detect](docs/screenshots/tech-detect.png)

### Interactive Mode
![Interactive](docs/screenshots/interactive.png)

### Web UI
![Web UI](docs/screenshots/web-ui.png)

### HTML Report
![HTML Report](docs/screenshots/report-html.png)

> ℹ️ Save your screenshots in `docs/screenshots/` folder in the repository.

---

## 🏗️ Architecture

```
th0rsc4n/
├── th0rsc4n/
│   ├── core/
│   │   ├── scanner.py          # Async engine + persistent session pool
│   │   └── finding.py          # Finding data model
│   ├── modules/                # 12 security scanning modules
│   │   ├── m00_tech_detect.py  # Technology fingerprinting
│   │   ├── m01_bac.py          # A01: Broken Access Control
│   │   ├── m02_crypto.py       # A02: Cryptographic Failures
│   │   ├── m03_injection.py    # A03: Injection (SQLi/XSS/CMDi/SSTI)
│   │   ├── m04_design.py       # A04: Insecure Design
│   │   ├── m05_misconfig.py    # A05: Security Misconfiguration
│   │   ├── m06_components.py   # A06: Vulnerable Components
│   │   ├── m07_auth.py         # A07: Auth Failures
│   │   ├── m08_integrity.py    # A08: Integrity Failures
│   │   ├── m09_logging.py      # A09: Logging Failures
│   │   ├── m10_ssrf.py         # A10: SSRF
│   │   └── m99_extra.py        # Extra scenarios
│   ├── reporters/              # Output formatters
│   │   ├── terminal.py         # Rich terminal output
│   │   ├── html.py             # HTML report
│   │   ├── json_rep.py         # JSON report
│   │   ├── markdown.py         # Markdown report
│   │   └── pdf.py              # PDF report (fpdf2)
│   ├── utils/
│   │   ├── banner.py           # ASCII banner
│   │   ├── loading.py          # Loading animations
│   │   ├── config.py           # Config manager
│   │   └── helpers.py          # Utilities
│   ├── web/                    # Flask Web UI
│   │   ├── server.py           # Async endpoint
│   │   └── templates/
│   │       └── index.html      # Dashboard UI
│   └── cli.py                  # CLI entry point
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Async-first** | `asyncio` + `aiohttp`, persistent session pool |
| **Anti-false-positive** | Baseline comparison, signature verification |
| **Adaptive executor** | Sync/async module auto-detection |
| **Safe by default** | Bounded concurrency, timeout per request |
| **Modular** | Each OWASP category = separate module |

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Coverage report
pytest --cov=th0rsc4n
```

---

## 📊 Sample Output

```
▶ A05: Misconfig
  ⚪ INFO     Platform terdeteksi: VERCEL
  🟠 HIGH     Strict-Transport-Security HILANG
      ↳ Tambahkan `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` di vercel.json
  🟠 HIGH     Content-Security-Policy HILANG
      ↳ Tambahkan `Content-Security-Policy: default-src 'self'; ...` di vercel.json
  🟡 MEDIUM   X-Frame-Options HILANG
      ↳ Tambahkan `X-Frame-Options: DENY` di vercel.json

╔══════════════════════════════════════╗
║      << TH0RSC4N SUMMARY >>          ║
╚══════════════════════════════════════╝
  🔴 CRITICAL: 0
  🟠 HIGH    : 2
  🟡 MEDIUM  : 3
  🔵 LOW     : 4
  ⚪ INFO    : 11
  🟢 SAFE    : 64
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Ideas for Contribution

- 🔌 Add new vulnerability scenarios
- 🌍 Multi-language support (i18n)
- 📊 Enhanced reporting (charts, graphs)
- 🔐 Authentication for Web UI
- 🐳 Docker image
- 📦 PyPI publishing

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

---

## ⚠️ Disclaimer

This tool is developed for **educational purposes** and **authorized security testing only**.

- ✅ **DO** use it to scan your own applications
- ✅ **DO** use it with written permission from the target owner
- ❌ **DO NOT** use it to attack systems you don't own
- ❌ **DO NOT** use it for illegal activities

**The author is not responsible for any misuse or damage caused by this tool.**

---

## 🙏 Acknowledgments

- [OWASP Foundation](https://owasp.org/) — for the Top 10 framework
- [aiohttp](https://docs.aiohttp.org/) — async HTTP client
- [Rich](https://rich.readthedocs.io/) — beautiful terminal output
- [Click](https://click.palletsprojects.com/) — CLI framework
- [fpdf2](https://py-pdf.github.io/fpdf2/) — PDF generation

---

## 📞 Contact

**Thorranov** — Cybersecurity Practitioner & CTF Player

[![Portfolio](https://img.shields.io/badge/Portfolio-thorranov.dev-blue?style=flat-square)](https://thorranov-portfolio.vercel.app)
[![GitHub](https://img.shields.io/badge/GitHub-3LB4R-black?style=flat-square&logo=github)](https://github.com/3LB4R)

---

<div align="center">

**⭐ If you find this project useful, consider giving it a star! ⭐**

Made with 🖤 by [Thorranov](https://github.com/3LB4R)

</div>
