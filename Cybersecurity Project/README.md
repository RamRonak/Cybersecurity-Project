# SecureScan — Automated Web Security Scanner & Configuration Assessment Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/tests-59%20passed%20(100%25)-success.svg)](https://pytest.org/)
[![Bootcamp](https://img.shields.io/badge/IBM%20SkillsBuild-Cyber%20Security%202026-052FAD.svg)](#about-the-project)
[![Partner](https://img.shields.io/badge/conducted%20by-BharatCares-orange.svg)](#about-the-project)

> **Candidate / Author:** Ronak Ram  
> **Program:** IBM SkillsBuild Cyber Security BootCamp 2026 conducted by BharatCares  
> **Project Title:** SecureScan — Automated Web Security Scanner & Configuration Assessment Framework  
> **Submission Deliverables:**
> 1. `RonakRam_SecureScan.py` (Consolidated runnable Python entry-point with Web & CLI interfaces)
> 2. `requirements.txt` (Pinned compatible external dependencies)
> 3. `RonakRam_ProjectReport.docx` (Academic capstone project report with embedded screenshots)
> 4. `README.md` (Technical documentation & setup guide)

---

## 1. Project Overview

**SecureScan** is a defensive, non-destructive web application security scanner designed to evaluate transport security, HTTP security response headers, Cross-Origin Resource Sharing (CORS) access policies, and session cookie configuration. 

Built with **Python**, **Flask**, and **ReportLab**, SecureScan addresses the prevalent issue of misconfigured security boundaries by offering pre-flight Server-Side Request Forgery (SSRF) defenses, multi-IP DNS resolution, deep syntax inspection of declarative headers, strict secret redaction, and publication-ready PDF security audit reports. It provides both an interactive Dark Navy Security Operations Center (SOC) web dashboard and a standalone Command-Line Interface (CLI).

---

## 2. Problem Statement & Objectives

### Problem Statement
Modern web vulnerabilities frequently stem from preventable configuration oversights rather than complex zero-day exploits. Software developers routinely deploy web applications without configuring essential browser-enforced security headers, leaving users exposed to Clickjacking (UI Redress), Cross-Site Scripting (XSS), and SSL-stripping downgrade attacks. Furthermore, overly permissive CORS directives and cookies lacking `Secure` or `HttpOnly` attributes facilitate data leakage and session hijacking.

Manual auditing via browser developer tools or `curl` is repetitive, prone to human error, and fails to yield standardized documentation. Conventional vulnerability scanners often deploy aggressive exploit payloads that can disrupt production services or violate authorization policies.

### Project Objectives
- **Defensive & Non-Destructive:** Audit configurations passively without intrusive payloads, port scanning, or brute-force requests.
- **SSRF Immunity:** Implement multi-IP DNS resolution and strict IP boundary filtering to prevent Server-Side Request Forgery against loopback, private subnets (RFC 1918), and cloud metadata services (`169.254.169.254`).
- **Deep Syntax Header Auditing:** Evaluate directive syntax across six core headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **CORS & Cookie Review:** Identify risky wildcard origins paired with credentials (`Access-Control-Allow-Credentials: true`) and audit session cookie flags while strictly redacting confidential values.
- **Dynamic Executive Reporting:** Programmatically compile multi-page PDF audit reports via ReportLab.
- **Deterministic Offline Demonstration:** Provide 5 preconfigured offline scenarios to enable complete evaluation without outbound network connectivity.

---

## 3. Core Features

- **Consolidated & Modular Architecture:** Run via the consolidated `RonakRam_SecureScan.py` submission entry point or the multi-file application layout (`app.py` + `scanner/`).
- **Dual Execution Interfaces:** Interactive Web Dashboard (Flask/Jinja2/Bootstrap 5) and Command-Line Interface (CLI with argparse).
- **Pre-Flight SSRF Protection:** Validates every resolved IP address across multi-A DNS records and re-validates destination IPs at each redirect hop (up to 4 hops).
- **TLS Certificate Analysis:** Queries native SSL sockets to extract certificate validity periods, expiration countdown (days remaining), subject, issuer, and negotiated TLS protocol version.
- **Secret Redaction by Design:** All raw `Set-Cookie` token values are masked to `[REDACTED_FOR_SECURITY]` across memory, UI, console, and PDF outputs.
- **Security Posture Scoring:** Calculates a weighted 0–100 score:
  $$\text{Score} = \max(0, \min(100, 100 - (25 \times N_{\text{High}} + 10 \times N_{\text{Med}} + 4 \times N_{\text{Low}})))$$
  Maps scores to academic letter grades: **A** (90–100), **B** (75–89), **C** (60–74), **D** (40–59), and **F** (0–39).
- **Publication-Ready PDF Reports:** Dynamically compiled with executive metrics, severity cards, detailed finding tables, and custom two-pass `NumberedCanvas` ("Page X of Y").
- **Offline Demonstration Laboratory:** 5 built-in simulation scenarios covering varied security postures.

---

## 4. Technologies Used

| Category | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Backend Core** | Python | 3.10+ (tested on 3.14.7) | Core runtime, socket management, SSL parsing, IP address validation. |
| **Web Framework** | Flask | >=3.1.0, <3.2.0 | WSGI web application, routing, session management, CSRF defense. |
| **HTTP Client** | Requests & urllib3 | requests >=2.32, urllib3 >=2.2 | Bounded HTTP communication, response streaming, redirect interception. |
| **PDF Reporting** | ReportLab | >=4.2.0, <5.1.0 | Programmatic compilation of multi-page executive security audit reports. |
| **Documentation** | python-docx | >=1.1.0, <2.0.0 | Programmatic compilation of formal academic Word project report. |
| **Testing Suite** | pytest | >=8.0.0, <10.0.0 | Unit and integration testing with deterministic mock fixtures. |
| **Frontend UI** | Bootstrap 5, Custom CSS | 5.3.x | Dark Navy SOC dashboard, interactive filters, animated indicators. |

---

## 5. Project Directory Structure

```text
Cybersecurity Project/
├── RonakRam_SecureScan.py          # Primary consolidated Python submission deliverable (CLI + Web)
├── requirements.txt                # Pinned external dependencies
├── RonakRam_ProjectReport.docx     # Academic project report with embedded screenshots
├── README.md                       # Comprehensive technical documentation & run guide
├── build_report_docx.py            # Python script to compile RonakRam_ProjectReport.docx
├── app.py                          # Original multi-file Flask application entry point
├── config.py                       # Application configuration and security boundaries
├── pytest.ini                      # Pytest discovery configuration
├── PROJECT_REPORT.md               # Markdown source of the formal capstone report
│
├── scanner/                        # Core defensive scanning engine modules
│   ├── __init__.py
│   ├── url_validation.py           # URL RFC parsing, scheme checking, and normalization
│   ├── network_safety.py           # SSRF defense, multi-IP resolution, redirect validation
│   ├── http_client.py              # Safe bounded HTTP client with strict TLS enforcement
│   ├── tls_checks.py               # Certificate validity, lifetime, issuer, and protocol checks
│   ├── header_checks.py            # Deep syntax evaluation of 6 security response headers
│   ├── cors_checks.py              # CORS origin, method, and credential risk analyzer
│   ├── cookie_checks.py            # Cookie flags auditor with strict secret redaction
│   ├── findings.py                 # Findings compilation, score deduction, and grade mapping
│   ├── scan_service.py             # Scan orchestration service & in-memory history buffer
│   └── demo_fixtures.py            # 5 deterministic offline demonstration test scenarios
│
├── reports/                        # Reporting module
│   ├── __init__.py
│   └── pdf_generator.py            # ReportLab PDF report generation engine
│
├── screenshots/                    # Real screenshots of the running application
│   ├── dashboard.png               # Web UI landing dashboard
│   ├── demo_lab.png                # Offline demonstration laboratory page
│   ├── scan_results_hardened.png   # Hardened scenario results (Grade A - 100/100)
│   ├── scan_results_legacy.png     # Legacy scenario results (Grade F - 30/100)
│   └── about_page.png              # Architecture and standards documentation page
│
├── templates/                      # Jinja2 HTML templates
│   ├── base.html                   # Master layout with dark theme and navbar
│   ├── index.html                  # Main scanning form and session metrics
│   ├── scan_results.html           # Detailed scan results with accordions and filters
│   ├── demo.html                   # Offline demo lab selector
│   ├── history.html                # Session scan history table
│   ├── about.html                  # Methodology and OWASP references
│   └── error.html                  # Error view (400, 404, 500)
│
├── static/                         # Static web assets
│   ├── css/style.css               # SOC dark navy aesthetic with cyan accents
│   └── js/app.js                   # Interactive filters, radar scan animation
│
└── tests/                          # Automated pytest suite (59 test cases)
    ├── test_url_validation.py      # 9 tests: URL syntax, schemes, ports, credentials
    ├── test_network_safety.py      # 10 tests: SSRF ranges, private IPs, DNS rebinding
    ├── test_header_checks.py       # 7 tests: CSP, HSTS, XFO, XCTO, RP, and PP checks
    ├── test_cors_checks.py         # 5 tests: CORS wildcards, credentials, methods
    ├── test_cookie_checks.py       # 6 tests: Cookie flags and secret value redaction
    ├── test_findings.py            # 4 tests: Score calculations, grades, deductions
    ├── test_pdf_report.py          # 3 tests: ReportLab PDF building and XML escaping
    ├── test_routes.py              # 9 tests: Flask routes, CSRF tokens, 404 error handling
    └── test_submission_entrypoint.py# 6 tests: Consolidated submission entry-point & CLI
```

---

## 6. Python Prerequisites & Windows Installation

### Prerequisites
- **Operating System:** Windows 10 or Windows 11 (also runs on Linux / macOS).
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14.

### Step 1: Open Terminal in Project Directory
Open PowerShell or Command Prompt in the workspace root:
```powershell
cd "c:\Users\ronak\OneDrive\Desktop\Cybersecurity Project"
```

### Step 2: Create a Virtual Environment
```powershell
python -m venv .venv
```

### Step 3: Activate the Virtual Environment
- **In PowerShell:**
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  ```
- **In Command Prompt (cmd):**
  ```cmd
  .venv\Scripts\activate
  ```

### Step 4: Install Required Dependencies
```powershell
python -m pip install -r requirements.txt
```

---

## 7. Exact Commands to Run `RonakRam_SecureScan.py`

The submitted `RonakRam_SecureScan.py` is a complete, runnable Python deliverable providing both a Web Dashboard and a full Command-Line Interface (CLI).

### 1. Launch the Web Dashboard (Default)
Run without arguments to launch the local SOC web application:
```powershell
python RonakRam_SecureScan.py
```
*(Alternatively: `python RonakRam_SecureScan.py --web --port 5000`)*

Output:
```text
  ____                            ____                  
 / ___|  ___  ___ _   _ _ __ ___ / ___|  ___ __ _ _ __  
 \___ \ / _ \/ __| | | | '__/ _ \\___ \ / __/ _` | '_ \ 
  ___) |  __/ (__| |_| | | |  __/ ___) | (_| (_| | | | |
 |____/ \___|\___|\__,_|_|  \___||____/ \___\__,_|_| |_|
  Defensive Web Security Scanner & Configuration Auditor
  Author: Ronak Ram | IBM SkillsBuild Cyber Security BootCamp 2026

[*] Starting SecureScan Web Dashboard on http://127.0.0.1:5000
[*] Access the SOC Dashboard in your browser: http://127.0.0.1:5000
[*] Press CTRL+C to stop the web server.
```
Open your web browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.

---

### 2. Run Safe Offline Demonstration Scenarios (CLI)
No outbound internet access required:

- **List all 5 available demo scenarios:**
  ```powershell
  python RonakRam_SecureScan.py --list-demos
  ```

- **Run Hardened Enterprise Web App scenario (Grade A - 100/100):**
  ```powershell
  python RonakRam_SecureScan.py --demo hardened
  ```

- **Run Legacy Website scenario and export PDF report:**
  ```powershell
  python RonakRam_SecureScan.py --demo legacy --pdf legacy_audit.pdf
  ```

- **Run Misconfigured CORS API scenario:**
  ```powershell
  python RonakRam_SecureScan.py --demo permissive_cors
  ```

- **Run Vulnerable Session Cookies scenario:**
  ```powershell
  python RonakRam_SecureScan.py --demo vulnerable_cookies
  ```

- **Run Gateway Timeout simulation:**
  ```powershell
  python RonakRam_SecureScan.py --demo timeout_error
  ```

---

### 3. Run a Live Passive Scan on an Authorized Target (CLI)
Explicit authorization confirmation (`--auth`) is mandatory:
```powershell
python RonakRam_SecureScan.py --url https://example.com --auth --pdf example_report.pdf
```

To display raw JSON results:
```powershell
python RonakRam_SecureScan.py --url https://example.com --auth --json
```

---

### 4. Display Help & Options
```powershell
python RonakRam_SecureScan.py --help
```

---

## 8. How to Use the Scanner

### Web Interface Workflow
1. **Navigate to Dashboard:** Open `http://127.0.0.1:5000/`.
2. **Enter Target URL:** Provide an authorized HTTP or HTTPS URL (e.g. `https://example.com`).
3. **Select Timeout:** Choose a conservative request timeout (default: 6 seconds).
4. **Confirm Authorization:** Check the mandatory checkbox: *"I confirm that I own or have explicit written authorization to assess this target."*
5. **Launch Audit:** Click **"Launch Security Audit"**. An animated scanning indicator tracks progress.
6. **Review Findings:**
   - Examine the calculated **Security Posture Score** and **Grade Badge** (A through F).
   - Filter findings by severity (All, High, Medium, Low, Informational).
   - Expand finding accordions to inspect evidence, technical explanations, and code remediation snippets.
7. **Download PDF Report:** Click **"Download PDF Report"** to export a formal, publication-ready security audit document.

---

## 9. Safe Offline Demonstration Mode (Academic Evaluation)

To enable live evaluation and grading without requiring network permissions to scan live external websites, SecureScan includes **5 built-in offline test scenarios**:

1. In the Web UI, click the **Demo Lab** tab (`http://127.0.0.1:5000/demo`).
2. Select any preconfigured scenario:
   - **Scenario 1 — Hardened Enterprise Web App:** Simulates Grade A posture with all 6 security headers configured, strict HSTS preload, and secure cookies.
   - **Scenario 2 — Legacy Unhardened Website:** Simulates Grade D/F posture missing CSP, X-Frame-Options (Clickjacking vulnerability), and HSTS.
   - **Scenario 3 — Misconfigured CORS API:** Simulates a high-severity CORS misconfiguration where `Access-Control-Allow-Origin: *` is combined with `Access-Control-Allow-Credentials: true`.
   - **Scenario 4 — Insecure Session Cookies:** Simulates plaintext HTTP transport with session tokens missing `Secure`, `HttpOnly`, and `SameSite` flags.
   - **Scenario 5 — Network Timeout Simulation:** Demonstrates clean error handling without false positives when a target is unresponsive.
3. Click **"Run Simulated Audit"**. The analytical engine compiles findings and allows immediate ReportLab PDF download.

---

## 10. Running Automated Tests

SecureScan includes a 59-case automated test suite verifying URL validation, SSRF boundary defenses, header analysis, CORS security, cookie redaction, PDF generation, Flask routes, and the consolidated submission entry point.

Execute the test suite:
```powershell
python -m pytest -v
```

### Actual Test Execution Output:
```text
============================= test session starts =============================
platform win32 -- Python 3.14.7, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\Users\ronak\OneDrive\Desktop\Cybersecurity Project
configfile: pytest.ini
testpaths: tests
collected 59 items

tests\test_cookie_checks.py ......                                       [ 10%]
tests\test_cors_checks.py .....                                          [ 18%]
tests\test_findings.py ....                                              [ 25%]
tests\test_header_checks.py .......                                      [ 37%]
tests\test_network_safety.py ..........                                  [ 54%]
tests\test_pdf_report.py ...                                             [ 59%]
tests\test_routes.py .........                                           [ 74%]
tests\test_submission_entrypoint.py ......                               [ 84%]
tests\test_url_validation.py .........                                   [100%]

============================= 59 passed in 1.08s ==============================
```

---

## 11. Security Design & Authorization Disclaimer

### Server-Side Request Forgery (SSRF) Defense
- **Multi-IP DNS Resolution:** Hostnames are resolved via `socket.getaddrinfo()`. If any returned IP address belongs to loopback, private, link-local, or cloud metadata ranges, the scan is immediately aborted.
- **Redirect Re-validation:** HTTP redirects (301, 302, 307, 308) are followed manually up to a maximum of 4 hops. Each redirection destination URL and resolved IP is re-verified before connecting.
- **Protocol Scoping:** Only explicit `http` and `https` schemes are permitted. Internal protocols (`file://`, `gopher://`, `ftp://`) and embedded credentials (`user:pass@host`) are rejected during pre-flight validation.

### Privacy & Secret Redaction
- `Set-Cookie` response headers are parsed to audit flags (`Secure`, `HttpOnly`, `SameSite`), but the cookie values themselves are strictly masked (`[REDACTED_FOR_SECURITY]`). Confidential tokens or session identifiers are never logged, printed, or exported to PDF reports.

### Ethical Usage Statement
> **LEGAL NOTICE:** SecureScan is developed strictly for educational purposes, defensive auditing, and authorized security assessments within the IBM SkillsBuild Cyber Security BootCamp 2026. Users must possess explicit written consent from the target website owner before initiating any network scans. Unauthorized testing against third-party systems may violate national and international cybersecurity statutes (e.g., Computer Fraud and Abuse Act, UK Computer Misuse Act, Information Technology Act). The authors and contributors assume no liability for misuse of this software.

---

## 12. Project Limitations

1. **Passive-Only Scope:** SecureScan inspects only HTTP response headers and TLS handshake properties. It does not crawl dynamic Single-Page Applications (SPAs) or render client-side JavaScript.
2. **Single Endpoint Evaluation:** The scanner assesses the specific URL endpoint provided by the user. Sub-routes, administrative consoles, and protected backend APIs requiring multi-step authentication are not automatically traversed.
3. **No Active Exploitation:** Misconfigurations at the authorization, business logic, or database query layer cannot be identified via header inspection alone.
4. **In-Memory History:** Scan history is maintained in thread-safe application memory and will reset upon application restart unless extended with persistent database storage.

---

## 13. Dataset & Source Information

**NOTICE REGARDING DATASET:**  
This project is an automated defensive web security scanner and configuration assessment framework. **It does not require or utilize an external machine-learning dataset.**

- The scanner directly evaluates live HTTP/HTTPS response headers and TLS certificates obtained from explicitly authorized web endpoints.
- For offline demonstrations, grading, and testing without network access, the application utilizes controlled, deterministic mock fixtures defined in `scanner/demo_fixtures.py` (and consolidated in `RonakRam_SecureScan.py`).
- No external training data or third-party datasets were downloaded or required.

---

## 14. Authoritative References

1. [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
2. [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
3. [RFC 6797: HTTP Strict Transport Security (HSTS)](https://datatracker.ietf.org/doc/html/rfc6797)
4. [RFC 6265: HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265)
5. [W3C Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
6. [MDN Web Docs: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
7. [ReportLab PDF Generation User Guide](https://www.reportlab.com/docs/reportlab-userguide.pdf)
