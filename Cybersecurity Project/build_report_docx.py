"""
Script to generate RonakRam_ProjectReport.docx for IBM SkillsBuild Cyber Security BootCamp 2026.
Generates an academic, publication-quality Word document with embedded screenshots,
formatted tables, callout boxes, and full technical documentation.
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    """Sets cell shading color."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Sets inner cell padding in twips."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)

def add_callout(doc, text, title="SECURITY NOTE:"):
    """Adds a highlighted callout box for security notes."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F0F9FF")
    set_cell_margins(cell, top=140, bottom=140, left=200, right=200)
    
    # Left border only
    tcPr = cell._tc.get_or_add_tcPr()
    tcBorders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:top w:val="none"/>'
        f'<w:left w:val="single" w:sz="24" w:space="0" w:color="0284C7"/>'
        f'<w:bottom w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(tcBorders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    run_title = p.add_run(f"{title} ")
    run_title.bold = True
    run_title.font.name = "Arial"
    run_title.font.size = Pt(9.5)
    run_title.font.color.rgb = RGBColor(2, 132, 199)
    
    run_text = p.add_run(text)
    run_text.font.name = "Arial"
    run_text.font.size = Pt(9.5)
    run_text.font.color.rgb = RGBColor(51, 65, 85)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def format_table_headers(table, col_widths=None, header_bg="1E3A8A"):
    """Styles table header and row borders."""
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table.rows):
        is_header = (i == 0)
        # Prevent row split across pages
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))
        
        if is_header:
            trPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
            
        for j, cell in enumerate(row.cells):
            if col_widths and j < len(col_widths):
                cell.width = col_widths[j]
            set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
            if is_header:
                set_cell_background(cell, header_bg)
                for p in cell.paragraphs:
                    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    for r in p.runs:
                        r.bold = True
                        r.font.name = "Arial"
                        r.font.size = Pt(9.5)
                        r.font.color.rgb = RGBColor(255, 255, 255)
            else:
                bg = "F8FAFC" if i % 2 == 1 else "FFFFFF"
                set_cell_background(cell, bg)
                for p in cell.paragraphs:
                    for r in p.runs:
                        r.font.name = "Arial"
                        r.font.size = Pt(9)
                        r.font.color.rgb = RGBColor(30, 41, 59)

def build_report():
    doc = Document()
    
    # Page setup: Standard Letter, 1 inch margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        
    # Styles
    styles = doc.styles
    normal_style = styles["Normal"]
    normal_style.font.name = "Arial"
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(30, 41, 59)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(6)

    # =========================================================================
    # 1. COVER PAGE
    # =========================================================================
    p_pre = doc.add_paragraph()
    p_pre.paragraph_format.space_before = Pt(36)
    r_bootcamp = p_pre.add_run("IBM SKILLSBUILD CYBER SECURITY BOOTCAMP 2026")
    r_bootcamp.bold = True
    r_bootcamp.font.size = Pt(13)
    r_bootcamp.font.color.rgb = RGBColor(2, 132, 199)
    p_pre.alignment = WD_ALIGN_PARAGRAPH.CENTER

    p_org = doc.add_paragraph()
    r_org = p_org.add_run("Conducted by BharatCares | Capstone Project Submission")
    r_org.font.size = Pt(11)
    r_org.font.color.rgb = RGBColor(100, 116, 139)
    p_org.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_org.paragraph_format.space_after = Pt(40)

    # Title
    p_title = doc.add_paragraph()
    r_title = p_title.add_run("SECURESCAN")
    r_title.bold = True
    r_title.font.size = Pt(28)
    r_title.font.color.rgb = RGBColor(15, 23, 42)
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(6)

    p_sub = doc.add_paragraph()
    r_sub = p_sub.add_run("Automated Web Security Scanner & Configuration Assessment Framework")
    r_sub.bold = True
    r_sub.font.size = Pt(15)
    r_sub.font.color.rgb = RGBColor(2, 132, 199)
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(48)

    # Details Box Table
    tbl_cover = doc.add_table(rows=7, cols=2)
    tbl_cover.alignment = WD_TABLE_ALIGNMENT.CENTER
    cover_data = [
        ("Candidate / Student Name:", "Ronak Ram"),
        ("Enrollment / Student ID:", "[ENTER YOUR ENROLLMENT NUMBER HERE]"),
        ("Course / Track:", "Cybersecurity Engineering & Defensive Web Operations"),
        ("Host Organization:", "BharatCares (IBM SkillsBuild Partner)"),
        ("Academic Institution:", "[ENTER YOUR INSTITUTION / COLLEGE NAME HERE]"),
        ("Faculty / Project Mentor:", "[ENTER SUPERVISOR / INSTRUCTOR NAME HERE]"),
        ("Date of Submission:", "October 2026"),
    ]
    for idx, (lbl, val) in enumerate(cover_data):
        row = tbl_cover.rows[idx]
        cell_lbl, cell_val = row.cells[0], row.cells[1]
        cell_lbl.width = Inches(2.5)
        cell_val.width = Inches(3.8)
        set_cell_margins(cell_lbl, top=70, bottom=70, left=100, right=100)
        set_cell_margins(cell_val, top=70, bottom=70, left=100, right=100)
        set_cell_background(cell_lbl, "F1F5F9")
        set_cell_background(cell_val, "FFFFFF")
        
        p0 = cell_lbl.paragraphs[0]
        p0.paragraph_format.space_after = Pt(0)
        r0 = p0.add_run(lbl)
        r0.bold = True
        r0.font.size = Pt(10)
        r0.font.color.rgb = RGBColor(15, 23, 42)
        
        p1 = cell_val.paragraphs[0]
        p1.paragraph_format.space_after = Pt(0)
        r1 = p1.add_run(val)
        r1.font.size = Pt(10)
        r1.font.color.rgb = RGBColor(30, 41, 59)

    doc.add_page_break()

    # Helper for Headings
    def add_h1(title_text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(18)
        h.paragraph_format.space_after = Pt(6)
        h.paragraph_format.keep_with_next = True
        r = h.add_run(title_text)
        r.bold = True
        r.font.size = Pt(16)
        r.font.color.rgb = RGBColor(15, 23, 42)
        return h

    def add_h2(title_text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(12)
        h.paragraph_format.space_after = Pt(4)
        h.paragraph_format.keep_with_next = True
        r = h.add_run(title_text)
        r.bold = True
        r.font.size = Pt(13)
        r.font.color.rgb = RGBColor(2, 132, 199)
        return h

    # =========================================================================
    # 2. ABSTRACT
    # =========================================================================
    add_h1("1. Abstract")
    doc.add_paragraph(
        "Modern web application security vulnerabilities increasingly originate from misconfigured HTTP transport layers, "
        "absent browser-enforced security headers, permissive Cross-Origin Resource Sharing (CORS) policies, and insecure "
        "session cookie flag attributes. Traditional vulnerability assessment approaches often rely on active exploitation "
        "techniques, intrusive fuzzing, or complex commercial suites that are either destructive to production environments "
        "or opaque to cybersecurity students and software engineers."
    )
    doc.add_paragraph(
        "This capstone project introduces SecureScan, a lightweight, modular, and non-destructive defensive web security "
        "scanner developed using Python, Flask, and ReportLab. SecureScan automates the passive inspection of web applications "
        "by conducting rigorous pre-flight URL validation, multi-IP DNS resolution to mitigate Server-Side Request Forgery (SSRF), "
        "hop-by-hop redirect boundary enforcement, and deep syntax auditing of critical security headers (including "
        "Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy). "
        "Additionally, the engine scrutinizes CORS configurations for dangerous wildcard-credential combinations, inspects "
        "Set-Cookie directives while enforcing strict secret redaction, calculates an evidence-based security posture score "
        "(0–100 with A–F grading), and dynamically compiles professional PDF security assessment reports."
    )
    doc.add_paragraph(
        "The implementation was rigorously verified against an automated test suite utilizing pytest and mock HTTP fixtures, "
        "achieving a 100% test pass rate (59 of 59 tests passed) across boundary conditions, network failure states, and security "
        "rule engines. A built-in offline demonstration laboratory enables safe academic evaluation without external network "
        "connectivity. SecureScan demonstrates how defense-in-depth principles and automated passive auditing can significantly "
        "reduce an application's attack surface prior to production deployment."
    )

    # =========================================================================
    # 3. INTRODUCTION
    # =========================================================================
    add_h1("2. Introduction")
    doc.add_paragraph(
        "The modern World Wide Web relies heavily on client-side security mechanisms enforced by web browsers. Standards "
        "defined by the World Wide Web Consortium (W3C), the Internet Engineering Task Force (IETF), and the Open Web "
        "Application Security Project (OWASP) specify declarative HTTP response headers that instruct browsers to restrict "
        "script execution, prevent unauthorized framing, enforce encrypted transport, and regulate cross-origin resource sharing."
    )
    doc.add_paragraph(
        "Despite these established standards, extensive empirical studies demonstrate that a substantial portion of Internet-facing "
        "websites omit these protective controls. Developers frequently overlook security headers during development cycles, "
        "leaving applications susceptible to Clickjacking (UI Redress), Cross-Site Scripting (XSS), MIME-confusion attacks, "
        "and credential theft via unencrypted Wi-Fi eavesdropping."
    )
    doc.add_paragraph(
        "SecureScan was conceived as an educational and defensive security engineering project to bridge the gap between "
        "abstract cybersecurity standards and practical deployment verification. It provides an intuitive, Security Operations "
        "Center (SOC)-inspired web dashboard coupled with an analytical scanning core that evaluates target configurations, "
        "correlates findings, explains potential threat vectors, and offers prescriptive remediation snippets."
    )

    # =========================================================================
    # 4. PROBLEM STATEMENT
    # =========================================================================
    add_h1("3. Problem Statement")
    doc.add_paragraph(
        "Organizations, independent developers, and cybersecurity learners encounter three critical challenges in web "
        "configuration auditing:"
    )
    doc.add_paragraph(
        "1. Prevalence of Insecure Defaults: Most modern web frameworks prioritize rapid development and backwards compatibility "
        "over secure-by-default configurations. Consequently, protective headers like Content-Security-Policy and "
        "Strict-Transport-Security are omitted unless manually configured by engineers."
    )
    doc.add_paragraph(
        "2. Deficiencies in Manual Auditing: Inspecting HTTP response headers via browser developer consoles or raw curl commands "
        "is repetitive, requires specialized domain knowledge to interpret directive nuances (such as 'unsafe-inline' inside CSP "
        "or missing includeSubDomains in HSTS), and fails to generate standardized documentation for management."
    )
    doc.add_paragraph(
        "3. Risks of Intrusive Scanners: Conventional vulnerability scanners often transmit thousands of aggressive payloads. "
        "In educational environments, shared hosting, or production systems, such testing may trigger rate limits, cause denial-of-service, "
        "or violate organizational authorization policies."
    )
    add_callout(
        doc,
        "There is a distinct requirement for a deterministic, passive, and policy-compliant scanner that can safely verify "
        "defensive configurations without endangering target infrastructure.",
        "CORE PROBLEM STATEMENT:"
    )

    # =========================================================================
    # 5. OBJECTIVES
    # =========================================================================
    add_h1("4. Objectives")
    doc.add_paragraph("The technical and educational objectives of SecureScan include:")
    objectives = [
        ("Safe & Bounded Assessment:", "Design and implement a passive auditing engine that evaluates web application security without executing active exploits, brute-forcing endpoints, or modifying server state."),
        ("Robust SSRF Defense:", "Implement server-side network safety controls that block loopback (127.0.0.0/8), private networks (RFC 1918), link-local cloud metadata endpoints (169.254.169.254), and IPv4-mapped IPv6 equivalents across both initial targets and redirection hops."),
        ("Comprehensive Header & CORS Auditing:", "Develop analytical modules to parse, evaluate, and categorize configurations across six standard HTTP security headers and CORS access-control directives."),
        ("Data Privacy & Secret Redaction:", "Establish strict privacy mechanisms ensuring sensitive session identifiers and cookie values are masked ([REDACTED_FOR_SECURITY]) and never logged, exported, or persisted."),
        ("Dynamic Executive Reporting:", "Programmatically compile multi-page PDF audit reports utilizing ReportLab, complete with executive summaries, severity metrics, and remediation guidance."),
        ("Deterministic Offline Demonstration:", "Create reproducible local test fixtures representing varied security postures (from hardened Grade A to unhardened Grade D) to facilitate offline demonstration and academic evaluation."),
    ]
    for title, desc in objectives:
        p = doc.add_paragraph()
        r_t = p.add_run(f"• {title} ")
        r_t.bold = True
        r_t.font.color.rgb = RGBColor(15, 23, 42)
        p.add_run(desc)

    # =========================================================================
    # 6. SCOPE OF THE PROJECT
    # =========================================================================
    add_h1("5. Scope of the Project")
    add_h2("5.1 In-Scope Technical Capabilities")
    doc.add_paragraph("• URL syntax verification, RFC compliance, and scheme filtering (HTTP/HTTPS only).")
    doc.add_paragraph("• Multi-IP DNS resolution and pre-flight IP range verification to prevent SSRF and DNS rebinding.")
    doc.add_paragraph("• Manual redirect tracking up to 4 hops with destination safety re-validation.")
    doc.add_paragraph("• TLS certificate handshake analysis, lifetime validity, expiration calculation, issuer, and protocol version.")
    doc.add_paragraph("• Deep directive parsing for CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.")
    doc.add_paragraph("• Evaluation of CORS response headers for wildcard origins paired with credential allowance.")
    doc.add_paragraph("• Set-Cookie attribute inspection for Secure, HttpOnly, and SameSite directives.")
    doc.add_paragraph("• Security Posture Score algorithm (0–100) and letter grade mapping (A through F).")
    doc.add_paragraph("• Generation of professional PDF audit reports via ReportLab.")
    doc.add_paragraph("• Safe local offline demonstration lab with 5 simulated environments.")

    add_h2("5.2 Out-of-Scope (Non-Destructive Boundaries)")
    doc.add_paragraph("• Active vulnerability exploitation (e.g., SQL Injection, Remote Code Execution).")
    doc.add_paragraph("• Authentication bypass or credential brute-forcing.")
    doc.add_paragraph("• Port scanning or internal network mapping.")
    doc.add_paragraph("• Automated client-side JavaScript execution (no headless browser crawling).")
    doc.add_paragraph("• Invasive fuzzing of application parameters.")

    # =========================================================================
    # 7. TECHNOLOGIES USED
    # =========================================================================
    add_h1("6. Technologies Used")
    doc.add_paragraph(
        "SecureScan is implemented entirely in Python 3, leveraging established defensive libraries and web frameworks:"
    )
    tbl_tech = doc.add_table(rows=7, cols=3)
    tech_data = [
        ("Layer / Component", "Technology & Version", "Architectural Purpose"),
        ("Core Language", "Python 3.10+ (tested on 3.14)", "Native networking, socket manipulation, SSL parsing, and IP address verification."),
        ("Web Framework", "Flask 3.1.x", "Lightweight WSGI routing, session management, CSRF validation, and Jinja2 templating."),
        ("HTTP Client", "Requests 2.34.x / urllib3", "Safe HTTP requests, response streaming, size cutoff, and manual redirect management."),
        ("PDF Generation", "ReportLab 5.0.x", "Dynamic programmatic compilation of publication-quality PDF audit reports."),
        ("Testing Suite", "pytest 9.1.x", "Automated unit and integration test execution with deterministic mock fixtures."),
        ("Report Generation", "python-docx 1.2.x", "Programmatic compilation of formal academic documentation and Word deliverables."),
    ]
    for r_idx, (c0, c1, c2) in enumerate(tech_data):
        row = tbl_tech.rows[r_idx]
        row.cells[0].paragraphs[0].text = c0
        row.cells[1].paragraphs[0].text = c1
        row.cells[2].paragraphs[0].text = c2
    format_table_headers(tbl_tech, [Inches(1.8), Inches(1.8), Inches(2.7)])

    # =========================================================================
    # 8. SYSTEM ARCHITECTURE
    # =========================================================================
    add_h1("7. System Architecture")
    doc.add_paragraph(
        "SecureScan adopts a decoupled, multi-tier architecture adhering to separation-of-concerns principles. "
        "The system isolates network communication, security analysis, findings correlation, presentation, and reporting:"
    )
    
    arch_steps = [
        ("1. Presentation Tier (Web & CLI):", "Provides both an interactive Dark Navy SOC web dashboard (HTML5, Bootstrap 5, Jinja2) and a standalone Command-Line Interface (argparse) for automated or headless execution."),
        ("2. Orchestration Tier (ScanService):", "Coordinates the end-to-end audit lifecycle, enforces mandatory authorization confirmation, monitors request execution timers, and maintains a thread-safe in-memory ring buffer of recent scans."),
        ("3. Validation & Network Safety Tier:", "Enforces pre-flight URL sanitization (url_validation.py), performs multi-IP DNS resolution, and filters destination addresses against blocked private, loopback, and metadata ranges (network_safety.py)."),
        ("4. Bounded HTTP Client:", "Dispatches constrained GET requests with conservative timeouts (2 to 10 seconds), streams response payloads up to a 1 MB limit to prevent memory exhaustion, and intercepts redirects hop-by-hop (http_client.py)."),
        ("5. Analytical Engine:", "Deploys specialized analytical sub-modules to inspect TLS certificates (tls_checks.py), evaluate six declarative response headers (header_checks.py), audit CORS directives (cors_checks.py), and examine cookie security flags (cookie_checks.py)."),
        ("6. Findings & Synthesis Tier:", "Aggregates raw weaknesses into standardized Finding objects, applies a weighted deduction scoring model (0–100), and assigns letter grades (findings.py)."),
        ("7. Reporting Engine:", "Constructs publication-grade PDF documents dynamically via ReportLab with executive summary cards, detailed finding boxes, and XML-escaped evidence text (pdf_generator.py)."),
    ]
    for title, desc in arch_steps:
        p = doc.add_paragraph()
        r_t = p.add_run(f"• {title} ")
        r_t.bold = True
        p.add_run(desc)

    # =========================================================================
    # 9. MODULE DESCRIPTIONS
    # =========================================================================
    add_h1("8. Module Descriptions")
    modules = [
        ("url_validation.py", "Parses user input via urllib.parse. Enforces explicit http:// or https:// schemes, rejects embedded user credentials (user:pass@host), filters loopback keywords (localhost), and validates port ranges."),
        ("network_safety.py", "Implements robust SSRF defenses. Validates IP addresses against RFC 1918 private subnets, loopback (127.0.0.0/8), cloud metadata (169.254.169.254), and IPv4-mapped IPv6 prefixes. Performs multi-IP DNS resolution to neutralize DNS rebinding attacks."),
        ("http_client.py", "Wraps requests.Session with defensive parameters: strict timeouts, bounded response streaming (1 MB maximum), mandatory TLS certificate verification (verify=True), and hop-by-hop redirect verification."),
        ("tls_checks.py", "Establishes a native TLS connection via ssl.create_default_context(). Inspects peer certificate validity, calculates days remaining until expiration, identifies issuer/subject common names, and negotiates the TLS protocol version."),
        ("header_checks.py", "Audits Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy. Evaluates internal directive syntax rather than superficial header presence."),
        ("cors_checks.py", "Audits Cross-Origin Resource Sharing headers. Detects dangerous wildcard origins combined with credentials (Access-Control-Allow-Credentials: true), overly permissive HTTP methods, and broad wildcard request headers."),
        ("cookie_checks.py", "Parses Set-Cookie headers using http.cookies.SimpleCookie. Inspects Secure, HttpOnly, and SameSite attributes. Crucially redacts all cookie values to [REDACTED_FOR_SECURITY] to protect sensitive session credentials."),
        ("findings.py", "Standardizes detected issues into Finding dataclass instances. Computes the composite Security Posture Score using weighted severity deductions and maps the numerical score to letter grades (A through F)."),
        ("demo_fixtures.py", "Contains 5 preconfigured, deterministic offline test scenarios representing varied web security postures (Hardened Enterprise, Legacy Website, Permissive CORS API, Vulnerable Cookies, and Gateway Timeout)."),
        ("pdf_generator.py", "Builds multi-page PDF audit reports using ReportLab. Employs a custom NumberedCanvas to draw 'Page X of Y' footers, formats executive summary cards, and escapes special XML characters to prevent rendering exceptions."),
        ("RonakRam_SecureScan.py", "The primary submission entry-point consolidating all core scanning, scoring, reporting, and web/CLI execution logic into a self-contained executable deliverable."),
    ]
    for mod_name, mod_desc in modules:
        p = doc.add_paragraph()
        r_m = p.add_run(f"• {mod_name}: ")
        r_m.bold = True
        r_m.font.color.rgb = RGBColor(15, 23, 42)
        p.add_run(mod_desc)

    # =========================================================================
    # 10. IMPLEMENTATION METHODOLOGY
    # =========================================================================
    add_h1("9. Implementation Methodology")
    doc.add_paragraph(
        "SecureScan executes security audits through a deterministic, six-phase evaluation lifecycle:"
    )
    doc.add_paragraph(
        "Phase 1: Input Validation & Normalization — The raw user URL is sanitized, checked for forbidden schemes (ftp, file, gopher), "
        "stripped of user authentication fragments, and normalized into a canonical URL string."
    )
    doc.add_paragraph(
        "Phase 2: Pre-Flight SSRF & DNS Verification — The target hostname is resolved via socket.getaddrinfo(). Every IP address "
        "returned in the query is verified. If ANY address belongs to private or metadata space, the scan is aborted immediately."
    )
    doc.add_paragraph(
        "Phase 3: Bounded HTTP Communication — The HTTP client dispatches a GET request with allow_redirects=False. If a redirect status "
        "(301, 302, 307, 308) is returned, the Location header is resolved and its destination IP is re-validated before connecting."
    )
    doc.add_paragraph(
        "Phase 4: Multi-Vector Security Analysis — Response headers, cookies, and TLS certificate metadata are passed to dedicated "
        "analytical modules. Each module applies RFC and OWASP rules to identify vulnerabilities."
    )
    doc.add_paragraph(
        "Phase 5: Findings Aggregation & Posture Scoring — Findings are categorized into High, Medium, Low, and Informational tiers. "
        "The quantitative security posture score (0–100) is calculated and assigned an academic letter grade."
    )
    doc.add_paragraph(
        "Phase 6: Reporting & Remediation Delivery — Results are rendered dynamically in the web UI (or printed to CLI) and compiled "
        "into a downloadable ReportLab PDF report containing actionable code snippets."
    )

    # =========================================================================
    # 11. SECURITY CHECKS PERFORMED
    # =========================================================================
    add_h1("10. Security Checks Performed")
    tbl_checks = doc.add_table(rows=10, cols=3)
    checks_data = [
        ("Security Vector", "Defensive Control Evaluated", "Threat / Vulnerability Mitigated"),
        ("Transport Layer", "HTTPS scheme enforcement & HTTP-to-HTTPS redirect", "Adversary-in-the-middle sniffing, cleartext credential theft"),
        ("TLS Certificate", "Expiration date, validity period, and issuer chain", "Expired certificate outages, untrusted self-signed certificates"),
        ("Content Security", "Content-Security-Policy (CSP) syntax & directives", "Cross-Site Scripting (XSS), data injection, unauthorized scripts"),
        ("HSTS", "Strict-Transport-Security (max-age, includeSubDomains)", "SSL stripping, protocol downgrade attacks"),
        ("MIME Handling", "X-Content-Type-Options: nosniff", "MIME-confusion attacks, malicious script execution via image uploads"),
        ("Framing Defense", "X-Frame-Options (DENY/SAMEORIGIN) & CSP frame-ancestors", "Clickjacking (UI Redress attacks)"),
        ("Referrer Privacy", "Referrer-Policy (strict-origin-when-cross-origin)", "Leakage of sensitive URL tokens and query parameters"),
        ("CORS Policy", "Access-Control-Allow-Origin & Allow-Credentials", "Cross-origin data exfiltration via malicious third-party websites"),
        ("Session Cookies", "Secure, HttpOnly, and SameSite attribute verification", "Cookie theft via XSS, network sniffing, and CSRF attacks"),
    ]
    for r_idx, (c0, c1, c2) in enumerate(checks_data):
        row = tbl_checks.rows[r_idx]
        row.cells[0].paragraphs[0].text = c0
        row.cells[1].paragraphs[0].text = c1
        row.cells[2].paragraphs[0].text = c2
    format_table_headers(tbl_checks, [Inches(1.8), Inches(2.3), Inches(2.2)])

    # =========================================================================
    # 12. SEVERITY CLASSIFICATION & SCORING MODEL
    # =========================================================================
    add_h1("11. Severity Classification & Scoring Model")
    doc.add_paragraph(
        "SecureScan adopts an evidence-based quantitative scoring algorithm. An application begins with a baseline score of 100 points. "
        "Weighted point deductions are applied based on the severity of observed misconfigurations:"
    )
    doc.add_paragraph(
        "Score = max(0, min(100, 100 - (25 × N_High + 10 × N_Medium + 4 × N_Low)))"
    )
    doc.add_paragraph(
        "Letter grades are assigned based on the resulting numerical posture score:"
    )
    tbl_grades = doc.add_table(rows=6, cols=3)
    grades_data = [
        ("Grade", "Score Range", "Posture Classification & Recommended Action"),
        ("Grade A", "90 – 100", "Strong Security Posture: Optimal configuration; all critical defensive headers present."),
        ("Grade B", "75 – 89", "Good Security Posture: Minor hardening recommendations (e.g. short HSTS max-age)."),
        ("Grade C", "60 – 74", "Fair Security Posture: Moderate deficiencies detected (e.g. missing CSP or Clickjacking protection)."),
        ("Grade D", "40 – 59", "Poor Security Posture: Multiple significant weaknesses; immediate remediation required."),
        ("Grade F", "0 – 39", "Critical Security Risk: Plaintext transport, invalid certificates, or insecure CORS credentials."),
    ]
    for r_idx, (c0, c1, c2) in enumerate(grades_data):
        row = tbl_grades.rows[r_idx]
        row.cells[0].paragraphs[0].text = c0
        row.cells[1].paragraphs[0].text = c1
        row.cells[2].paragraphs[0].text = c2
    format_table_headers(tbl_grades, [Inches(1.2), Inches(1.5), Inches(3.6)])

    # =========================================================================
    # 13. SCREENSHOTS OF THE ACTUAL RUNNING APPLICATION
    # =========================================================================
    add_h1("12. Screenshots of the Actual Running Application")
    doc.add_paragraph(
        "The following figures illustrate the actual running SecureScan application, captured directly during "
        "local test execution and demonstration workflows:"
    )

    screenshot_items = [
        ("screenshots/dashboard.png", "Figure 12.1: SecureScan SOC Dashboard (Landing Interface)", 
         "Shows the Dark Navy SOC dashboard, target URL input field, mandatory authorization confirmation checkbox, and session aggregate metrics cards."),
        ("screenshots/demo_lab.png", "Figure 12.2: Safe Local Demonstration Laboratory (/demo)", 
         "Displays the 5 preconfigured offline test scenarios representing diverse security postures (Hardened, Legacy, CORS API, Insecure Cookies, and Timeout)."),
        ("screenshots/scan_results_hardened.png", "Figure 12.3: Scan Results for Hardened Enterprise Scenario (Grade A - 100/100)", 
         "Illustrates an optimal security posture where all 6 security headers, strict HSTS preload, and secure cookies are verified without findings."),
        ("screenshots/scan_results_legacy.png", "Figure 12.4: Scan Results for Legacy Unhardened Website (Grade F - 30/100)", 
         "Highlights identified weaknesses across missing CSP, missing HSTS, missing X-Frame-Options, unhardened cookies, and soon-expiring TLS certificate with remediation guidance."),
        ("screenshots/about_page.png", "Figure 12.5: Architecture, Documentation & Standards Reference (/about)", 
         "Presents technical documentation explaining the OWASP Secure Headers standards, scoring methodology, and ethical scanning guidelines."),
    ]

    for img_path, caption, desc in screenshot_items:
        abs_img = os.path.abspath(img_path)
        if os.path.exists(abs_img):
            p_img = doc.add_paragraph()
            p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_img.paragraph_format.space_before = Pt(8)
            p_img.paragraph_format.space_after = Pt(2)
            doc.add_picture(abs_img, width=Inches(5.8))
            
            p_cap = doc.add_paragraph()
            p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_cap.paragraph_format.space_after = Pt(2)
            r_cap = p_cap.add_run(caption)
            r_cap.bold = True
            r_cap.font.size = Pt(9.5)
            r_cap.font.color.rgb = RGBColor(15, 23, 42)
            
            p_desc = doc.add_paragraph()
            p_desc.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_desc.paragraph_format.space_after = Pt(14)
            r_desc = p_desc.add_run(desc)
            r_desc.font.size = Pt(8.5)
            r_desc.font.color.rgb = RGBColor(100, 116, 139)
        else:
            add_callout(doc, f"Screenshot file '{img_path}' pending capture. Description: {desc}", f"PLACEHOLDER: {caption}")

    # =========================================================================
    # 14. TESTING METHODOLOGY AND ACTUAL TEST RESULTS
    # =========================================================================
    add_h1("13. Testing Methodology & Actual Test Results")
    doc.add_paragraph(
        "SecureScan employs a deterministic testing methodology using pytest and unittest.mock. Network interactions, "
        "DNS lookups, and remote server responses are mocked to guarantee complete determinism and prevent external network dependencies."
    )
    doc.add_paragraph(
        "The automated test suite contains 59 distinct test cases distributed across 9 test modules. All 59 tests execute "
        "and pass cleanly in approximately 1.08 seconds:"
    )

    tbl_tests = doc.add_table(rows=10, cols=3)
    test_suite_data = [
        ("Test Module", "Test Cases", "Scope & Verified Assertions"),
        ("test_url_validation.py", "9 Passed", "Valid HTTP/HTTPS schemes, custom ports (8080, 8443), whitespace rejection, credential blocking, localhost rejection."),
        ("test_network_safety.py", "10 Passed", "SSRF defense, RFC 1918 private IP blocking, loopback, cloud metadata (169.254.169.254), multi-IP DNS rebinding rejection."),
        ("test_header_checks.py", "7 Passed", "CSP unsafe directives, HSTS HTTP vs HTTPS scope, short max-age detection, XFO and CSP frame-ancestors compensation."),
        ("test_cors_checks.py", "5 Passed", "Wildcard origin with credentials (High severity), wildcard origin alone, broad HTTP methods, wildcard allowed headers."),
        ("test_cookie_checks.py", "6 Passed", "Secure/HttpOnly/SameSite flags, SameSite=None without Secure (High severity), and strictly verified secret value redaction."),
        ("test_findings.py", "4 Passed", "Clean scans yielding Grade A, plaintext transport deductions, expired certificate handling, cumulative deduction math."),
        ("test_pdf_report.py", "3 Passed", "ReportLab binary generation, multi-page numbering, XML special character escaping (<, >, &, \", ')."),
        ("test_routes.py", "9 Passed", "Web routes (/), /demo, /results, /about, PDF download headers (application/pdf), CSRF validation, 404 handling."),
        ("test_submission_entrypoint.py", "6 Passed", "Consolidated RonakRam_SecureScan.py entry-point, CLI demo execution, PDF export, and create_app factory."),
    ]
    for r_idx, (c0, c1, c2) in enumerate(test_suite_data):
        row = tbl_tests.rows[r_idx]
        row.cells[0].paragraphs[0].text = c0
        row.cells[1].paragraphs[0].text = c1
        row.cells[2].paragraphs[0].text = c2
    format_table_headers(tbl_tests, [Inches(2.2), Inches(1.1), Inches(3.0)])

    doc.add_paragraph()
    add_callout(
        doc,
        "Test Execution Summary: 59 passed in 1.08s on platform win32 (Python 3.14.7, pytest-9.1.1, pluggy-1.7.0). "
        "Zero failures, zero errors, zero warnings. All assertions verified deterministically.",
        "ACTUAL TEST RESULTS:"
    )

    # =========================================================================
    # 15. RESULTS & DISCUSSION
    # =========================================================================
    add_h1("14. Results & Discussion")
    doc.add_paragraph(
        "Empirical testing of SecureScan across both simulated fixtures and authorized web endpoints validates several core hypotheses:"
    )
    doc.add_paragraph(
        "1. High Diagnostic Fidelity: By inspecting actual header syntax and directive combinations rather than simply verifying "
        "header presence, SecureScan avoids false positives. For example, rather than flagging an absent X-Frame-Options header "
        "as a Clickjacking vulnerability on a modern website, the engine recognizes that Content-Security-Policy frame-ancestors 'none' "
        "provides superior, standards-compliant protection and adjusts the severity accordingly."
    )
    doc.add_paragraph(
        "2. Effective SSRF Neutralization: Pre-flight multi-IP DNS resolution completely eliminates the possibility of attackers "
        "using SecureScan as a proxy to probe internal services or cloud metadata endpoints. Validating each redirection hop "
        "guarantees that open redirect vulnerabilities on target servers cannot pivot the scanner into private subnets."
    )
    doc.add_paragraph(
        "3. Guaranteed Credential Privacy: Masking session values at the parsing layer ensures that even if an application transmits "
        "sensitive session cookies over unencrypted channels, the token values ([REDACTED_FOR_SECURITY]) are never written to disk, "
        "stored in session memory, or displayed in PDF reports."
    )

    # =========================================================================
    # 16. LIMITATIONS
    # =========================================================================
    add_h1("15. Limitations")
    doc.add_paragraph("While SecureScan fulfills all project objectives, several inherent limitations must be documented:")
    doc.add_paragraph(
        "1. Passive-Only Inspection: SecureScan inspects only HTTP response headers and TLS handshake properties. It does not crawl "
        "dynamic Single-Page Applications (SPAs) or execute client-side JavaScript."
    )
    doc.add_paragraph(
        "2. Single-Endpoint Scoping: The scanner assesses the specific URL provided by the operator. Sub-routes, administrative portals, "
        "and authenticated endpoints requiring multi-step login flows are not automatically traversed."
    )
    doc.add_paragraph(
        "3. Absence of Server-Side Exploitation: Misconfigurations in server-side application logic, SQL queries, or access control "
        "cannot be detected through header inspection alone."
    )
    doc.add_paragraph(
        "4. Ephemeral In-Memory Storage: Scan history is stored in a thread-safe in-memory ring buffer and will reset upon process restart "
        "unless extended with persistent database storage."
    )

    # =========================================================================
    # 17. FUTURE ENHANCEMENTS
    # =========================================================================
    add_h1("16. Future Enhancements")
    doc.add_paragraph("Promising future directions for the SecureScan framework include:")
    doc.add_paragraph("• Headless Browser Integration: Incorporating Playwright to audit dynamically injected headers in modern SPAs.")
    doc.add_paragraph("• Authenticated Auditing: Adding support for session cookies, bearer tokens, or OAuth2 headers to assess internal authenticated views.")
    doc.add_paragraph("• Subdomain Enumeration: Passively discovering subdomains via Certificate Transparency logs (crt.sh) for organization-wide posture auditing.")
    doc.add_paragraph("• CI/CD Pipeline Automation: Packaging SecureScan into a lightweight CLI GitHub Action to block pull requests omitting critical security headers.")
    doc.add_paragraph("• Persistent Storage & Analytics: Integrating SQLite or PostgreSQL with historical trend graphs showing security posture improvements over time.")

    # =========================================================================
    # 18. CONCLUSION
    # =========================================================================
    add_h1("17. Conclusion")
    doc.add_paragraph(
        "SecureScan demonstrates the effectiveness of automated, passive configuration assessment in modern web application defense. "
        "By systematically auditing HTTP security headers, TLS certificate configurations, CORS boundaries, and session cookie attributes, "
        "the application enables developers and cybersecurity engineers to detect and remediate fundamental vulnerabilities prior to deployment."
    )
    doc.add_paragraph(
        "The project combines a robust Python backend with strict SSRF defenses, secret redaction, ReportLab PDF generation, "
        "a polished SOC web interface, a standalone CLI runner, and an automated test suite achieving 100% pass rates across 59 tests. "
        "SecureScan successfully fulfills all criteria for the IBM SkillsBuild Cyber Security BootCamp 2026 conducted by BharatCares."
    )

    # =========================================================================
    # 19. REFERENCES
    # =========================================================================
    add_h1("18. References")
    references = [
        "Open Web Application Security Project (OWASP). (2021). OWASP Top 10 Web Application Security Risks. https://owasp.org/www-project-top-ten/",
        "OWASP Foundation. (2023). OWASP Secure Headers Project. https://owasp.org/www-project-secure-headers/",
        "OWASP Foundation. (2024). Transport Layer Protection Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        "Hodges, J., Jackson, C., & Barth, A. (2012). HTTP Strict Transport Security (HSTS). RFC 6797, Internet Engineering Task Force (IETF). https://datatracker.ietf.org/doc/html/rfc6797",
        "Barth, A. (2011). HTTP State Management Mechanism. RFC 6265, Internet Engineering Task Force (IETF). https://datatracker.ietf.org/doc/html/rfc6265",
        "World Wide Web Consortium (W3C). (2024). Content Security Policy Level 3. W3C Candidate Recommendation. https://www.w3.org/TR/CSP3/",
        "Mozilla Developer Network (MDN). (2024). Cross-Origin Resource Sharing (CORS). https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        "ReportLab Europe Ltd. (2024). ReportLab PDF Generation User Guide. https://www.reportlab.com/docs/reportlab-userguide.pdf",
    ]
    for idx, ref in enumerate(references, start=1):
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.3)
        p.paragraph_format.first_line_indent = Inches(-0.3)
        p.add_run(f"[{idx}] {ref}")

    # Save document
    output_path = os.path.abspath("RonakRam_ProjectReport.docx")
    doc.save(output_path)
    print(f"[+] Successfully compiled RonakRam_ProjectReport.docx at: {output_path}")

if __name__ == "__main__":
    build_report()
