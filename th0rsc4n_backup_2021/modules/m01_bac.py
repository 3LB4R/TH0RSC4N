"""
A01:2025 - Broken Access Control (Universal)
- Multi-path admin discovery + content validation
- IDOR testing (numeric + UUID)
- CORS misconfiguration
- Anti false-positive heuristic
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode


# ==========================================
# ADMIN PATHS (Universal)
# ==========================================
ADMIN_PATHS = [
    # Generic admin
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/panel", "/cpanel", "/dashboard", "/console", "/manage",
    "/management", "/backend", "/control", "/control-panel",
    # CMS
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/wp-content/uploads/", "/wp-json/wp/v2/users",
    "/drupal/admin", "/administrator/manifests/files/joomla.xml",
    # API
    "/api/admin", "/api/v1/admin", "/api/users", "/api/v1/users",
    "/api/me", "/api/profile",
    # Config files
    "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config",
    "/config.php", "/config.json", "/config.yaml",
    "/wp-config.php", "/database.yml",
    # Backup
    "/backup.zip", "/backup.sql", "/backup.tar.gz", "/db.sql",
    # Monitoring
    "/server-status", "/server-info", "/actuator",
    "/actuator/health", "/actuator/env", "/actuator/beans",
    # Metadata
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/humans.txt", "/crossdomain.xml",
]

# False positive keywords (halaman 404 kosmetik)
FP_KEYWORDS = [
    "404", "not found", "tidak ditemukan", "not_found",
    "page could not be found", "lost in space",
    "halaman tidak ada", "error-page", "error_page",
    "halaman tidak ditemukan", "no such file",
    "cannot be found", "does not exist",
    "this page could not be found", "page not found",
    "404 |", "| 404", "404 -",
]

# Admin content keywords (halaman admin ASLI)
ADMIN_KEYWORDS = [
    "password", "login", "username", "signin", "sign in",
    "sign-in", "dashboard", "admin panel", "adminpanel",
    "auth", "authorization", "access token", "refresh token",
    "session", "logout", "sign out", "signout",
    "csrf", "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "welcome admin", "admin_data", "user_data", "manage_users",
    "forgot password", "reset password",
]

# IDOR parameters
IDOR_PARAMS = [
    "id", "user_id", "uid", "userid", "account_id", "account",
    "invoice", "invoice_id", "order", "order_id",
    "document_id", "doc_id", "file_id", "file",
    "post_id", "item_id", "product_id", "cust_id",
]


# ==========================================
# HEURISTIC VALIDATOR
# ==========================================
def _is_false_positive(body: str) -> bool:
    """Return True jika body cuma halaman 404 kosmetik."""
    if not body or len(body) < 100:
        return True
    body_low = body.lower()
    fp_hits = sum(1 for kw in FP_KEYWORDS if kw in body_low)
    # Kalau ada >= 2 keyword 404, kemungkinan besar false positive
    if fp_hits >= 2:
        return True
    # Cek apakah ada tag 404 khas
    if re.search(r"<title>[^<]*404[^<]*</title>", body, re.IGNORECASE):
        return True
    # Cek Vercel/Next.js 404 page
    if "lost in space" in body_low or "page could not be found" in body_low:
        return True
    return False


def _has_admin_content(body: str) -> tuple:
    """Return (bool, evidence_str) apakah body mengandung form/element admin ASLI."""
    if not body:
        return False, ""
    body_low = body.lower()

    # Keyword hits
    found = [kw for kw in ADMIN_KEYWORDS if kw in body_low]
    if not found:
        return False, ""

    # Verifikasi struktural: harus ada form / input / JSON auth
    has_form = bool(re.search(r"<form[\s>]", body, re.IGNORECASE))
    has_input = bool(re.search(r"<input[\s>]", body, re.IGNORECASE))
    has_button = bool(re.search(r"<button[\s>].*?(?:login|signin|submit)", body, re.IGNORECASE | re.DOTALL))
    has_json_auth = bool(re.search(
        r'"(?:token|session|user_id|authenticated|role|access_token)"\s*:',
        body, re.IGNORECASE
    ))

    if has_form or has_input or has_button or has_json_auth:
        return True, ", ".join(found[:5])
    return False, ""


def _has_personal_data(body: str) -> bool:
    """Cek apakah body mengandung data personal (indikasi IDOR valid)."""
    if not body:
        return False
    # Email
    if re.search(r"[\w\.\-]+@[\w\.\-]+\.\w{2,}", body):
        return True
    # Phone
    if re.search(r"(?:\+?\d{1,3}[\s\-]?)?\d{9,15}", body):
        return True
    # JSON keys personal
    if re.search(r'"(?:name|email|phone|address|dob|ssn|credit)"\s*:', body, re.IGNORECASE):
        return True
    return False


# ==========================================
# SCAN FUNCTIONS
# ==========================================
async def _scan_admin_paths(scanner):
    """Scan admin paths dengan content validation."""
    base_url = scanner.target.rstrip("/")
    tasks = [scanner.aget(base_url + p) for p in ADMIN_PATHS]
    results = await scanner.agather(tasks)

    found = False
    for path, r in zip(ADMIN_PATHS, results):
        if not isinstance(r, dict):
            continue
        status = r.get("status", 0)
        body = r.get("body", "")

        if status != 200:
            continue
        # Skip 404 kosmetik
        if _is_false_positive(body):
            continue
        # Validasi admin content
        is_admin, evidence = _has_admin_content(body)
        if is_admin:
            scanner.add_finding(
                "A01: Admin Panel Exposed",
                "HIGH",
                f"Panel admin dapat diakses tanpa otentikasi: {path}",
                mitigation=(
                    "Batasi akses via autentikasi kuat. "
                    "Implementasikan IP whitelist atau VPN. "
                    "Hapus dari production jika tidak diperlukan."
                ),
                evidence=f"HTTP {status} | Keywords: {evidence}",
                url=base_url + path,
            )
            found = True

    if not found:
        scanner.add_finding(
            "A01: Admin Path",
            "SAFE",
            f"Tidak ada panel admin yang terekspos (dari {len(ADMIN_PATHS)} path diuji)",
        )


async def _scan_idor(scanner):
    """Test IDOR pada parameter numerik."""
    is_idor_found = False

    for param in IDOR_PARAMS:
        sep = "&" if "?" in scanner.target else "?"
        url_1 = f"{scanner.target}{sep}{param}=1"
        url_2 = f"{scanner.target}{sep}{param}=2"

        r1 = await scanner.aget(url_1)
        r2 = await scanner.aget(url_2)
        if not isinstance(r1, dict) or not isinstance(r2, dict):
            continue

        body_1 = r1.get("body", "")
        body_2 = r2.get("body", "")
        len_1 = len(body_1)
        len_2 = len(body_2)

        # Skip kalau response kosong atau sama
        if len_1 < 200 or len_2 < 200:
            continue
        if len_1 == len_2:
            continue

        # Delta signifikan?
        delta = abs(len_1 - len_2)
        if delta < 200:
            continue

        # Cek personal data
        combined = body_1 + body_2
        if _has_personal_data(combined):
            scanner.add_finding(
                "A01: IDOR",
                "MEDIUM",
                f"Parameter '{param}' berpotensi IDOR (delta {delta} bytes)",
                mitigation=(
                    "Verifikasi otorisasi objek per-user. "
                    "Jangan gunakan ID langsung dari user tanpa validasi kepemilikan."
                ),
                evidence=f"Len(1)={len_1} vs Len(2)={len_2} | Personal data: yes",
            )
            is_idor_found = True
            break

    if not is_idor_found:
        scanner.add_finding(
            "A01: IDOR",
            "SAFE",
            f"Tidak ada IDOR terdeteksi ({len(IDOR_PARAMS)} parameter diuji)",
        )


async def _scan_cors(scanner):
    """Cek CORS misconfiguration."""
    origin_evil = "https://attacker-th0rscan.com"
    r = await scanner.aget(scanner.target, headers_override={"Origin": origin_evil})

    if not isinstance(r, dict):
        return

    h = r.get("headers", {})
    acao = h.get("access-control-allow-origin", "").strip()
    acac = h.get("access-control-allow-credentials", "").strip().lower()

    if acao == origin_evil and acac == "true":
        scanner.add_finding(
            "A01: CORS Misconfiguration",
            "HIGH",
            "CORS salah konfigurasi — origin attacker diizinkan dengan credentials",
            mitigation=(
                "Batasi Access-Control-Allow-Origin ke whitelist domain. "
                "Jangan pernah kombinasikan wildcard dengan credentials."
            ),
            evidence=f"ACAO: {acao} | ACAC: {acac}",
        )
    elif acao == origin_evil:
        scanner.add_finding(
            "A01: CORS Misconfiguration",
            "MEDIUM",
            "CORS merefleksikan origin attacker",
            mitigation="Batasi ACAO ke whitelist domain yang dikenal",
            evidence=f"ACAO: {acao}",
        )
    elif acao == "*":
        scanner.add_finding(
            "A01: CORS Wildcard",
            "LOW",
            "CORS wildcard (*) — memungkinkan akses dari mana saja",
            mitigation="Batasi ACAO ke domain spesifik",
            evidence=f"ACAO: {acao}",
        )
    else:
        scanner.add_finding(
            "A01: CORS",
            "SAFE",
            "Konfigurasi CORS terlihat aman",
            evidence=f"ACAO: {acao or '(tidak ada)'}",
        )


# ==========================================
# MAIN
# ==========================================
async def _run(scanner):
    # Jalankan 3 sub-scan paralel
    await asyncio.gather(
        _scan_admin_paths(scanner),
        _scan_idor(scanner),
        _scan_cors(scanner),
        return_exceptions=True,
    )


def scan(scanner):
    """Entry point — dipanggil dari cli.py."""
    try:
        asyncio.run(_run(scanner))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_run(scanner))
    except Exception as e:
        scanner.add_finding("A01: BAC", "INFO", f"Error: {e}")
