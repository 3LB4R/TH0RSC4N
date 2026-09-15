"""
A02:2025 - Security Misconfiguration
Adaptive + verbose error leak detection.
Anti false-positive content-based verification for sensitive files.
"""
import re
import json
import requests

# Recommended headers
HEADERS_DB = {
    "Strict-Transport-Security": ("HIGH", "Mencegah MITM & downgrade",
        "max-age=63072000; includeSubDomains; preload"),
    "Content-Security-Policy": ("HIGH", "Mencegah XSS & injection",
        "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"),
    "X-Frame-Options": ("MEDIUM", "Mencegah Clickjacking", "DENY"),
    "X-Content-Type-Options": ("MEDIUM", "Mencegah MIME sniffing", "nosniff"),
    "Referrer-Policy": ("LOW", "Kontrol Referrer", "strict-origin-when-cross-origin"),
    "Permissions-Policy": ("LOW", "Batasi fitur browser", "camera=(), microphone=(), geolocation=()"),
    "Cross-Origin-Opener-Policy": ("LOW", "Isolasi browsing context", "same-origin"),
}

# Platform detection
PLATFORM_MAP = {
    "vercel": ["vercel", "x-vercel-id"],
    "netlify": ["netlify", "x-nf-request-id"],
    "cloudflare": ["cloudflare", "cf-ray"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "caddy": ["caddy"],
    "iis": ["microsoft-iis"],
    "python": ["gunicorn", "uvicorn", "werkzeug"],
    "express": ["express"],
}

# Stack trace signatures
ERROR_SIGS = [
    r"Traceback \(most recent call last\)",
    r"at [\w\.]+\([\w\.]+\.java:\d+\)",
    r"Stack trace:",
    r"Fatal error:.*?on line \d+",
    r"Warning:.*?on line \d+",
    r"Microsoft OLE DB.*?error",
    r"System\.Data\.SqlClient",
    r"SyntaxError:.*?in .*? on line \d+",
    r"SQLSTATE\[\w+\]",
    r"mysqli_sql_exception",
    r"Call to (?:a member function|undefined)",
    r"/var/www/[\w/\.]+",
    r"/home/[\w/\.]+\.py",
    r"C:\\Users\\[\w\\\.]+",
    r"C:\\xampp\\htdocs",
]

# ==========================================
# ENV VARIABLE PATTERNS (untuk verifikasi .env leak)
# ==========================================
ENV_PATTERNS = [
    r"^[A-Z_][A-Z0-9_]*\s*=\s*\S+",        # KEY=value (uppercase)
    r"^[A-Z_][A-Z0-9_]*\s*=\s*['\"].+['\"]",  # KEY="value"
]

ENV_KEYWORDS = [
    "DB_", "DB_HOST", "DB_USER", "DB_PASS", "DB_NAME",
    "APP_KEY", "APP_SECRET", "APP_ENV", "APP_DEBUG",
    "SECRET_", "JWT_", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY",
    "AWS_", "STRIPE_", "SMTP_", "MAIL_", "REDIS_", "MONGO_",
]

# ==========================================
# JSON INTERNAL KEYS (untuk verifikasi manifest/package.json)
# ==========================================
JSON_INTERNAL_KEYS = [
    "dependencies", "devDependencies", "peerDependencies",
    "compilerOptions", "chunks", "scripts", "version", "name",
    "main", "module", "types", "engines", "resolutions",
]


# ==========================================
# HELPERS
# ==========================================
def _detect_platform(headers):
    h = {k.lower(): v.lower() for k, v in headers.items()}
    server = h.get("server", "")
    for plat, sigs in PLATFORM_MAP.items():
        for sig in sigs:
            if sig in server or sig in h:
                return plat
    return "generic"


def _mitigation(platform, header, value):
    m = {
        "vercel": f"Tambahkan `{header}: {value}` di vercel.json",
        "netlify": f"Tambahkan `{header}: {value}` di _headers",
        "cloudflare": f"Tambahkan `{header}: {value}` di Transform Rules",
        "nginx": f"Tambahkan `add_header {header} \"{value}\" always;` di nginx.conf",
        "apache": f"Tambahkan `Header always set {header} \"{value}\"` di .htaccess",
        "caddy": f"Tambahkan `header {header} \"{value}\"` di Caddyfile",
        "iis": f"Tambahkan `<add name=\"{header}\" value=\"{value}\" />` di web.config",
        "python": f"Tambahkan `response.headers['{header}'] = '{value}'` di middleware",
        "express": f"Tambahkan `res.setHeader('{header}', '{value}')`",
        "generic": f"Tambahkan header `{header}: {value}` di server",
    }
    return m.get(platform, m["generic"])


# ==========================================
# CONTENT-BASED VERIFICATION
# ==========================================
def _verify_env_content(body):
    """
    Verifikasi apakah konten BENAR-BENAR file .env.
    Return (is_valid, evidence_str)
    """
    if not body or len(body) < 10:
        return (False, "")

    # Harus TIDAK mengandung tag HTML (kalau ada HTML, ini false positive)
    if re.search(r"<(?:html|body|head|div|script|!doctype)", body[:500], re.IGNORECASE):
        return (False, "HTML detected")

    # Cek pattern KEY=value
    lines = body.strip().split("\n")
    env_lines = 0
    keyword_hits = []

    for line in lines[:50]:  # Batasi 50 baris pertama
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Cek pattern KEY=value
        for pat in ENV_PATTERNS:
            if re.match(pat, line):
                env_lines += 1
                break

        # Cek keyword sensitif
        for kw in ENV_KEYWORDS:
            if line.upper().startswith(kw):
                keyword_hits.append(kw)

    # Minimal 3 baris KEY=value ATAU 1 keyword sensitif (DB_, APP_KEY, dll)
    if env_lines >= 3 or len(keyword_hits) >= 1:
        evidence = f"EnvLines={env_lines}"
        if keyword_hits:
            evidence += f" | Keywords={keyword_hits[:3]}"
        return (True, evidence)

    return (False, f"Only {env_lines} env lines")


def _verify_json_manifest(body, path):
    """
    Verifikasi apakah konten BENAR-BENAR file JSON manifest/package.json.
    Return (is_valid, evidence_str)
    """
    if not body or len(body) < 10:
        return (False, "")

    # Harus TIDAK mengandung tag HTML
    if re.search(r"<(?:html|body|head|div|!doctype)", body[:500], re.IGNORECASE):
        return (False, "HTML detected")

    # Coba parse sebagai JSON
    try:
        # Cari JSON object mulai dari karakter { pertama
        json_start = body.find("{")
        if json_start == -1:
            json_start = body.find("[")
        if json_start == -1:
            return (False, "No JSON structure")

        json_str = body[json_start:]
        # Batasi sampe 100KB
        json_str = json_str[:100000]

        # Coba parse beberapa kali dengan padding
        parsed = None
        for trim in [len(json_str), len(json_str) - 100, len(json_str) - 500]:
            if trim < 10:
                continue
            try:
                parsed = json.loads(json_str[:trim])
                break
            except json.JSONDecodeError:
                continue

        if parsed is None:
            return (False, "Invalid JSON")

        # Cek apakah ada key internal
        if isinstance(parsed, dict):
            keys = set(parsed.keys())
            matched = [k for k in JSON_INTERNAL_KEYS if k in keys]
            if matched:
                return (True, f"JSON keys={matched[:3]}")

            # Kalau gak ada key spesifik, tapi isinya JSON valid minimal 3 keys
            if len(keys) >= 3:
                return (True, f"JSON dict with {len(keys)} keys")

        return (False, "JSON valid but no internal keys")

    except Exception:
        return (False, "Parse error")


def _is_homepage_spa(body, homepage_body):
    """
    Cek apakah body identik/sangat mirip dengan homepage (indikasi SPA routing).
    Return True kalau ini false positive.
    """
    if not body or not homepage_body:
        return False

    # Cek apakah ada tag HTML utuh (SPA routing biasanya return HTML homepage)
    has_html = bool(re.search(r"<html|<!doctype", body[:500], re.IGNORECASE))
    if not has_html:
        return False

    # Bandingkan dengan homepage: kalau 80% mirip → false positive
    # Bandingkan jumlah tag dan judul
    tags_body = set(re.findall(r"<(\w+)[\s>]", body, re.IGNORECASE))
    tags_home = set(re.findall(r"<(\w+)[\s>]", homepage_body, re.IGNORECASE))

    if not tags_body or not tags_home:
        return False

    intersection = tags_body & tags_home
    union = tags_body | tags_home
    similarity = len(intersection) / len(union) if union else 0

    # Kalau >80% tag sama dengan homepage, kemungkinan besar SPA routing
    if similarity > 0.8:
        return True

    # Cek apakah title sama dengan homepage
    title_body = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
    title_home = re.search(r"<title>([^<]+)</title>", homepage_body, re.IGNORECASE)
    if title_body and title_home:
        if title_body.group(1).strip() == title_home.group(1).strip():
            return True

    return False


# ==========================================
# MAIN SCAN
# ==========================================
def scan(scanner):
    """Entry point."""
    r = scanner.get()

    if not r:
        try:
            r = requests.get(scanner.target, headers=scanner.headers,
                             timeout=15, verify=False, allow_redirects=True)
        except Exception as e:
            scanner.add_finding("A02:2025 - Security Misconfiguration", "INFO",
                                f"Tidak bisa konek: {e}")
            return

    h = r.headers
    h_lower = {k.lower(): v for k, v in h.items()}
    platform = _detect_platform(h)
    homepage_body = r.text  # Simpan baseline homepage untuk perbandingan

    scanner.add_finding(
        "A02:2025 - Security Misconfiguration", "INFO",
        f"Platform terdeteksi: {platform.upper()}",
        evidence=f"Server: {h.get('Server', 'N/A')}"
    )

    # -------- 1. SECURITY HEADERS (case-insensitive) --------
    for header, (sev, desc, rec) in HEADERS_DB.items():
        header_lower = header.lower()
        if header_lower in h_lower:
            scanner.add_finding("A02:2025 - Security Misconfiguration", "SAFE",
                                f"{header} aktif", evidence=h_lower[header_lower][:100])
        else:
            scanner.add_finding(
                "A02:2025 - Security Misconfiguration", sev,
                f"{header} HILANG ({desc})",
                mitigation=_mitigation(platform, header, rec)
            )

    # -------- 2. INFO DISCLOSURE --------
    if "server" in h_lower:
        server = h_lower["server"]
        if re.search(r"[\d\.]+", server):
            scanner.add_finding("A02:2025 - Security Misconfiguration", "LOW",
                                f"Server header bocorkan versi: {server}",
                                mitigation="Sembunyikan versi: nginx `server_tokens off;` / apache `ServerTokens Prod`")
        else:
            scanner.add_finding("A02:2025 - Security Misconfiguration", "INFO",
                                f"Server header: {server}",
                                mitigation="Sembunyikan header Server")

    if "x-powered-by" in h_lower:
        scanner.add_finding("A02:2025 - Security Misconfiguration", "LOW",
                            f"X-Powered-By bocor: {h_lower['x-powered-by']}",
                            mitigation="Hapus X-Powered-By (app.disable('x-powered-by'))")

    # -------- 3. ERROR LEAK --------
    for err_path in ["/nonexistent-th0rscan-test", "/%00", "/.env.bak"]:
        rr = scanner.get(err_path)
        if not rr:
            continue
        # Skip kalau ini SPA routing (return homepage)
        if _is_homepage_spa(rr.text, homepage_body):
            continue
        for sig in ERROR_SIGS:
            if re.search(sig, rr.text, re.IGNORECASE):
                scanner.add_finding(
                    "A02:2025 - Security Misconfiguration", "MEDIUM",
                    f"Stack trace bocor di {err_path}",
                    mitigation="Matikan debug mode di production. Custom error page.",
                    evidence=f"Signature: {sig[:60]}",
                )
                break

    # -------- 4. DIRECTORY LISTING --------
    for p in ["/images/", "/assets/", "/static/", "/backup/", "/uploads/"]:
        rr = scanner.get(p)
        if rr and "Index of /" in rr.text:
            scanner.add_finding(
                "A02:2025 - Security Misconfiguration", "MEDIUM",
                f"Directory listing aktif di {p}",
                mitigation="Nonaktifkan autoindex (nginx: `autoindex off;` / apache: `Options -Indexes`)"
            )

    # -------- 5. SENSITIVE FILES (dengan Content-Based Verification) --------
    sensitive = [
        # Generic
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/HEAD", "/.git/config",
        "/config.php", "/wp-config.php",
        "/backup.zip", "/.htaccess", "/server-status", "/.DS_Store",
        # Next.js / NPM
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/_next/static/development/_devPagesManifest.json",
        "/_next/static/development/_buildManifest.js",
        "/_next/static/chunks/webpack.js",
        "/_next/webpack-hmr",
        # Vercel / Vercel-like
        "/.vercel/project.json",
        # API docs
        "/api-docs", "/swagger.json", "/openapi.json",
    ]

    for f in sensitive:
        rr = scanner.get(f)
        if not rr or rr.status_code != 200:
            continue

        body = rr.text
        if len(body) < 10:
            continue

        # ==========================================
        # VERIFIKASI 1: Bukan homepage SPA (false positive paling umum)
        # ==========================================
        if _is_homepage_spa(body, homepage_body):
            continue  # FALSE POSITIVE — skip

        # ==========================================
        # VERIFIKASI 2: Content-based verification sesuai tipe file
        # ==========================================
        is_valid = False
        verify_evidence = ""
        severity = "MEDIUM"

        if ".env" in f:
            # Env file: harus punya pattern KEY=value
            is_valid, verify_evidence = _verify_env_content(body)
            severity = "CRITICAL"

        elif "package.json" in f or "_next" in f or "manifest" in f or "vercel" in f or "swagger" in f or "openapi" in f:
            # JSON file: harus parse JSON valid + ada key internal
            is_valid, verify_evidence = _verify_json_manifest(body, f)
            severity = "HIGH"

        elif ".git/" in f:
            # Git files: signature khas
            if f.endswith("HEAD") and (body.startswith("ref:") or "refs/heads" in body):
                is_valid = True
                verify_evidence = "Git HEAD signature"
                severity = "CRITICAL"
            elif f.endswith("config") and "[core]" in body.lower():
                is_valid = True
                verify_evidence = "Git config signature"
                severity = "CRITICAL"

        elif ".htaccess" in f:
            # .htaccess: signature khas
            if any(k in body for k in ["RewriteEngine", "Order deny", "Require all", "<IfModule"]):
                is_valid = True
                verify_evidence = ".htaccess signature"
                severity = "MEDIUM"

        elif ".DS_Store" in f:
            # .DS_Store: binary magic bytes
            if body.startswith("\x00\x00\x00\x01Bud1") or "Bud1" in body[:10]:
                is_valid = True
                verify_evidence = ".DS_Store magic bytes"
                severity = "LOW"

        elif "backup" in f.lower() and f.endswith(".zip"):
            # Backup zip: signature PK
            if body.startswith("PK\x03\x04"):
                is_valid = True
                verify_evidence = "ZIP magic bytes"
                severity = "HIGH"

        elif "server-status" in f:
            # Apache server-status signature
            if "Apache Server Status" in body:
                is_valid = True
                verify_evidence = "Apache server-status"
                severity = "HIGH"

        # ==========================================
        # REPORT kalau lolos verifikasi
        # ==========================================
        if is_valid:
            scanner.add_finding(
                "A02:2025 - Security Misconfiguration", severity,
                f"File sensitif terekspos: {f}",
                mitigation=(
                    "Blokir akses ke file konfigurasi & manifest. "
                    "Untuk Next.js, pastikan `_next/static/development/` tidak di-deploy ke production. "
                    "Untuk .env, hapus dari public folder & gunakan environment variables."
                ),
                evidence=f"HTTP 200 | Size: {len(body)} bytes | {verify_evidence}",
                url=scanner.target.rstrip("/") + f,
            )