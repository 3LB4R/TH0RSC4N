"""
A05:2021 - Security Misconfiguration
Adaptive + verbose error leak detection.
"""
import re
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


def scan(scanner):
    """Entry point."""
    r = scanner.get()

    if not r:
        # Fallback: pakai requests langsung
        try:
            r = requests.get(scanner.target, headers=scanner.headers,
                             timeout=15, verify=False, allow_redirects=True)
        except Exception as e:
            scanner.add_finding("A05: Misconfig", "INFO", f"Tidak bisa konek: {e}")
            return

    h = r.headers
    h_lower = {k.lower(): v for k, v in h.items()}
    platform = _detect_platform(h)

    scanner.add_finding(
        "A05: Misconfig", "INFO",
        f"Platform terdeteksi: {platform.upper()}",
        evidence=f"Server: {h.get('Server', 'N/A')}"
    )

    # -------- 1. SECURITY HEADERS --------
    for header, (sev, desc, rec) in HEADERS_DB.items():
        if header in h:
            scanner.add_finding("A05: Misconfig", "SAFE", f"{header} aktif",
                                evidence=h[header][:100])
        else:
            scanner.add_finding(
                "A05: Misconfig", sev,
                f"{header} HILANG ({desc})",
                mitigation=_mitigation(platform, header, rec)
            )

    # -------- 2. INFO DISCLOSURE --------
    if "server" in h_lower:
        server = h_lower["server"]
        # Cek apakah versi bocor
        if re.search(r"[\d\.]+", server):
            scanner.add_finding("A05: Misconfig", "LOW",
                                f"Server header bocorkan versi: {server}",
                                mitigation="Sembunyikan versi: nginx `server_tokens off;` / apache `ServerTokens Prod`")
        else:
            scanner.add_finding("A05: Misconfig", "INFO",
                                f"Server header: {server}",
                                mitigation="Sembunyikan header Server")

    if "x-powered-by" in h_lower:
        scanner.add_finding("A05: Misconfig", "LOW",
                            f"X-Powered-By bocor: {h_lower['x-powered-by']}",
                            mitigation="Hapus X-Powered-By (app.disable('x-powered-by'))")

    # -------- 3. ERROR LEAK --------
    for err_path in ["/nonexistent-th0rscan-test", "/%00", "/.env.bak"]:
        rr = scanner.get(err_path)
        if not rr:
            continue
        # Cek signature di response error
        for sig in ERROR_SIGS:
            if re.search(sig, rr.text, re.IGNORECASE):
                scanner.add_finding(
                    "A05: Verbose Error Leak", "MEDIUM",
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
                "A05: Misconfig", "MEDIUM",
                f"Directory listing aktif di {p}",
                mitigation="Nonaktifkan autoindex (nginx: `autoindex off;` / apache: `Options -Indexes`)"
            )

    # -------- 5. SENSITIVE FILES --------
        # -------- 5. SENSITIVE FILES (termasuk Next.js/Turbopack) --------
    sensitive = [
        # Generic
        "/.env", "/.git/HEAD", "/config.php", "/wp-config.php",
        "/backup.zip", "/.htaccess", "/server-status", "/.DS_Store",
        "/package.json", "/package-lock.json", "/yarn.lock",
        # Next.js / Turbopack
        "/_next/static/development/_devPagesManifest.json",
        "/_next/static/development/_buildManifest.js",
        "/_next/static/chunks/webpack.js",
        "/_next/webpack-hmr",
        # Vercel
        "/.vercel/project.json",
        # Common API docs
        "/api-docs", "/swagger.json", "/openapi.json",
    ]
    for f in sensitive:
        rr = scanner.get(f)
        if rr and rr.status_code == 200 and len(rr.text) > 10:
            # Cek konten JSON (kemungkinan leak struktur)
            body = rr.text[:500]
            is_json = body.strip().startswith(("{", "["))
            is_manifest = "_next" in f or "package.json" in f

            severity = "HIGH" if is_json or is_manifest else "MEDIUM"
            scanner.add_finding(
                f"A05: Sensitive File ({severity})", severity,
                f"File sensitif terekspos: {f}",
                mitigation="Blokir akses ke file konfigurasi & manifest. Untuk Next.js, pastikan `_next/static/development/` tidak di-deploy ke production.",
                evidence=f"HTTP 200 | Size: {len(rr.text)} bytes | JSON: {is_json}"
            )