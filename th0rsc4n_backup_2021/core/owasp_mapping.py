"""
OWASP Top 10 2025 - Module Mapping
Sentral mapping modul th0rsc4n → OWASP 2025 categories.
"""

# ==========================================
# MAPPING MODUL → OWASP 2025
# ==========================================
OWASP_2025_MAP = {
    # A01:2025 - Broken Access Control
    "m01_bac":          ("A01:2025", "Broken Access Control"),
    "m10_ssrf":         ("A01:2025", "Broken Access Control"),
    "bac":              ("A01:2025", "Broken Access Control"),
    "ssrf":             ("A01:2025", "Broken Access Control"),
    "idor":             ("A01:2025", "Broken Access Control"),
    "cors":             ("A01:2025", "Broken Access Control"),

    # A02:2025 - Security Misconfiguration
    "m05_misconfig":    ("A02:2025", "Security Misconfiguration"),
    "misconfig":        ("A02:2025", "Security Misconfiguration"),
    "headers":          ("A02:2025", "Security Misconfiguration"),
    "default_creds":    ("A02:2025", "Security Misconfiguration"),

    # A03:2025 - Software Supply Chain Failures
    "m06_components":   ("A03:2025", "Software Supply Chain Failures"),
    "components":       ("A03:2025", "Software Supply Chain Failures"),
    "cve":              ("A03:2025", "Software Supply Chain Failures"),
    "outdated":         ("A03:2025", "Software Supply Chain Failures"),

    # A04:2025 - Cryptographic Failures
    "m02_crypto":       ("A04:2025", "Cryptographic Failures"),
    "crypto":           ("A04:2025", "Cryptographic Failures"),
    "tls":              ("A04:2025", "Cryptographic Failures"),
    "cookies":          ("A04:2025", "Cryptographic Failures"),
    "weak_crypto":      ("A04:2025", "Cryptographic Failures"),

    # A05:2025 - Injection
    "m03_injection":    ("A05:2025", "Injection"),
    "injection":        ("A05:2025", "Injection"),
    "sqli":             ("A05:2025", "Injection"),
    "xss":              ("A05:2025", "Injection"),
    "cmdi":             ("A05:2025", "Injection"),
    "ssti":             ("A05:2025", "Injection"),
    "nosqli":           ("A05:2025", "Injection"),
    "xxe":              ("A05:2025", "Injection"),

    # A06:2025 - Insecure Design
    "m04_design":       ("A06:2025", "Insecure Design"),
    "design":           ("A06:2025", "Insecure Design"),
    "rate_limit":       ("A06:2025", "Insecure Design"),
    "business_logic":   ("A06:2025", "Insecure Design"),

    # A07:2025 - Authentication Failures
    "m07_auth":         ("A07:2025", "Authentication Failures"),
    "auth":             ("A07:2025", "Authentication Failures"),
    "jwt":              ("A07:2025", "Authentication Failures"),
    "session":          ("A07:2025", "Authentication Failures"),
    "bruteforce":       ("A07:2025", "Authentication Failures"),

    # A08:2025 - Insecure Deserialization
    "m08_integrity":    ("A08:2025", "Insecure Deserialization"),
    "integrity":        ("A08:2025", "Insecure Deserialization"),
    "deserialization":  ("A08:2025", "Insecure Deserialization"),
    "sri":              ("A08:2025", "Insecure Deserialization"),

    # A09:2025 - Security Logging and Alerting Failures
    "m09_logging":      ("A09:2025", "Security Logging and Alerting Failures"),
    "logging":          ("A09:2025", "Security Logging and Alerting Failures"),
    "security_txt":     ("A09:2025", "Security Logging and Alerting Failures"),

    # A10:2025 - Mishandling of Exceptional Conditions
    "m99_extra":        ("A10:2025", "Mishandling of Exceptional Conditions"),
    "error_handling":   ("A10:2025", "Mishandling of Exceptional Conditions"),
    "crash":            ("A10:2025", "Mishandling of Exceptional Conditions"),
    "exception":        ("A10:2025", "Mishandling of Exceptional Conditions"),
}


# ==========================================
# IMPACT ANALYSIS TEMPLATES
# ==========================================
IMPACT_TEMPLATES = {
    "A01:2025": (
        "Broken Access Control memungkinkan attacker mengakses data atau fungsi "
        "yang seharusnya dilindungi. Dampak: kebocoran data sensitif, eskalasi "
        "privilege, manipulasi objek milik user lain (IDOR), SSRF ke internal "
        "network, hingga full account takeover."
    ),
    "A02:2025": (
        "Security Misconfiguration memperbesar attack surface karena server "
        "mengekspos informasi internal, headers tidak aman, atau default credentials. "
        "Dampak: XSS via missing CSP, clickjacking, MIME sniffing, dan informasi "
        "arsitektur bocor ke publik."
    ),
    "A03:2025": (
        "Software Supply Chain Failures terjadi ketika komponen pihak ketiga "
        "rentan/outdated dipakai. Dampak: RCE via CVE publik, dependency confusion, "
        "kompromi build pipeline, dan eksekusi kode arbitrary di server."
    ),
    "A04:2025": (
        "Cryptographic Failures mengakibatkan data sensitif terekspos dalam "
        "plaintext atau dengan enkripsi lemah. Dampak: MITM attack, session "
        "hijacking via cookie tanpa Secure/HttpOnly, dan kebocoran kredensial."
    ),
    "A05:2025": (
        "Injection (SQLi/NoSQLi/CMDi/SSTI/XSS) memungkinkan eksekusi kode atau "
        "query arbitrary di server. Dampak: dump database, RCE, defacement, "
        "session hijacking, hingga full server compromise."
    ),
    "A06:2025": (
        "Insecure Design adalah kelemahan arsitektur yang tidak bisa diperbaiki "
        "hanya dengan coding. Dampak: bypass rate limiting, abuse business logic, "
        "resource exhaustion, dan race condition pada transaksi kritikal."
    ),
    "A07:2025": (
        "Authentication Failures memungkinkan attacker masuk tanpa kredensial "
        "valid. Dampak: brute force berhasil, session fixation, JWT forgery, "
        "credential stuffing, dan account takeover."
    ),
    "A08:2025": (
        "Insecure Deserialization memungkinkan eksekusi kode via objek yang "
        "di-deserialize. Dampak: RCE, DoS via gadget chain, dan kompromi sistem "
        "dari input user biasa."
    ),
    "A09:2025": (
        "Security Logging & Alerting Failures membuat serangan tidak terdeteksi. "
        "Dampak: attacker bisa persist di sistem tanpa ketahuan, forensic jadi "
        "sulit, dan incident response terlambat."
    ),
    "A10:2025": (
        "Mishandling of Exceptional Conditions membuat aplikasi crash atau bocorkan "
        "informasi saat terjadi error. Dampak: DoS, stack trace leak, informasi "
        "internal terekspos, dan aplikasi tidak resilien."
    ),
}


# ==========================================
# REMEDIATION TEMPLATES
# ==========================================
REMEDIATION_TEMPLATES = {
    "A01:2025": (
        "1. Implementasikan otorisasi per-objek (verifikasi kepemilikan resource). "
        "2. Jangan pakai ID langsung dari user — gunakan UUID acak. "
        "3. Whitelist endpoint admin dengan autentikasi kuat + IP whitelist. "
        "4. Batasi CORS: ACAO harus domain spesifik, jangan wildcard dengan credentials. "
        "5. Blokir request ke IP internal/loopback (khusus SSRF) via whitelist domain."
    ),
    "A02:2025": (
        "1. Set security headers: HSTS, CSP ketat, X-Frame-Options=DENY, "
        "X-Content-Type-Options=nosniff, Referrer-Policy, Permissions-Policy. "
        "2. Nonaktifkan directory listing (autoindex off / Options -Indexes). "
        "3. Ubah default credentials & hapus panel admin yang tidak dipakai. "
        "4. Matikan debug mode & custom error page. "
        "5. Sembunyikan versi server (ServerTokens Prod / server_tokens off)."
    ),
    "A03:2025": (
        "1. Update semua dependency ke versi terbaru (npm audit / pip-audit). "
        "2. Gunakan SCA (Software Composition Analysis) di CI/CD. "
        "3. Lock file (package-lock.json / poetry.lock) di-commit. "
        "4. Subresource Integrity (SRI) untuk script eksternal. "
        "5. Verifikasi signature package sebelum install."
    ),
    "A04:2025": (
        "1. Paksa HTTPS dengan HSTS + redirect 301. "
        "2. Nonaktifkan TLS 1.0/1.1 & cipher lemah (RC4, DES, MD5). "
        "3. Set cookie flags: Secure, HttpOnly, SameSite=Strict. "
        "4. Jangan simpan data sensitif di plaintext — gunakan AES-256 / bcrypt. "
        "5. Gunakan HSTS preload untuk domain produksi."
    ),
    "A05:2025": (
        "1. Prepared Statements / Parameterized Queries untuk SQL. "
        "2. Validasi & escape output (HTML escape, CSP). "
        "3. Jangan pass input user ke shell — gunakan API spesifik. "
        "4. Sanitasi template input (SSTI). "
        "5. Untuk NoSQL: validasi tipe data, tolak operator ($, {})."
    ),
    "A06:2025": (
        "1. Threat modeling sejak fase design. "
        "2. Implementasikan rate limiting per-IP & per-user. "
        "3. Batasi resource (timeout, memory, query complexity). "
        "4. Gunakan transaction + locking untuk race condition. "
        "5. Audit business logic dengan test case abuse scenario."
    ),
    "A07:2025": (
        "1. Wajib MFA untuk akun sensitif. "
        "2. Rate limit login (5 attempt/menit) + captcha + account lockout. "
        "3. Password hashing: bcrypt / argon2. "
        "4. Session: regenerate ID setelah login, timeout idle 15 menit. "
        "5. JWT: verifikasi signature + algorithm whitelist (tolak 'none')."
    ),
    "A08:2025": (
        "1. Jangan deserialize data dari user input. "
        "2. Whitelist class yang boleh di-deserialize. "
        "3. Gunakan format aman: JSON, Protobuf (bukan pickle / Java serialized). "
        "4. Signature verification untuk update/plugin. "
        "5. Isolasi proses deserialization di sandbox."
    ),
    "A09:2025": (
        "1. Log semua event: login, akses admin, error, injection attempt. "
        "2. Centralize log (SIEM/ELK) — jangan disimpan lokal server. "
        "3. Alert real-time untuk anomali (multiple 401, injection pattern). "
        "4. Buat /.well-known/security.txt untuk kontak keamanan. "
        "5. Audit log integrity (append-only / signed)."
    ),
    "A10:2025": (
        "1. Custom error page — jangan bocorkan stack trace. "
        "2. Debug mode OFF di production. "
        "3. Try/except di semua I/O operation. "
        "4. Circuit breaker untuk dependency eksternal. "
        "5. Graceful degradation saat service down."
    ),
}


def get_owasp_2025(module_name: str) -> tuple:
    """
    Ambil mapping OWASP 2025 dari nama modul.
    Return (code, category) atau default A10.
    """
    if not module_name:
        return ("A10:2025", "Mishandling of Exceptional Conditions")
    key = module_name.lower().replace(".py", "").strip()
    return OWASP_2025_MAP.get(key, ("A10:2025", "Mishandling of Exceptional Conditions"))


def get_impact(code: str) -> str:
    """Ambil impact analysis berdasarkan kode OWASP."""
    return IMPACT_TEMPLATES.get(code, "Dampak: kelemahan keamanan yang perlu diperbaiki segera.")


def get_remediation(code: str) -> str:
    """Ambil remediation steps berdasarkan kode OWASP."""
    return REMEDIATION_TEMPLATES.get(code, "Lakukan security review & follow OWASP guidelines.")
