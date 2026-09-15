"""
OWASP Top 10 2025 - Module Mapping
Sentral mapping modul th0rsc4n → OWASP 2025 categories.
"""

# ==========================================
# MAPPING MODUL → OWASP 2025
# ==========================================
OWASP_2025_MAP = {
    # M00:2025 - Technology Fingerprinting (Informatif)
    "m00":              ("M00:2025", "Technology Fingerprinting"),
    "m00_tech_detect":  ("M00:2025", "Technology Fingerprinting"),
    "tech_detect":      ("M00:2025", "Technology Fingerprinting"),

    # A01:2025 - Broken Access Control
    "m01_bac":          ("A01:2025", "Broken Access Control"),
    "bac":              ("A01:2025", "Broken Access Control"),
    "idor":             ("A01:2025", "Broken Access Control"),
    "cors":             ("A01:2025", "Broken Access Control"),

    # A02:2025 - Security Misconfiguration
    "m05_misconfig":    ("A02:2025", "Security Misconfiguration"),
    "misconfig":        ("A02:2025", "Security Misconfiguration"),
    "headers":          ("A02:2025", "Security Misconfiguration"),
    "default_creds":    ("A02:2025", "Security Misconfiguration"),
    "sensitive_file":   ("A02:2025", "Security Misconfiguration"),

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
    "mixed_content":    ("A04:2025", "Cryptographic Failures"),

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

    # A08:2025 - Software and Data Integrity Failures
    "m08_integrity":    ("A08:2025", "Software and Data Integrity Failures"),
    "integrity":        ("A08:2025", "Software and Data Integrity Failures"),
    "deserialization":  ("A08:2025", "Software and Data Integrity Failures"),
    "sri":              ("A08:2025", "Software and Data Integrity Failures"),
    "prototype":        ("A08:2025", "Software and Data Integrity Failures"),

    # A09:2025 - Security Logging and Alerting Failures
    "m09_logging":      ("A09:2025", "Security Logging and Alerting Failures"),
    "logging":          ("A09:2025", "Security Logging and Alerting Failures"),
    "security_txt":     ("A09:2025", "Security Logging and Alerting Failures"),

    # A10:2025 - Mishandling of Exceptional Conditions (termasuk SSRF)
    "m10_ssrf":         ("A10:2025", "Mishandling of Exceptional Conditions"),
    "ssrf":             ("A10:2025", "Mishandling of Exceptional Conditions"),
    "m99_extra":        ("A10:2025", "Mishandling of Exceptional Conditions"),
    "error_handling":   ("A10:2025", "Mishandling of Exceptional Conditions"),
    "crash":            ("A10:2025", "Mishandling of Exceptional Conditions"),
    "exception":        ("A10:2025", "Mishandling of Exceptional Conditions"),
}


# ==========================================
# IMPACT ANALYSIS TEMPLATES
# ==========================================
IMPACT_TEMPLATES = {
    "M00:2025": "Informasi teknologi yang terdeteksi. Bukan vulnerability, hanya fingerprint.",
    "A01:2025": (
        "Broken Access Control memungkinkan attacker mengakses data atau fungsi "
        "yang seharusnya dilindungi. Dampak: kebocoran data sensitif, eskalasi "
        "privilege, IDOR, hingga full account takeover."
    ),
    "A02:2025": (
        "Security Misconfiguration memperbesar attack surface. Dampak: XSS via missing CSP, "
        "clickjacking, MIME sniffing, dan informasi arsitektur bocor."
    ),
    "A03:2025": (
        "Software Supply Chain Failures terjadi ketika komponen pihak ketiga rentan. "
        "Dampak: RCE via CVE publik, dependency confusion, kompromi build pipeline."
    ),
    "A04:2025": (
        "Cryptographic Failures mengakibatkan data sensitif terekspos. "
        "Dampak: MITM attack, session hijacking via cookie tanpa Secure/HttpOnly."
    ),
    "A05:2025": (
        "Injection memungkinkan eksekusi kode atau query arbitrary di server. "
        "Dampak: dump database, RCE, defacement, session hijacking."
    ),
    "A06:2025": (
        "Insecure Design adalah kelemahan arsitektur. Dampak: bypass rate limiting, "
        "abuse business logic, resource exhaustion, race condition."
    ),
    "A07:2025": (
        "Authentication Failures memungkinkan attacker masuk tanpa kredensial valid. "
        "Dampak: brute force, session fixation, JWT forgery, account takeover."
    ),
    "A08:2025": (
        "Software and Data Integrity Failures memungkinkan eksekusi kode via objek yang "
        "di-deserialize. Dampak: RCE, DoS via gadget chain."
    ),
    "A09:2025": (
        "Security Logging & Alerting Failures membuat serangan tidak terdeteksi. "
        "Dampak: attacker bisa persist tanpa ketahuan, forensic sulit."
    ),
    "A10:2025": (
        "Mishandling of Exceptional Conditions membuat aplikasi crash atau bocorkan "
        "informasi saat error. Dampak: DoS, stack trace leak, SSRF."
    ),
}


# ==========================================
# REMEDIATION TEMPLATES
# ==========================================
REMEDIATION_TEMPLATES = {
    "M00:2025": "Tidak ada aksi — ini hanya laporan informasi teknologi.",
    "A01:2025": (
        "1. Implementasikan otorisasi per-objek. "
        "2. Jangan pakai ID langsung dari user. "
        "3. Whitelist endpoint admin dengan autentikasi kuat. "
        "4. Batasi CORS ke domain spesifik."
    ),
    "A02:2025": (
        "1. Set security headers: HSTS, CSP ketat, X-Frame-Options=DENY, "
        "X-Content-Type-Options=nosniff, Referrer-Policy, Permissions-Policy. "
        "2. Nonaktifkan directory listing. "
        "3. Matikan debug mode & custom error page."
    ),
    "A03:2025": (
        "1. Update semua dependency ke versi terbaru (npm audit / pip-audit). "
        "2. Gunakan SCA di CI/CD. "
        "3. Lock file di-commit. "
        "4. SRI untuk script eksternal."
    ),
    "A04:2025": (
        "1. Paksa HTTPS dengan HSTS + redirect 301. "
        "2. Nonaktifkan TLS 1.0/1.1 & cipher lemah. "
        "3. Set cookie flags: Secure, HttpOnly, SameSite=Strict."
    ),
    "A05:2025": (
        "1. Prepared Statements / Parameterized Queries untuk SQL. "
        "2. Validasi & escape output (HTML escape, CSP). "
        "3. Jangan pass input user ke shell."
    ),
    "A06:2025": (
        "1. Threat modeling sejak fase design. "
        "2. Implementasikan rate limiting per-IP & per-user. "
        "3. Batasi resource (timeout, memory)."
    ),
    "A07:2025": (
        "1. Wajib MFA untuk akun sensitif. "
        "2. Rate limit login (5 attempt/menit) + captcha + lockout. "
        "3. Password hashing: bcrypt / argon2."
    ),
    "A08:2025": (
        "1. Jangan deserialize data dari user input. "
        "2. Whitelist class yang boleh di-deserialize. "
        "3. Gunakan format aman: JSON, Protobuf."
    ),
    "A09:2025": (
        "1. Log semua event: login, akses admin, error, injection attempt. "
        "2. Centralize log (SIEM/ELK). "
        "3. Alert real-time untuk anomali."
    ),
    "A10:2025": (
        "1. Custom error page — jangan bocorkan stack trace. "
        "2. Debug mode OFF di production. "
        "3. Blokir SSRF: whitelist URL, blokir IP internal. "
        "4. Circuit breaker untuk dependency eksternal."
    ),
}


def get_owasp_2025(module_name: str) -> tuple:
    """Ambil mapping OWASP 2025 dari nama modul."""
    if not module_name:
        return ("M00:2025", "Technology Fingerprinting")

    key = module_name.lower().replace(".py", "").strip()

    # Cek M00 dulu
    if "m00" in key or "tech" in key or "fingerprint" in key:
        return ("M00:2025", "Technology Fingerprinting")

    return OWASP_2025_MAP.get(key, ("A10:2025", "Mishandling of Exceptional Conditions"))


def get_impact(code: str) -> str:
    return IMPACT_TEMPLATES.get(code, "Dampak: kelemahan keamanan yang perlu diperbaiki segera.")


def get_remediation(code: str) -> str:
    return REMEDIATION_TEMPLATES.get(code, "Lakukan security review & follow OWASP guidelines.")