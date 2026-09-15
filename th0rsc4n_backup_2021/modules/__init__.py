"""TH0RSC4N Modules Registry + Scan Modes"""
from th0rsc4n.modules import (
    m00_tech_detect, m01_bac, m02_crypto, m03_injection, m04_design, m05_misconfig,
    m06_components, m07_auth, m08_integrity, m09_logging, m10_ssrf, m99_extra
)

# ==========================================
# SEMUA MODUL (untuk DEEP mode)
# ==========================================
ALL_MODULES = [
    ("M00 - Technology Fingerprinting", m00_tech_detect.scan),
    ("A01:2025 - Broken Access Control", m01_bac.scan),
    ("A02:2025 - Cryptographic Failures", m02_crypto.scan),
    ("A03:2025 - Injection", m03_injection.scan),
    ("A04:2025 - Insecure Design", m04_design.scan),
    ("A05:2025 - Security Misconfiguration", m05_misconfig.scan),
    ("A06:2025 - Vulnerable Components", m06_components.scan),
    ("A07:2025 - Auth Failures", m07_auth.scan),
    ("A08:2025 - Integrity Failures", m08_integrity.scan),
    ("A09:2025 - Logging Failures", m09_logging.scan),
    ("A10:2025 - SSRF", m10_ssrf.scan),
    ("M99 - Extra Scenarios", m99_extra.scan),
]

# ==========================================
# QUICK MODE - ~5 detik
# ==========================================
QUICK_MODULES = [
    ("M00 - Technology Fingerprinting", m00_tech_detect.scan),
    ("A05:2025 - Security Misconfiguration", m05_misconfig.scan),
    ("A09:2025 - Logging Failures", m09_logging.scan),
    ("M99 - Quick Checks", m99_extra.scan),
]

# ==========================================
# NORMAL MODE - ~15 detik (default)
# ==========================================
NORMAL_MODULES = [
    ("M00 - Technology Fingerprinting", m00_tech_detect.scan),
    ("A01:2025 - Broken Access Control", m01_bac.scan),
    ("A02:2025 - Cryptographic Failures", m02_crypto.scan),
    ("A03:2025 - Injection", m03_injection.scan),
    ("A05:2025 - Security Misconfiguration", m05_misconfig.scan),
    ("A06:2025 - Vulnerable Components", m06_components.scan),
    ("A07:2025 - Auth Failures", m07_auth.scan),
    ("A09:2025 - Logging Failures", m09_logging.scan),
    ("M99 - Extra Scenarios", m99_extra.scan),
]

# ==========================================
# DEEP MODE - ~60 detik (semua)
# ==========================================
DEEP_MODULES = ALL_MODULES

# ==========================================
# MODE REGISTRY
# ==========================================
SCAN_MODES = {
    "quick": {
        "name": "QUICK",
        "icon": "⚡",
        "description": "Fast scan - Security headers & critical checks",
        "modules": QUICK_MODULES,
        "eta": "~5 detik",
    },
    "normal": {
        "name": "NORMAL",
        "icon": "⚙️",
        "description": "Balanced scan - OWASP Top 10 inti",
        "modules": NORMAL_MODULES,
        "eta": "~15 detik",
    },
    "deep": {
        "name": "DEEP",
        "icon": "🔬",
        "description": "Full scan - Semua 80+ skenario OWASP + Extra",
        "modules": DEEP_MODULES,
        "eta": "~60 detik",
    },
}


def get_modules(mode="normal"):
    """Ambil daftar modul berdasarkan mode."""
    return SCAN_MODES.get(mode.lower(), SCAN_MODES["normal"])["modules"]


def get_mode_info(mode):
    """Ambil info mode."""
    return SCAN_MODES.get(mode.lower(), SCAN_MODES["normal"])
