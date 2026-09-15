"""TH0RSC4N Modules Registry + Scan Modes (OWASP 2025)"""
from th0rsc4n.modules import (
    m00_tech_detect, m01_bac, m02_crypto, m03_injection, m04_design,
    m05_misconfig, m06_components, m07_auth, m08_integrity,
    m09_logging, m10_ssrf, m99_extra
)

ALL_MODULES = [
    ("M00 - Technology Fingerprinting", m00_tech_detect.scan),  # ← SEKALI SAJA
    ("A01:2025 - Broken Access Control", m01_bac.scan),
    ("A02:2025 - Security Misconfiguration", m05_misconfig.scan),
    ("A03:2025 - Software Supply Chain Failures", m06_components.scan),
    ("A04:2025 - Cryptographic Failures", m02_crypto.scan),
    ("A05:2025 - Injection", m03_injection.scan),
    ("A06:2025 - Insecure Design", m04_design.scan),
    ("A07:2025 - Authentication Failures", m07_auth.scan),
    ("A08:2025 - Software and Data Integrity Failures", m08_integrity.scan),
    ("A09:2025 - Security Logging and Alerting Failures", m09_logging.scan),
    ("A10:2025 - Mishandling of Exceptional Conditions", m10_ssrf.scan),
    ("M99 - Extra Scenarios", m99_extra.scan),
]

QUICK_MODULES = [
    ("M00 - Technology Fingerprinting", m00_tech_detect.scan),
    ("A02:2025 - Security Misconfiguration", m05_misconfig.scan),
]

NORMAL_MODULES = [
    ("M00 - Technology Fingerprinting", m00_tech_detect.scan),
    ("A01:2025 - Broken Access Control", m01_bac.scan),
    ("A02:2025 - Security Misconfiguration", m05_misconfig.scan),
    ("A03:2025 - Software Supply Chain Failures", m06_components.scan),
    ("A04:2025 - Cryptographic Failures", m02_crypto.scan),
    ("A05:2025 - Injection", m03_injection.scan),
    ("A07:2025 - Authentication Failures", m07_auth.scan),
    ("A09:2025 - Security Logging and Alerting Failures", m09_logging.scan),
    ("A10:2025 - Mishandling of Exceptional Conditions", m10_ssrf.scan),
]

DEEP_MODULES = ALL_MODULES

SCAN_MODES = {
    "quick": {"name": "QUICK", "icon": "⚡",
              "description": "Fast scan - Headers & tech detect saja (~3-5s)",
              "modules": QUICK_MODULES, "eta": "~5 detik"},
    "normal": {"name": "NORMAL", "icon": "⚙️",
               "description": "Balanced scan - OWASP Top 10 2025 inti",
               "modules": NORMAL_MODULES, "eta": "~15 detik"},
    "deep": {"name": "DEEP", "icon": "🔬",
             "description": "Full scan - Semua skenario OWASP 2025",
             "modules": DEEP_MODULES, "eta": "~60 detik"},
}


def get_modules(mode="normal"):
    return SCAN_MODES.get(mode.lower(), SCAN_MODES["normal"])["modules"]


def get_mode_info(mode):
    return SCAN_MODES.get(mode.lower(), SCAN_MODES["normal"])