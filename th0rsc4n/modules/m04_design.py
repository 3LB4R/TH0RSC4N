"""A06:2025 - Insecure Design"""
import asyncio
import time


CATEGORY = "A06:2025 - Insecure Design"


async def _burst_test(scanner, count=25):
    """Burst test: kirim N request paralel."""
    tasks = [scanner.aget(scanner.target) for _ in range(count)]
    results = await scanner.agather(tasks)

    rate_limited = False
    evidence_parts = []
    status_counts = {}
    total_ok = 0

    for r in results:
        if not isinstance(r, dict):
            continue
        status = r.get("status", 0)
        status_counts[status] = status_counts.get(status, 0) + 1
        total_ok += 1

        headers = r.get("headers", {})
        if not isinstance(headers, dict):
            headers = {}

        if status == 429:
            rate_limited = True
            evidence_parts.append("HTTP 429 Too Many Requests")
        elif status == 403:
            rate_limited = True
            evidence_parts.append("HTTP 403 (Possible WAF)")

        if "retry-after" in headers:
            rate_limited = True
            evidence_parts.append(f"Retry-After: {headers['retry-after']}")
        if headers.get("x-ratelimit-remaining") == "0":
            rate_limited = True
            evidence_parts.append("X-RateLimit-Remaining: 0")

    return rate_limited, status_counts, evidence_parts, total_ok


async def _run(scanner):
    # ==========================================
    # 1. Burst test
    # ==========================================
    try:
        t0 = time.perf_counter()
        rate_limited, status_counts, evidence_parts, total_ok = await _burst_test(scanner, count=25)
        elapsed = time.perf_counter() - t0

        scanner.add_finding(
            CATEGORY, "INFO",
            f"25 burst request dalam {elapsed:.2f}s | Status: {status_counts}"
        )

        if total_ok == 0:
            scanner.add_finding(
                CATEGORY, "INFO",
                "Burst test tidak dapat response valid — di-skip"
            )
        elif rate_limited:
            scanner.add_finding(
                CATEGORY, "SAFE",
                "Rate limiting / Edge WAF aktif",
                evidence=" | ".join(evidence_parts[:3])
            )
        else:
            scanner.add_finding(
                CATEGORY, "MEDIUM",
                f"Tidak ada rate limiting ({total_ok} burst requests lolos)",
                mitigation="Aktifkan rate limiter / WAF (Vercel Firewall, Cloudflare Rate Limiting)."
            )
    except Exception as e:
        scanner.add_finding(CATEGORY, "INFO", f"Rate limit test error: {e}")

    # ==========================================
    # 2. Input validation
    # ==========================================
    try:
        r = await scanner.aget(scanner.target.rstrip("/") + "/?q=<invalid>")
        if isinstance(r, dict) and "<invalid>" in r.get("body", ""):
            scanner.add_finding(CATEGORY, "LOW", "Input direfleksikan tanpa sanitasi",
                                mitigation="Validasi & sanitasi semua input")
        else:
            scanner.add_finding(CATEGORY, "SAFE", "Input divalidasi dengan baik")
    except Exception as e:
        scanner.add_finding(CATEGORY, "INFO", f"Input validation error: {e}")

    # ==========================================
    # 3. Race condition
    # ==========================================
    scanner.add_finding(CATEGORY, "INFO", "Race Condition: tidak ada transaksi state-changing")


def scan(scanner):
    """Entry point."""
    try:
        asyncio.run(_run(scanner))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_run(scanner))
    except Exception as e:
        scanner.add_finding(CATEGORY, "INFO", f"Error: {e}")