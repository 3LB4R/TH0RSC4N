"""A09:2025 - Security Logging and Alerting Failures"""
import asyncio


CATEGORY = "A09:2025 - Security Logging and Alerting Failures"


async def _check_security_txt_path(scanner, path):
    """Cek security.txt di path tertentu, toleransi redirect."""
    r = await scanner.aget(scanner.target.rstrip("/") + path, allow_redirects=False)

    if not isinstance(r, dict):
        return None

    status = r.get("status", 0)

    # Direct 200
    if status == 200:
        body = r.get("body", "")
        if "Contact:" in body:
            return (True, f"HTTP 200 di {path}")

    # Redirect 301/308 — follow dan cek
    if status in (301, 302, 307, 308):
        # Follow manual redirect sekali
        location = r.get("headers", {}).get("location", "")
        if location:
            # Resolve relative URL
            from urllib.parse import urljoin
            redirect_url = urljoin(scanner.target, location)
            r2 = await scanner.aget(redirect_url)
            if isinstance(r2, dict) and r2.get("status") == 200:
                body = r2.get("body", "")
                if "Contact:" in body:
                    return (True, f"HTTP {status} → {redirect_url}")

    return None


async def _run(scanner):
    # ==========================================
    # Cek 2 path: /.well-known/security.txt dan /security.txt
    # ==========================================
    paths = ["/.well-known/security.txt", "/security.txt"]

    for path in paths:
        result = await _check_security_txt_path(scanner, path)
        if result:
            ok, evidence = result
            scanner.add_finding(
                CATEGORY, "SAFE",
                f"security.txt ditemukan (RFC 9116)",
                evidence=evidence,
            )
            break
    else:
        scanner.add_finding(
            CATEGORY, "LOW",
            "security.txt tidak ditemukan di /.well-known/ maupun /",
            mitigation="Buat /.well-known/security.txt untuk kontak keamanan (RFC 9116)."
        )

    scanner.add_finding(CATEGORY, "SAFE", "Log Injection: tidak ada custom parser")


def scan(scanner):
    """Entry point — dipanggil dari cli.py."""
    try:
        asyncio.run(_run(scanner))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_run(scanner))
    except Exception as e:
        scanner.add_finding(CATEGORY, "INFO", f"Error: {e}")