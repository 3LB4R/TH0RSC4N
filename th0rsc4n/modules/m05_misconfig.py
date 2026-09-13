"""A05:2021 - Security Misconfiguration"""
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HIGH", "Mencegah MITM & protocol downgrade",
        "max-age=63072000; includeSubDomains; preload"),
    "Content-Security-Policy": ("HIGH", "Mencegah XSS & code injection",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'; object-src 'none';"),
    "X-Frame-Options": ("MEDIUM", "Mencegah Clickjacking", "DENY"),
    "X-Content-Type-Options": ("MEDIUM", "Mencegah MIME sniffing", "nosniff"),
    "Referrer-Policy": ("LOW", "Kontrol kebocoran Referrer", "strict-origin-when-cross-origin"),
    "Permissions-Policy": ("LOW", "Batasi fitur browser", "camera=(), microphone=(), geolocation=()"),
}

def scan(scanner):
    # Coba 3 strategi: scanner.get() → direct requests → session
    r = scanner.get()
    if not r:
        try:
            r = requests.get(scanner.target, timeout=15, verify=True,
                           headers=scanner.headers, allow_redirects=True)
        except Exception:
            try:
                r = scanner.session.get(scanner.target, timeout=15,
                                       verify=False, allow_redirects=True)
            except Exception as e:
                scanner.add_finding("A05: Misconfig", "INFO", f"Tidak bisa konek: {e}")
                return
    
    h = r.headers
    
    for header, (severity, desc, recommended) in SECURITY_HEADERS.items():
        if header in h:
            scanner.add_finding("A05: Misconfig", "SAFE", f"{header} aktif",
                                evidence=h[header][:100])
        else:
            scanner.add_finding("A05: Misconfig", severity,
                f"{header} HILANG ({desc})",
                mitigation=f"Tambahkan '{header}: {recommended}' di vercel.json")
    
    if "Server" in h:
        scanner.add_finding("A05: Misconfig", "LOW",
            f"Server header bocor: {h['Server']}",
            mitigation="Sembunyikan header Server")
    
    if "X-Powered-By" in h:
        scanner.add_finding("A05: Misconfig", "LOW",
            f"X-Powered-By bocor: {h['X-Powered-By']}",
            mitigation="Hapus header X-Powered-By")