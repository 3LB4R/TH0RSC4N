"""A10:2021 - Server-Side Request Forgery (SSRF)"""

SSRF_PAYLOADS = [
    "http://localhost:80", "http://127.0.0.1:80",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd", "gopher://localhost:80",
]
PARAMS = ["url", "uri", "path", "src", "dest", "redirect", "proxy", "fetch", "callback", "image"]

def scan(scanner):
    found = False
    for p in PARAMS:
        for pl in SSRF_PAYLOADS:
            r = scanner.get(f"?{p}={pl}")
            if r and ("root:" in r.text or "ami-id" in r.text):
                scanner.add_finding("A10: SSRF", "CRITICAL",
                    f"SSRF di '{p}'",
                    mitigation="Whitelist URL, blokir IP internal")
                found = True
    if not found:
        scanner.add_finding("A10: SSRF", "SAFE", "Tidak ada SSRF")
    
    # Request Smuggling
    r = scanner.post(headers={"Content-Length": "6", "Transfer-Encoding": "chunked"},
                     data="0\r\n\r\nG")
    if r and r.status_code in (400, 501):
        scanner.add_finding("A10: SSRF", "SAFE", "Request Smuggling ditolak")
    else:
        scanner.add_finding("A10: SSRF", "SAFE", "Request Smuggling tidak applicable")