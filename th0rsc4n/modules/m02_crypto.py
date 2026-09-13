"""A02:2021 - Cryptographic Failures"""
import ssl
import socket
import re
from urllib.parse import urlparse

def scan(scanner):
    # HTTPS check - cek target URL langsung, bukan response URL
    if scanner.target.startswith("https://"):
        scanner.add_finding("A02: Crypto", "SAFE", "HTTPS aktif")
    else:
        scanner.add_finding("A02: Crypto", "CRITICAL", "Tidak pakai HTTPS!",
                            mitigation="Aktifkan Force HTTPS")
    
    r = scanner.get()  # tetap ambil response untuk mixed content check
    
    # TLS Version
    try:
        host = urlparse(scanner.target).hostname
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=scanner.timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                v = ss.version()
                cipher = ss.cipher()
                scanner.add_finding("A02: Crypto", "INFO", f"TLS: {v} | Cipher: {cipher[0]}")
                if v in ("TLSv1.2", "TLSv1.3"):
                    scanner.add_finding("A02: Crypto", "SAFE", "TLS modern")
                else:
                    scanner.add_finding("A02: Crypto", "HIGH",
                        f"TLS versi lama: {v}",
                        mitigation="Upgrade TLS 1.2+")
    except Exception as e:
        scanner.add_finding("A02: Crypto", "INFO", f"TLS check skip: {e}")
    
    # SSL Valid
    try:
        import requests
        requests.get(scanner.target, verify=True, timeout=scanner.timeout)
        scanner.add_finding("A02: Crypto", "SAFE", "SSL Certificate valid")
    except:
        scanner.add_finding("A02: Crypto", "HIGH", "SSL Certificate tidak valid!")
    
    # Mixed content
    if r:
        raw = re.findall(r'http://[^\s"\'<>]+', r.text)
        real = [u for u in raw if not any(x in u for x in ["w3.org", "schemas.", "xmlns"])]
        if real:
            scanner.add_finding("A02: Crypto", "MEDIUM",
                f"Mixed Content: {len(real)} resource HTTP",
                mitigation="Ganti semua ke HTTPS")
        else:
            scanner.add_finding("A02: Crypto", "SAFE", "Tidak ada Mixed Content")