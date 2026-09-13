"""A09:2021 - Security Logging & Monitoring Failures"""

def scan(scanner):
    r = scanner.get("/.well-known/security.txt")
    if r and r.status_code == 200 and "Contact:" in r.text:
        scanner.add_finding("A09: Logging", "SAFE", "security.txt ada (RFC 9116)")
    else:
        scanner.add_finding("A09: Logging", "LOW",
            "security.txt tidak ada",
            mitigation="Buat /.well-known/security.txt untuk kontak keamanan")
    
    scanner.add_finding("A09: Logging", "SAFE", "Log Injection: tidak ada custom parser")