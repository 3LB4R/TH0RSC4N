"""A01:2021 - Broken Access Control"""

PATHS = [
    "/admin", "/admin/", "/dashboard", "/panel", "/cpanel", "/wp-admin",
    "/phpmyadmin", "/api/admin", "/private", "/backup", "/.git/HEAD",
    "/.git/config", "/config.php", "/wp-config.php", "/server-status",
    "/.htaccess", "/web.config", "/.env", "/actuator", "/actuator/health",
    "/console", "/manager/html", "/jenkins", "/grafana",
]

def scan(scanner):
    # Admin paths
    for p in PATHS:
        r = scanner.get(p)
        if not r:
            continue
        if r.status_code == 200 and len(r.text) > 100:
            scanner.add_finding("A01: BAC", "HIGH",
                f"Akses tidak sah: {p}",
                mitigation="Batasi akses / hapus file dari deploy")
        elif r.status_code in (401, 403):
            scanner.add_finding("A01: BAC", "SAFE", f"{p} terproteksi ({r.status_code})")
    
    # IDOR
    idor_paths = ["/user/1", "/profile/1", "/api/user/1", "/document/1",
                  "/file/1", "/invoice/1", "/order/1"]
    idor_found = False
    for p in idor_paths:
        r = scanner.get(p)
        if r and r.status_code == 200 and "404" not in r.text[:500]:
            scanner.add_finding("A01: BAC", "MEDIUM",
                f"Endpoint IDOR potensial: {p}",
                mitigation="Verifikasi otorisasi objek")
            idor_found = True
    if not idor_found:
        scanner.add_finding("A01: BAC", "SAFE", "Tidak ada endpoint IDOR")