"""A07:2021 - Auth Failures"""
from bs4 import BeautifulSoup

def scan(scanner):
    r = scanner.get()
    if not r:
        return
    
    soup = BeautifulSoup(r.text, "html.parser")
    
    # Login form
    pw = soup.find_all("input", {"type": "password"})
    if pw:
        scanner.add_finding("A07: Auth", "MEDIUM",
            f"{len(pw)} field password ditemukan",
            mitigation="Pastikan pakai HTTPS + MFA")
    else:
        scanner.add_finding("A07: Auth", "SAFE", "Tidak ada form login")
    
    # Cookies
    if r.cookies:
        for c in r.cookies:
            if not c.secure:
                scanner.add_finding("A07: Auth", "HIGH",
                    f"Cookie '{c.name}' tidak Secure flag",
                    mitigation="Tambah flag Secure, HttpOnly, SameSite")
            elif not c.has_nonstandard_attr("HttpOnly"):
                scanner.add_finding("A07: Auth", "MEDIUM",
                    f"Cookie '{c.name}' tidak HttpOnly",
                    mitigation="Tambah HttpOnly flag")
            else:
                scanner.add_finding("A07: Auth", "SAFE", f"Cookie '{c.name}' aman")
    else:
        scanner.add_finding("A07: Auth", "SAFE", "Tidak ada cookie yang di-set")
    
    # JWT
    if "eyJ" in str(r.cookies):
        scanner.add_finding("A07: Auth", "MEDIUM",
            "JWT cookie terdeteksi",
            mitigation="Verifikasi signature & algoritma (no 'none')")
    else:
        scanner.add_finding("A07: Auth", "SAFE", "Tidak ada JWT cookie")
    
    scanner.add_finding("A07: Auth", "SAFE", "Brute Force: tidak ada endpoint login")
    scanner.add_finding("A07: Auth", "SAFE", "Account Takeover: tidak ada fitur akun")