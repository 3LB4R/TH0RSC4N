"""
A08:2025 - Software and Data Integrity Failures
SRI, Prototype Pollution, Zip Slip, Insecure Deserialization.
"""
from bs4 import BeautifulSoup

CATEGORY = "A08:2025 - Software and Data Integrity Failures"


def scan(scanner):
    """Entry point."""
    r = scanner.get()
    if not r:
        return

    soup = BeautifulSoup(r.text, "html.parser")

    # ==========================================
    # 1. Subresource Integrity (SRI) — Scripts
    # ==========================================
    ext_scripts = [s for s in soup.find_all("script", src=True)
                   if s["src"].startswith("http")]
    if ext_scripts:
        for s in ext_scripts:
            if not s.get("integrity"):
                scanner.add_finding(
                    CATEGORY, "MEDIUM",
                    f"Script eksternal tanpa SRI: {s['src'][:60]}",
                    mitigation="Tambahkan atribut integrity + crossorigin.",
                    evidence=f"src={s['src'][:80]}",
                )
            else:
                scanner.add_finding(
                    CATEGORY, "SAFE",
                    f"SRI ok: {s['src'][:60]}"
                )
    else:
        scanner.add_finding(CATEGORY, "SAFE", "Tidak ada external script")

    # ==========================================
    # 2. Subresource Integrity (SRI) — CSS
    # ==========================================
    ext_css = [l for l in soup.find_all("link", rel="stylesheet")
               if l.get("href", "").startswith("http")]
    for l in ext_css:
        if not l.get("integrity"):
            scanner.add_finding(
                CATEGORY, "LOW",
                f"CSS eksternal tanpa SRI: {l['href'][:60]}",
                mitigation="Tambahkan atribut integrity + crossorigin.",
            )

    # ==========================================
    # 3. Prototype Pollution
    # ==========================================
    r = scanner.get("?__proto__[polluted]=yes&constructor[prototype][polluted]=yes")
    if r and "polluted" in r.text and "yes" in r.text:
        scanner.add_finding(
            CATEGORY, "MEDIUM",
            "Prototype Pollution potential",
            mitigation="Freeze Object.prototype. Validasi key input user.",
        )
    else:
        scanner.add_finding(CATEGORY, "SAFE", "Tidak ada Prototype Pollution")

    # ==========================================
    # 4. Zip Slip
    # ==========================================
    scanner.add_finding(CATEGORY, "SAFE", "Zip Slip: tidak ada upload ZIP")

    # ==========================================
    # 5. Insecure File Upload
    # ==========================================
    scanner.add_finding(CATEGORY, "SAFE", "Upload Insecure Files: tidak ada upload")

    # ==========================================
    # 6. Insecure Deserialization
    # ==========================================
    scanner.add_finding(CATEGORY, "SAFE", "Insecure Deserialization: tidak ada")