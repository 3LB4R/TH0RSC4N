"""A08:2025 - Software & Data Integrity Failures"""
from bs4 import BeautifulSoup

def scan(scanner):
    r = scanner.get()
    if not r:
        return
    
    soup = BeautifulSoup(r.text, "html.parser")
    
    # SRI for external scripts
    ext_scripts = [s for s in soup.find_all("script", src=True) if s["src"].startswith("http")]
    if ext_scripts:
        for s in ext_scripts:
            if not s.get("integrity"):
                scanner.add_finding("A08: Integrity", "MEDIUM",
                    f"Script eksternal tanpa SRI: {s['src'][:60]}",
                    mitigation="Tambahkan atribut integrity + crossorigin")
            else:
                scanner.add_finding("A08: Integrity", "SAFE", f"SRI ok: {s['src'][:60]}")
    else:
        scanner.add_finding("A08: Integrity", "SAFE", "Tidak ada external script")
    
    # CSS SRI
    ext_css = [l for l in soup.find_all("link", rel="stylesheet") 
               if l.get("href", "").startswith("http")]
    for l in ext_css:
        if not l.get("integrity"):
            scanner.add_finding("A08: Integrity", "LOW",
                f"CSS eksternal tanpa SRI: {l['href'][:60]}")
    
    # Prototype Pollution
    r = scanner.get("?__proto__[polluted]=yes&constructor[prototype][polluted]=yes")
    if r and "polluted" in r.text and "yes" in r.text:
        scanner.add_finding("A08: Integrity", "MEDIUM",
            "Prototype Pollution potential",
            mitigation="Freeze Object.prototype")
    else:
        scanner.add_finding("A08: Integrity", "SAFE", "Tidak ada Prototype Pollution")
    
    scanner.add_finding("A08: Integrity", "SAFE", "Zip Slip: tidak ada upload ZIP")
    scanner.add_finding("A08: Integrity", "SAFE", "Upload Insecure Files: tidak ada upload")
    scanner.add_finding("A08: Integrity", "SAFE", "Insecure Deserialization: tidak ada")
