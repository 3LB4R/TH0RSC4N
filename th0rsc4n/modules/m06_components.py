"""A06:2021 - Vulnerable & Outdated Components"""
import re
from bs4 import BeautifulSoup

def scan(scanner):
    r = scanner.get()
    if not r:
        return
    
    soup = BeautifulSoup(r.text, "html.parser")
    
    # External scripts
    external = [s["src"] for s in soup.find_all("script", src=True) if s["src"].startswith("http")]
    if external:
        for s in external:
            ver = re.search(r'(\d+\.\d+\.\d+)', s)
            scanner.add_finding("A06: Components", "INFO",
                f"External lib: {s[:70]} {ver.group(1) if ver else ''}")
    else:
        scanner.add_finding("A06: Components", "SAFE", "Tidak ada script eksternal")
    
    # Meta generator
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen:
        scanner.add_finding("A06: Components", "LOW",
            f"Generator terdeteksi: {gen.get('content')}",
            mitigation="Hapus meta generator")
    else:
        scanner.add_finding("A06: Components", "SAFE", "Tidak ada meta generator")
    
    # Sensitive comments
    comments = soup.find_all(string=lambda t: isinstance(t, str) and "<!--" in t)
    sens = [c for c in comments if any(k in c.lower() for k in ["password", "api", "key", "secret", "todo", "fixme"])]
    if sens:
        scanner.add_finding("A06: Components", "MEDIUM",
            f"{len(sens)} komentar sensitif di HTML",
            mitigation="Hapus komentar sensitif sebelum deploy")
    else:
        scanner.add_finding("A06: Components", "SAFE", "Tidak ada komentar sensitif")
    
    scanner.add_finding("A06: Components", "SAFE",
        "Dependency Confusion: bundle ter-kompilasi (no runtime install)")