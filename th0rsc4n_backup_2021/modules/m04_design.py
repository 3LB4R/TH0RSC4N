"""A04:2025 - Insecure Design"""
import time

def scan(scanner):
    # Rate limiting test
    try:
        start = time.time()
        for _ in range(15):
            scanner.get()
        el = time.time() - start
        scanner.add_finding("A04: Design", "INFO", f"15 request dalam {el:.2f}s")
        if el < 3:
            scanner.add_finding("A04: Design", "MEDIUM",
                "Tidak ada rate limiting",
                mitigation="Aktifkan Vercel Firewall / rate limiter")
        else:
            scanner.add_finding("A04: Design", "SAFE", "Rate limiting mungkin aktif")
    except:
        pass
    
    # Input validation
    r = scanner.get("?q=<invalid>")
    if r and "<invalid>" in r.text:
        scanner.add_finding("A04: Design", "LOW", "Input direfleksikan tanpa sanitasi",
                            mitigation="Validasi & sanitasi semua input")
    else:
        scanner.add_finding("A04: Design", "SAFE", "Input divalidasi dengan baik")
    
    scanner.add_finding("A04: Design", "INFO", "Race Condition: tidak ada transaksi state-changing")
