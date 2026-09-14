"""
A06:2021 - Vulnerable and Outdated Components
Deteksi teknologi + versi, cocokkan dengan CVE umum.
"""
import re
from bs4 import BeautifulSoup

# CVE database ringan (versi rentan)
KNOWN_VULNS = {
    "Next.js": {
        "vulnerable_below": "13.5.1",
        "cves": ["CVE-2023-46298 (DoS)", "CVE-2024-34351 (SSRF)"],
    },
    "React": {
        "vulnerable_below": "18.2.0",
        "cves": ["CVE-2024-XXXX (XSS di server components)"],
    },
    "Vue.js": {
        "vulnerable_below": "3.4.0",
        "cves": ["CVE-2023-XXXX"],
    },
    "Express": {
        "vulnerable_below": "4.19.2",
        "cves": ["CVE-2024-29041 (Open Redirect)"],
    },
    "jQuery": {
        "vulnerable_below": "3.5.0",
        "cves": ["CVE-2020-11022 (XSS)", "CVE-2020-11023 (XSS)"],
    },
    "Bootstrap": {
        "vulnerable_below": "5.2.0",
        "cves": ["CVE-2024-XXXX (XSS di tooltip)"],
    },
    "Lodash": {
        "vulnerable_below": "4.17.21",
        "cves": ["CVE-2021-23337 (Command Injection)", "CVE-2020-8203 (Prototype Pollution)"],
    },
}


def _version_tuple(v):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    except:
        return (0, 0, 0)


def scan(scanner):
    """Entry point."""
    r = scanner.get()
    if not r:
        return
    
    soup = BeautifulSoup(r.text, "html.parser")
    headers = {k.lower(): v for k, v in r.headers.items()}
    
    detected = []
    
    # Detect dari headers
    if "server" in headers:
        server = headers["server"]
        m = re.search(r"([a-zA-Z\-]+)/(\d+\.\d+(?:\.\d+)?)", server)
        if m:
            detected.append({"name": m.group(1), "version": m.group(2), "source": "Server header"})
    
    if "x-powered-by" in headers:
        powered = headers["x-powered-by"]
        m = re.search(r"([a-zA-Z\.]+)\s*/?\s*(\d+\.\d+(?:\.\d+)?)?", powered)
        if m:
            detected.append({"name": m.group(1), "version": m.group(2) or "unknown", "source": "X-Powered-By"})
    
    # Detect dari script tags
    for script in soup.find_all("script", src=True):
        src = script["src"]
        # jQuery
        m = re.search(r"jquery[.\-](\d+\.\d+\.\d+)", src, re.I)
        if m:
            detected.append({"name": "jQuery", "version": m.group(1), "source": "script src"})
        # React
        m = re.search(r"react[.\-](\d+\.\d+\.\d+)", src, re.I)
        if m:
            detected.append({"name": "React", "version": m.group(1), "source": "script src"})
        # Vue
        m = re.search(r"vue[.\-](\d+\.\d+\.\d+)", src, re.I)
        if m:
            detected.append({"name": "Vue.js", "version": m.group(1), "source": "script src"})
        # Bootstrap
        m = re.search(r"bootstrap[.\-](\d+\.\d+\.\d+)", src, re.I)
        if m:
            detected.append({"name": "Bootstrap", "version": m.group(1), "source": "script src"})
        # Lodash
        m = re.search(r"lodash[.\-](\d+\.\d+\.\d+)", src, re.I)
        if m:
            detected.append({"name": "Lodash", "version": m.group(1), "source": "script src"})
    
    # Detect dari meta generator
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen:
        content = gen.get("content", "")
        m = re.search(r"([a-zA-Z]+)\s*(\d+\.\d+(?:\.\d+)?)?", content)
        if m:
            detected.append({
                "name": m.group(1),
                "version": m.group(2) or "unknown",
                "source": "meta generator",
            })
        scanner.add_finding(
            "A06: Components", "LOW",
            f"Meta generator bocor: {content}",
            mitigation="Hapus meta generator dari HTML"
        )
    
    # Sensitive comments
    comments = soup.find_all(string=lambda t: isinstance(t, str) and "<!--" in t)
    sens = [c for c in comments if any(k in c.lower() for k in 
            ["password", "api_key", "secret", "todo", "fixme", "token"])]
    if sens:
        scanner.add_finding(
            "A06: Components", "MEDIUM",
            f"{len(sens)} komentar sensitif ditemukan di HTML",
            mitigation="Hapus komentar yang mengandung info sensitif sebelum deploy"
        )
    else:
        scanner.add_finding("A06: Components", "SAFE", "Tidak ada komentar sensitif")
    
    # Report detected tech
    if not detected:
        scanner.add_finding("A06: Components", "SAFE", 
                            "Tidak ada library eksternal dengan versi terekspos")
        return
    
    for tech in detected:
        name = tech["name"]
        version = tech["version"]
        source = tech["source"]
        
        # Cek CVE
        vuln = KNOWN_VULNS.get(name)
        if vuln and version != "unknown":
            if _version_tuple(version) < _version_tuple(vuln["vulnerable_below"]):
                cves = ", ".join(vuln["cves"])
                scanner.add_finding(
                    "A06: Components", "HIGH",
                    f"{name} v{version} rentan (dari {source})",
                    mitigation=f"Update ke versi >= {vuln['vulnerable_below']}. CVE: {cves}"
                )
            else:
                scanner.add_finding(
                    "A06: Components", "SAFE",
                    f"{name} v{version} (up-to-date)"
                )
        else:
            scanner.add_finding(
                "A06: Components", "INFO",
                f"{name} v{version} terdeteksi (dari {source})"
            )
    
    # Saran umum
    scanner.add_finding(
        "A06: Components", "INFO",
        f"Total {len(detected)} library terdeteksi — rutin update dependensi",
        mitigation="Gunakan Dependabot / npm audit / pip-audit untuk monitoring CVE"
    )