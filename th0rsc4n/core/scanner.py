import requests
import urllib3
from th0rsc4n.core.finding import Finding
from th0rsc4n.utils.helpers import normalize_url, truncate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Scanner:
    """Core scanner engine."""
    
    def __init__(self, target, timeout=10, user_agent=None, verbose=False, verify_ssl=False):
        self.target = normalize_url(target)
        self.timeout = timeout
        self.verbose = verbose
        self.verify_ssl = verify_ssl
        self.headers = {
            "User-Agent": user_agent or "TH0RSC4N/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def add_finding(self, category, severity, message, mitigation="", evidence="", url=None):
        """Tambah temuan."""
        finding = Finding(
            category=category,
            severity=severity,
            message=message,
            mitigation=mitigation,
            evidence=truncate(evidence, 200),
            url=url or self.target,
        )
        self.findings.append(finding)
        return finding
    
    def get(self, path="", **kwargs):
        """HTTP GET wrapper."""
        url = self.target.rstrip("/") + "/" + path.lstrip("/")
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        kwargs.setdefault("allow_redirects", False)
        try:
            return self.session.get(url, **kwargs)
        except requests.RequestException as e:
            if self.verbose:
                print(f"  [dim]✗ {url} → {e}[/dim]")
            return None
    
    def post(self, path="", **kwargs):
        """HTTP POST wrapper."""
        url = self.target.rstrip("/") + "/" + path.lstrip("/")
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        kwargs.setdefault("allow_redirects", False)
        try:
            return self.session.post(url, **kwargs)
        except requests.RequestException as e:
            if self.verbose:
                print(f"  [dim]✗ {url} → {e}[/dim]")
            return None
    
    def summary(self):
        """Statistik temuan."""
        stats = {s: 0 for s in Finding.SEVERITY_ORDER}
        for f in self.findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1
        return stats
    
    def filter_by_severity(self, min_severity):
        """Filter findings berdasarkan minimum severity."""
        try:
            idx = Finding.SEVERITY_ORDER.index(min_severity.upper())
        except ValueError:
            idx = len(Finding.SEVERITY_ORDER) - 1
        return [f for f in self.findings if Finding.SEVERITY_ORDER.index(f.severity) <= idx]