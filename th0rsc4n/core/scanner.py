"""
Core Scanner Engine — Enterprise-Ready Async
- Persistent aiohttp.ClientSession (1x creation, reused)
- Unified _arequest() untuk GET/POST (JSON + Form)
- Wrapper: aget(), apost() + sync get(), post()
- Compatible dengan modul m00-m99
"""
import asyncio
import requests
import urllib3
from typing import Optional, Any

from th0rsc4n.core.finding import Finding
from th0rsc4n.utils.helpers import normalize_url, truncate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


class Scanner:
    """Async scanner engine dengan persistent session pool."""

    def __init__(self, target, timeout=10, user_agent=None, verbose=False,
                 verify_ssl=False, concurrency=15):
        self.target = normalize_url(target)
        self.timeout = timeout
        self.verbose = verbose
        self.verify_ssl = verify_ssl
        self.concurrency = concurrency

        self.headers = {
            "User-Agent": user_agent or "TH0RSC4N/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

        self.findings = []
        self.detected_tech = []
        self.tech_by_category = {}
        self._baseline = None

        # Sync session (untuk modul lama yang pake get/post)
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        # Async persistent session (dibuat di __aenter__)
        self._async_session: Optional["aiohttp.ClientSession"] = None
        self._semaphore: Optional[asyncio.Semaphore] = None

    # ==========================================
    # ASYNC CONTEXT MANAGER (Persistent Pool)
    # ==========================================
    async def __aenter__(self):
        """Buat 1x persistent session + semaphore."""
        if HAS_AIOHTTP:
            connector = aiohttp.TCPConnector(
                limit=self.concurrency * 2,
                limit_per_host=self.concurrency,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._async_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.headers,
                skip_auto_headers={"Accept-Encoding"},
            )
        self._semaphore = asyncio.Semaphore(self.concurrency)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Tutup session di akhir engine."""
        if self._async_session and not self._async_session.closed:
            await self._async_session.close()
            # Beri waktu graceful close
            await asyncio.sleep(0.1)
        self._async_session = None

    # ==========================================
    # FINDING
    # ==========================================
    def add_finding(self, category, severity, message, mitigation="", evidence="", url=None):
        f = Finding(
            category=category,
            severity=severity,
            message=message,
            mitigation=mitigation,
            evidence=truncate(str(evidence), 300),
            url=url or self.target,
        )
        self.findings.append(f)
        return f

    # ==========================================
    # SYNC HTTP (untuk modul lama)
    # ==========================================
    def get(self, path="", **kw):
        url = self.target.rstrip("/") + "/" + path.lstrip("/") if path else self.target
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify_ssl)
        kw.setdefault("allow_redirects", True)
        try:
            return self.session.get(url, **kw)
        except requests.RequestException as e:
            if self.verbose:
                print(f"  [get] {url} -> {e}")
            return None

    def post(self, path="", **kw):
        url = self.target.rstrip("/") + "/" + path.lstrip("/") if path else self.target
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify_ssl)
        kw.setdefault("allow_redirects", True)
        try:
            return self.session.post(url, **kw)
        except requests.RequestException as e:
            if self.verbose:
                print(f"  [post] {url} -> {e}")
            return None

    # ==========================================
    # ASYNC CORE (_arequest)
    # ==========================================
    async def _arequest(
        self,
        method: str,
        url: str,
        json_data: Any = None,
        data: Any = None,
        headers_override: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> Optional[dict]:
        """Unified async request handler."""
        # Merge headers
        headers = dict(self.headers)
        if headers_override:
            headers.update(headers_override)

        # Auto Content-Type
        if json_data is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        elif data is not None and isinstance(data, str) and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        # ---- aiohttp path (persistent session) ----
        if HAS_AIOHTTP and self._async_session and not self._async_session.closed:
            try:
                async with self._semaphore:
                    async with self._async_session.request(
                        method,
                        url,
                        json=json_data,
                        data=data,
                        headers=headers,
                        allow_redirects=allow_redirects,
                        ssl=False,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return {
                            "status": resp.status,
                            "headers": {k.lower(): v for k, v in resp.headers.items()},
                            "body": body,
                            "url": str(resp.url),
                        }
            except asyncio.TimeoutError:
                if self.verbose:
                    print(f"  [timeout] {url}")
                return None
            except aiohttp.ClientError as e:
                if self.verbose:
                    print(f"  [aiohttp] {url} -> {e}")
                return None
            except Exception as e:
                if self.verbose:
                    print(f"  [async] {url} -> {e}")
                return None

        # ---- Fallback: requests via executor ----
        def _sync_request():
            try:
                r = requests.request(
                    method,
                    url,
                    json=json_data,
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=allow_redirects,
                )
                return {
                    "status": r.status_code,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": r.text,
                    "url": r.url,
                }
            except requests.RequestException as e:
                if self.verbose:
                    print(f"  [sync-fallback] {url} -> {e}")
                return None

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _sync_request)
        except Exception:
            return None

    # ==========================================
    # ASYNC WRAPPERS
    # ==========================================
    async def aget(self, url, headers_override=None, allow_redirects=True, **kw):
        """Async GET."""
        return await self._arequest(
            "GET", url,
            headers_override=headers_override,
            allow_redirects=allow_redirects,
            **kw,
        )

    async def apost(self, url, json=None, data=None, headers_override=None,
                    allow_redirects=True, **kw):
        """Async POST dengan JSON atau Form-Data."""
        return await self._arequest(
            "POST", url,
            json_data=json,
            data=data,
            headers_override=headers_override,
            allow_redirects=allow_redirects,
            **kw,
        )

    # ==========================================
    # BATCH GATHER (dengan concurrency control)
    # ==========================================
    async def agather(self, coros):
        """Batch async requests. Concurrency dikontrol via semaphore di _arequest."""
        return await asyncio.gather(*coros, return_exceptions=True)

    # ==========================================
    # BASELINE (cache)
    # ==========================================
    async def baseline(self):
        if self._baseline is None:
            self._baseline = await self.aget(self.target)
        return self._baseline

    # ==========================================
    # STATS
    # ==========================================
    def summary(self):
        stats = {s: 0 for s in Finding.SEVERITY_ORDER}
        for f in self.findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1
        return stats

    def filter_by_severity(self, min_sev):
        try:
            idx = Finding.SEVERITY_ORDER.index(min_sev.upper())
        except ValueError:
            idx = len(Finding.SEVERITY_ORDER) - 1
        return [f for f in self.findings
                if Finding.SEVERITY_ORDER.index(f.severity) <= idx]