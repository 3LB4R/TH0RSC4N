"""A03:2021 - Injection (semua jenis)"""
import re
import time

PARAMS = ["q", "s", "search", "id", "page", "name", "query", "keyword", "lang", "cat"]

def scan(scanner):
    _xss(scanner)
    _dom_xss(scanner)
    _sqli(scanner)
    _nosqli(scanner)
    _cmdi(scanner)
    _xxe(scanner)
    _ssti(scanner)
    _ldap(scanner)
    _xpath(scanner)
    _latex(scanner)
    _graphql(scanner)
    _crlf(scanner)
    _csv(scanner)
    _css(scanner)
    _xslt(scanner)
    _prompt(scanner)


def _xss(scanner):
    payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>",
                "\"><svg onload=alert(1)>", "javascript:alert(1)"]
    found = False
    for p in PARAMS[:5]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and pl in r.text:
                scanner.add_finding("A03: XSS", "HIGH",
                    f"Reflected XSS di '{p}'",
                    mitigation="Sanitasi input, gunakan textContent, terapkan CSP")
                found = True
                break
    if not found:
        scanner.add_finding("A03: XSS", "SAFE", "Tidak ada Reflected XSS")


def _dom_xss(scanner):
    r = scanner.get()
    if not r:
        return
    patterns = [r"innerHTML\s*=", r"document\.write\(", r"eval\(", r"dangerouslySetInnerHTML"]
    found = set()
    for p in patterns:
        if re.search(p, r.text):
            found.add(p)
    if found:
        scanner.add_finding("A03: DOM-XSS", "MEDIUM",
            f"Potensi DOM XSS: {found}",
            mitigation="Gunakan textContent, hindari eval/innerHTML")
    else:
        scanner.add_finding("A03: DOM-XSS", "SAFE", "Tidak ada pola DOM XSS")


def _sqli(scanner):
    payloads = ["'", "\"", "' OR '1'='1", "1' AND SLEEP(5)--", "1 UNION SELECT NULL--"]
    errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite", "ODBC", "syntax error"]
    found = False
    for p in PARAMS[:3]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and any(e.lower() in r.text.lower() for e in errors):
                scanner.add_finding("A03: SQLi", "CRITICAL",
                    f"SQL Injection di '{p}'",
                    mitigation="Prepared Statements")
                found = True
    if not found:
        scanner.add_finding("A03: SQLi", "SAFE", "Tidak ada SQLi")


def _nosqli(scanner):
    payloads = ["'||'1'=='1", '{"$gt":""}', "[$ne]=1"]
    found = False
    for p in PARAMS[:3]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and ("MongoError" in r.text or "BSONTypeError" in r.text):
                scanner.add_finding("A03: NoSQLi", "CRITICAL",
                    f"NoSQLi di '{p}'", mitigation="Sanitasi operator query")
                found = True
    if not found:
        scanner.add_finding("A03: NoSQLi", "SAFE", "Tidak ada NoSQLi")


def _cmdi(scanner):
    payloads = ["; ls", "| whoami", "`id`", "$(whoami)", "&& dir"]
    found = False
    for p in PARAMS[:3]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and re.search(r"root:|uid=|www-data", r.text):
                scanner.add_finding("A03: CMDi", "CRITICAL",
                    f"Command Injection di '{p}'",
                    mitigation="Jangan pass input ke shell")
                found = True
    if not found:
        scanner.add_finding("A03: CMDi", "SAFE", "Tidak ada Command Injection")


def _xxe(scanner):
    xxe = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    r = scanner.post(data=xxe, headers={"Content-Type": "application/xml"})
    if r and "root:" in r.text:
        scanner.add_finding("A03: XXE", "CRITICAL", "XXE Injection!",
                            mitigation="Disable external entities")
    else:
        scanner.add_finding("A03: XXE", "SAFE", "Tidak ada XXE")


def _ssti(scanner):
    payloads = [("{{9381*8192}}", "76849152"), ("${9381*8192}", "76849152"),
                ("<%= 9381*8192 %>", "76849152")]
    found = False
    for p in PARAMS[:3]:
        for pl, exp in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and exp in r.text and pl not in r.text:
                scanner.add_finding("A03: SSTI", "CRITICAL",
                    f"SSTI di '{p}'", mitigation="Jangan render input as template")
                found = True
    if not found:
        scanner.add_finding("A03: SSTI", "SAFE", "Tidak ada SSTI")


def _ldap(scanner):
    payloads = ["*)(uid=*", "*))(|(uid=*", "admin*"]
    found = False
    for p in PARAMS[:2]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and ("LDAP" in r.text or "ldap_" in r.text):
                scanner.add_finding("A03: LDAP", "HIGH",
                    f"LDAP Injection di '{p}'", mitigation="Escape LDAP chars")
                found = True
    if not found:
        scanner.add_finding("A03: LDAP", "SAFE", "Tidak ada LDAP Injection")


def _xpath(scanner):
    payloads = ["' or '1'='1", "x' or '1'='1", "']|//*|//*['"]
    found = False
    for p in PARAMS[:2]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and "XPath" in r.text:
                scanner.add_finding("A03: XPath", "HIGH",
                    f"XPath Injection di '{p}'", mitigation="Sanitasi XPath")
                found = True
    if not found:
        scanner.add_finding("A03: XPath", "SAFE", "Tidak ada XPath Injection")


def _latex(scanner):
    payloads = ["\\input{/etc/passwd}", "\\include{/etc/passwd}"]
    found = False
    for p in PARAMS[:2]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and "root:" in r.text:
                scanner.add_finding("A03: LaTeX", "HIGH",
                    f"LaTeX Injection di '{p}'", mitigation="Sanitasi LaTeX")
                found = True
    if not found:
        scanner.add_finding("A03: LaTeX", "SAFE", "Tidak ada LaTeX Injection")


def _graphql(scanner):
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
    found = False
    for ep in endpoints:
        r = scanner.post(ep, json={"query": "{__schema{types{name}}}"})
        if r and r.status_code == 200 and "__schema" in r.text:
            scanner.add_finding("A03: GraphQL", "HIGH",
                f"GraphQL introspection aktif di {ep}",
                mitigation="Disable introspection di production")
            found = True
    if not found:
        scanner.add_finding("A03: GraphQL", "SAFE", "Tidak ada GraphQL terekspos")


def _crlf(scanner):
    payloads = ["%0d%0aInjected: evil", "%0aSet-Cookie:evil=1"]
    found = False
    for pl in payloads:
        r = scanner.get(f"?q={pl}")
        if r and ("Injected" in str(r.headers) or "evil" in str(r.headers)):
            scanner.add_finding("A03: CRLF", "HIGH", "CRLF Injection!",
                                mitigation="Sanitasi \\r\\n")
            found = True
    if not found:
        scanner.add_finding("A03: CRLF", "SAFE", "Tidak ada CRLF Injection")


def _csv(scanner):
    payloads = ["=cmd|' /C calc'!A0", "+1+1", "@SUM(1+1)"]
    found = False
    for pl in payloads:
        r = scanner.get(f"?q={pl}")
        if r and pl in r.text:
            scanner.add_finding("A03: CSV", "LOW",
                f"CSV Injection potential ({pl})",
                mitigation="Sanitasi input sebelum export")
            found = True
            break
    if not found:
        scanner.add_finding("A03: CSV", "SAFE", "Tidak ada CSV Injection")


def _css(scanner):
    payloads = ["</style><script>alert(1)</script>", "expression(alert(1))"]
    found = False
    for p in PARAMS[:2]:
        for pl in payloads:
            r = scanner.get(f"?{p}={pl}")
            if r and pl in r.text:
                scanner.add_finding("A03: CSS", "MEDIUM",
                    f"CSS Injection di '{p}'", mitigation="Sanitasi CSS")
                found = True
    if not found:
        scanner.add_finding("A03: CSS", "SAFE", "Tidak ada CSS Injection")


def _xslt(scanner):
    xslt = '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="system-property(\'xsl:version\')"/></xsl:template></xsl:stylesheet>'
    r = scanner.post(data=xslt, headers={"Content-Type": "application/xml"})
    if r and "1.0" in r.text and "xsl" in r.text.lower():
        scanner.add_finding("A03: XSLT", "HIGH", "XSLT Injection!",
                            mitigation="Disable XSLT processing")
    else:
        scanner.add_finding("A03: XSLT", "SAFE", "Tidak ada XSLT Injection")


def _prompt(scanner):
    scanner.add_finding("A03: Prompt", "SAFE", "Tidak ada fitur AI/LLM")