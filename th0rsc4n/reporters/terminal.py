"""Terminal reporter — OWASP 2025 grouped, ASCII-safe."""
from rich.console import Console

console = Console()

# ==========================================
# SEVERITY STYLES (ASCII-safe, no emoji)
# ==========================================
SEVERITY_STYLES = {
    "CRITICAL": ("bold white on red", "!!"),
    "HIGH": ("bold red", "!"),
    "MEDIUM": ("yellow", "*"),
    "LOW": ("cyan", "-"),
    "INFO": ("blue", "i"),
    "SAFE": ("green", "+"),
}

# Warna khusus per kategori OWASP
OWASP_COLORS = {
    "M00": "bright_white",
    "A01": "bright_red",
    "A02": "yellow",
    "A03": "bright_magenta",
    "A04": "cyan",
    "A05": "red",
    "A06": "magenta",
    "A07": "bright_yellow",
    "A08": "blue",
    "A09": "bright_blue",
    "A10": "bright_cyan",
}


def _is_distinct_url(url, target):
    if not url or not target:
        return False
    return url.rstrip("/") != target.rstrip("/")


def _owasp_color(code):
    if not code:
        return "white"
    return OWASP_COLORS.get(code[:3], "white")


def _sort_key(key):
    """Sort: M00 di paling atas, lalu A01-A10."""
    if key.startswith("M00"):
        return "00_M00"
    return key


def report(findings, target, verbose=False):
    """Print findings grouped by OWASP 2025."""
    console.print()
    console.print(f"[bold red]+==============================================================+[/bold red]")
    console.print(f"[bold red]|  << TH0RSC4N REPORT >>                                        |[/bold red]")
    console.print(f"[bold red]+==============================================================+[/bold red]")
    console.print(f"[bold cyan]  TARGET :[/bold cyan] [white]{target}[/white]")
    console.print(f"[bold cyan]  OWASP  :[/bold cyan] [white]Top 10 2025 Edition[/white]")
    console.print(f"[bold cyan]  TOTAL  :[/bold cyan] [white]{len(findings)} findings[/white]")
    console.print()

    # Group by OWASP 2025
    by_owasp = {}
    for f in findings:
        code = getattr(f, "owasp_2025_code", "A10:2025")
        cat = getattr(f, "owasp_2025_category", "Unknown")
        key = f"{code} - {cat}"
        by_owasp.setdefault(key, []).append(f)

    # Sort: M00 di atas, lalu A01-A10
    for owasp_key in sorted(by_owasp.keys(), key=_sort_key):
        items = by_owasp[owasp_key]
        code = owasp_key.split(" ")[0]
        color = _owasp_color(code)

        console.print()
        console.print(f"[bold {color}]=== {owasp_key} ===[/bold {color}]")

        # Sort per severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                     "LOW": 3, "INFO": 4, "SAFE": 5}
        items_sorted = sorted(items, key=lambda x: sev_order.get(x.severity, 99))

        for item in items_sorted:
            style, icon = SEVERITY_STYLES.get(item.severity, ("white", "?"))
            console.print(f"  [{style}][{icon}][/{style}] [{style}]{item.severity:<8}[/{style}] {item.message}")

            if _is_distinct_url(getattr(item, "url", None), target):
                console.print(f"      [dim cyan]-> {item.url}[/dim cyan]")

            if item.mitigation:
                console.print(f"      [dim]-> {item.mitigation}[/dim]")

            if verbose and item.evidence:
                console.print(f"      [dim italic]Evidence: {item.evidence}[/dim italic]")


def print_summary(stats, elapsed, mode_info=None):
    """Print summary (ASCII-safe)."""
    mode_line = ""
    if mode_info:
        mode_line = f"  [dim]Mode: {mode_info['name']}[/dim]\n"

    console.print()
    console.print("[bold red]+======================================+[/bold red]")
    console.print("[bold red]|  << TH0RSC4N SUMMARY - 2025 >>       |[/bold red]")
    console.print("[bold red]+======================================+[/bold red]")
    if mode_line:
        console.print(mode_line, end="")
    console.print(f"  [bold red][!!] CRITICAL: {stats.get('CRITICAL', 0)}[/bold red]")
    console.print(f"  [red][!]  HIGH    : {stats.get('HIGH', 0)}[/red]")
    console.print(f"  [yellow][*]  MEDIUM  : {stats.get('MEDIUM', 0)}[/yellow]")
    console.print(f"  [cyan][-]  LOW     : {stats.get('LOW', 0)}[/cyan]")
    console.print(f"  [blue][i]  INFO    : {stats.get('INFO', 0)}[/blue]")
    console.print(f"  [green][+]  SAFE    : {stats.get('SAFE', 0)}[/green]")
    console.print(f"\n  [dim]Time: {elapsed:.2f}s[/dim]")