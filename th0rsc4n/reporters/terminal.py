from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": ("bold white on red", "🔴"),
    "HIGH": ("bold red", "🟠"),
    "MEDIUM": ("yellow", "🟡"),
    "LOW": ("cyan", "🔵"),
    "INFO": ("blue", "⚪"),
    "SAFE": ("green", "🟢"),
}

def report(findings, target, verbose=False):
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]TARGET:[/bold cyan] [white]{target}[/white]",
        title="[bold red]◤ TH0RSC4N REPORT ◢[/bold red]",
        border_style="red",
    ))
    
    # Group by category
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    
    for category, items in by_cat.items():
        console.print(f"\n[bold magenta]▶ {category}[/bold magenta]")
        for item in items:
            style, icon = SEVERITY_STYLES.get(item.severity, ("white", "•"))
            console.print(f"  {icon} [{style}]{item.severity:<8}[/{style}] {item.message}")
            if item.mitigation:
                console.print(f"      [dim]↳ {item.mitigation}[/dim]")
            if verbose and item.evidence:
                console.print(f"      [dim italic]Evidence: {item.evidence}[/dim italic]")


def print_summary(stats, elapsed, mode_info=None):
    mode_line = ""
    if mode_info:
        mode_line = f"  [dim]Mode: {mode_info['icon']} {mode_info['name']}[/dim]\n"
    
    console.print()
    console.print("[bold red]╔══════════════════════════════════════╗[/bold red]")
    console.print("[bold red]║      ◤ TH0RSC4N SUMMARY ◢           ║[/bold red]")
    console.print("[bold red]╚══════════════════════════════════════╝[/bold red]")
    if mode_line:
        console.print(mode_line, end="")
    console.print(f"  [bold red]🔴 CRITICAL: {stats.get('CRITICAL', 0)}[/bold red]")
    console.print(f"  [red]🟠 HIGH    : {stats.get('HIGH', 0)}[/red]")
    console.print(f"  [yellow]🟡 MEDIUM  : {stats.get('MEDIUM', 0)}[/yellow]")
    console.print(f"  [cyan]🔵 LOW     : {stats.get('LOW', 0)}[/cyan]")
    console.print(f"  [blue]⚪ INFO    : {stats.get('INFO', 0)}[/blue]")
    console.print(f"  [green]🟢 SAFE    : {stats.get('SAFE', 0)}[/green]")
    console.print(f"\n  [dim]Time: {elapsed:.2f}s[/dim]")