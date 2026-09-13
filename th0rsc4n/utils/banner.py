"""Banner & branding untuk TH0RSC4N — HACKER GREEN TEGAS."""
from rich.console import Console
from rich.panel import Panel
from rich.align import Align

from th0rsc4n import __version__, __tagline__
from th0rsc4n.utils.ascii_art import LOGO_TH0RSC4N

console = Console()


def show_banner():
    """Banner hacker tegas — hijau neon matrix."""
    try:
        console.clear()
    except Exception:
        pass

    # Logo — HIJAU NEON BOLD
    logo = LOGO_TH0RSC4N.strip("\n")
    console.print(f"[bold bright_green]{logo}[/bold bright_green]")

    console.print()

    # Tagline — PUTIH BOLD
    console.print(f"[bold white]              >> {__tagline__.upper()} <<[/bold white]")
    console.print(f"[bright_green]           v{__version__}  |  by Thorranov  |  Cyber Intelligence[/bright_green]")

    console.print()
    console.print(f"[bold bright_green]{'═' * 72}[/bold bright_green]")
    console.print()


def show_scan_header(target, modules_count, mode_info=None):
    """Header scan — tegas pakai double-line border."""
    content = f"[bold white]{target}[/bold white]"

    mode_line = ""
    if mode_info:
        mode_line = f"\n[bold bright_green]  MODE    [/bold bright_green][bright_green]│[/bright_green] [bold white]{mode_info['icon']} {mode_info['name']}[/bold white] [dim white]({mode_info['eta']})[/dim white]"

    console.print(
        f"[bold bright_green]  TARGET  [/bold bright_green][bright_green]│[/bright_green] {content}"
    )
    console.print(
        f"[bold bright_green]  MODULES [/bold bright_green][bright_green]│[/bright_green] [bold white]{modules_count} scenarios[/bold white]{mode_line}"
    )
    console.print(f"[bold bright_green]{'═' * 72}[/bold bright_green]")
    console.print()


def show_scan_complete(stats, elapsed):
    """Status selesai — tegas."""
    total = sum(stats.values())
    vuln = stats.get("CRITICAL", 0) + stats.get("HIGH", 0)
    color = "bold bright_red" if vuln > 0 else "bold bright_green"
    status = "VULNERABLE" if vuln > 0 else "SECURE"

    console.print()
    console.print(f"[bold bright_green]{'═' * 72}[/bold bright_green]")
    console.print(f"[bold bright_green]  STATUS  [/bold bright_green][bright_green]│[/bright_green] [{color}]{status}[/{color}]")
    console.print(f"[bold bright_green]  CHECKS  [/bold bright_green][bright_green]│[/bright_green] [bold white]{total}[/bold white]")
    console.print(f"[bold bright_green]  TIME    [/bold bright_green][bright_green]│[/bright_green] [bold white]{elapsed:.2f}s[/bold white]")
    console.print(f"[bold bright_green]{'═' * 72}[/bold bright_green]")