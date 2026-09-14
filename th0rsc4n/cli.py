"""
TH0RSC4N - Brutal OWASP Top 10 Security Scanner
by Thorranov | Cyber Intelligence

Async version — persistent session pool + adaptive module executor.
"""
import click
import sys
import time
import json
import asyncio
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from th0rsc4n import __version__
from th0rsc4n.utils.banner import show_banner, show_scan_header, show_scan_complete
from th0rsc4n.utils.config import load_config, save_config
from th0rsc4n.utils.helpers import is_valid_url, normalize_url
from th0rsc4n.core.scanner import Scanner
from th0rsc4n.modules import get_modules, get_mode_info, SCAN_MODES
from th0rsc4n.reporters import terminal, html as html_rep, json_rep, markdown

console = Console()


# ==========================================
# SECURITY HEADERS RECOMMENDED VALUES
# ==========================================
RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'; object-src 'none';",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


# ==========================================
# ASYNC EXECUTOR
# ==========================================
async def _run_module(engine, name, func, verbose):
    """Execute single module (adaptive sync/async)."""
    try:
        if asyncio.iscoroutinefunction(func):
            await func(engine)
        else:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, func, engine)
    except Exception as e:
        if verbose:
            console.print(f"[red]  [!] Error in {name}: {e}[/red]")


async def _run_async_scan(scanner, modules, verbose, concurrency=4):
    """Run all modules with persistent session + parallel execution."""
    async with scanner as engine:
        sem = asyncio.Semaphore(concurrency)

        async def _wrapped(name, func):
            async with sem:
                await _run_module(engine, name, func, verbose)

        await asyncio.gather(
            *[_wrapped(name, func) for name, func in modules],
            return_exceptions=True,
        )


def _execute_modules(scanner, modules, verbose, quiet):
    """Execute modules with loading animation."""
    if quiet:
        try:
            asyncio.run(_run_async_scan(scanner, modules, verbose))
        except Exception as e:
            if verbose:
                console.print(f"[red]Engine error: {e}[/red]")
        return

    from th0rsc4n.utils.loading import HackerLoading

    loader = HackerLoading(
        message="SCANNING",
        submessage=f"Analyzing {len(modules)} security modules...",
    )
    loader.start()

    try:
        asyncio.run(_run_async_scan(scanner, modules, verbose))
    except Exception as e:
        if verbose:
            console.print(f"[red]Engine error: {e}[/red]")
    finally:
        loader.stop()


# ==========================================
# MAIN CLI GROUP
# ==========================================
@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="TH0RSC4N")
@click.pass_context
def cli(ctx):
    """
    \b
    ╔═══════════════════════════════════════════════════════════╗
    ║   TH0RSC4N - Brutal OWASP Top 10 Security Scanner         ║
    ║   by Thorranov | Cyber Intelligence                       ║
    ╚═══════════════════════════════════════════════════════════╝

    \b
    Sebuah CLI tool untuk audit keamanan website dengan 80+ skenario
    OWASP Top 10 2021 + teknologi fingerprinting (150+ tech).

    \b
    Contoh penggunaan:
        th0rsc4n scan https://target.com              # Normal scan
        th0rsc4n scan https://target.com -m deep      # Deep scan
        th0rsc4n tech https://target.com              # Cek teknologi saja
        th0rsc4n interactive                          # Mode interaktif
        th0rsc4n web                                  # Web UI
    """
    if ctx.invoked_subcommand is None:
        show_banner()
        click.echo(ctx.get_help())


# ==========================================
# COMMAND: scan
# ==========================================
@cli.command()
@click.argument("target", required=False)
@click.option("-m", "--mode", "mode",
              type=click.Choice(["quick", "normal", "deep"], case_sensitive=False),
              default="normal", show_default=True,
              help="quick (~5s) | normal (~15s) | deep (~60s)")
@click.option("-o", "--output", type=click.Path(),
              help="Simpan report ke path ini (extension auto)")
@click.option("-f", "--format", "fmt",
              type=click.Choice(["html", "json", "md", "pdf", "all"]),
              default="html", show_default=True,
              help="Format report: html / json / md / pdf / all")
@click.option("-t", "--timeout", type=int, default=None,
              help="Timeout HTTP request dalam detik (default: 10)")
@click.option("--ua", "--user-agent", "ua", default=None,
              help="Custom User-Agent string")
@click.option("-v", "--verbose", is_flag=True, help="Tampilkan semua detail")
@click.option("-q", "--quiet", is_flag=True, help="Hanya tampilkan summary")
@click.option("--no-banner", is_flag=True, help="Sembunyikan banner ASCII")
@click.option("--severity",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
              default="INFO", show_default=True,
              help="Minimum severity yang ditampilkan")
@click.option("--export-config", "export_platform",
              type=click.Choice(["vercel", "netlify", "nginx", "apache",
                                 "cloudflare", "express"], case_sensitive=False),
              default=None,
              help="Export security config untuk platform tertentu")
@click.option("--interactive/--no-interactive", default=False,
              help="Prompt interaktif untuk input yang kosong")
def scan(target, mode, output, fmt, timeout, ua, verbose, quiet, no_banner,
         severity, export_platform, interactive):
    """
    Scan target URL untuk kerentanan OWASP Top 10.

    \b
    Contoh:
        th0rsc4n scan https://example.com
        th0rsc4n scan https://example.com -m deep -o report --format all
        th0rsc4n scan https://example.com -m deep -o report --format pdf
        th0rsc4n scan https://example.com --export-config nginx
    """
    if not target:
        show_banner()
        console.print("[bold cyan]Scan Mode[/bold cyan]\n")
        target = console.input("[bold]Masukkan URL target:[/bold] ").strip()
        if not target:
            console.print("[red]X Target tidak boleh kosong[/red]")
            sys.exit(1)

        if not interactive:
            console.print("\n[bold]Pilih mode:[/bold]")
            console.print("  [cyan]1.[/cyan] Quick  (~5 detik)")
            console.print("  [cyan]2.[/cyan] Normal (~15 detik)")
            console.print("  [cyan]3.[/cyan] Deep   (~60 detik)")
            choice = console.input("\n[bold]Pilih [1/2/3] (default: 2):[/bold] ").strip() or "2"
            mode = {"1": "quick", "2": "normal", "3": "deep"}.get(choice, "normal")

    if not no_banner and not quiet:
        show_banner()

    if not is_valid_url(target):
        target = "https://" + target
    if not is_valid_url(target):
        console.print(f"[bold red]X Target tidak valid:[/bold red] {target}")
        sys.exit(1)

    target = normalize_url(target)
    config = load_config()
    timeout = timeout or config["timeout"]
    ua = ua or config["user_agent"]

    modules = get_modules(mode)
    mode_info = get_mode_info(mode)

    if not quiet:
        show_scan_header(target, len(modules), mode_info)

    scanner = Scanner(target, timeout=timeout, user_agent=ua, verbose=verbose)

    start = time.time()
    _execute_modules(scanner, modules, verbose, quiet)
    elapsed = time.time() - start

    findings = scanner.filter_by_severity(severity)

    if not quiet:
        if hasattr(scanner, "tech_by_category") and scanner.tech_by_category:
            _print_tech_table(scanner.tech_by_category)

        terminal.report(findings, target, verbose=verbose)

    stats = scanner.summary()
    terminal.print_summary(stats, elapsed, mode_info)
    show_scan_complete(stats, elapsed)

    # ==========================================
    # OUTPUT REPORTS
    # ==========================================
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # ---------- HTML ----------
        if fmt in ("html", "all"):
            p = output_path.with_suffix(".html")
            html_rep.report(findings, target, p)
            console.print(f"[green]OK HTML report:[/green] {p}")

        # ---------- JSON ----------
        if fmt in ("json", "all"):
            p = output_path.with_suffix(".json")
            json_rep.report(findings, target, p)
            console.print(f"[green]OK JSON report:[/green] {p}")

        # ---------- MARKDOWN ----------
        if fmt in ("md", "all"):
            p = output_path.with_suffix(".md")
            markdown.report(findings, target, p)
            console.print(f"[green]OK Markdown report:[/green] {p}")

        # ---------- PDF ----------
        if fmt in ("pdf", "all"):
            try:
                from th0rsc4n.reporters import pdf as pdf_rep
                p = output_path.with_suffix(".pdf")
                pdf_rep.report(findings, target, p)
                console.print(f"[green]OK PDF report:[/green] {p}")
            except ImportError as e:
                console.print(f"[yellow]! PDF skipped (need xhtml2pdf): {e}[/yellow]")
                console.print("[yellow]  Install: pip install xhtml2pdf[/yellow]")
            except Exception as e:
                console.print(f"[red]X PDF error: {e}[/red]")

    # Export config
    if export_platform:
        _export_security_config(scanner, export_platform)

    if stats.get("CRITICAL", 0) > 0 or stats.get("HIGH", 0) > 0:
        sys.exit(1)
    sys.exit(0)


# ==========================================
# HELPER: Print Tech Table
# ==========================================
def _print_tech_table(tech_by_category):
    table = Table(title="Teknologi Terdeteksi", border_style="cyan")
    table.add_column("Kategori", style="cyan", no_wrap=True)
    table.add_column("Teknologi", style="green")

    for cat in sorted(tech_by_category.keys()):
        techs = ", ".join(sorted(tech_by_category[cat]))
        table.add_row(cat, techs)

    console.print()
    console.print(table)


# ==========================================
# HELPER: Export Security Config
# ==========================================
def _export_security_config(scanner, platform):
    missing = [f for f in scanner.findings
               if "HILANG" in f.message and f.severity in ("HIGH", "MEDIUM")]

    if not missing:
        console.print("\n[green]OK Semua security header sudah ada![/green]")
        return

    needed = {}
    for h in missing:
        for name, value in RECOMMENDED_HEADERS.items():
            if name in h.message:
                needed[name] = value

    if not needed:
        console.print("\n[yellow]! Tidak ada security header yang hilang[/yellow]")
        return

    platform = platform.lower()
    output_file = None
    content = ""

    if platform == "vercel":
        output_file = Path("vercel.json")
        config = {"headers": [{"source": "/(.*)", "headers": [
            {"key": k, "value": v} for k, v in needed.items()
        ]}]}
        content = json.dumps(config, indent=2)

    elif platform == "netlify":
        output_file = Path("_headers")
        lines = ["/*"]
        for k, v in needed.items():
            lines.append(f"  {k}: {v}")
        content = "\n".join(lines) + "\n"

    elif platform == "nginx":
        output_file = Path("nginx-security.conf")
        lines = ["# Tambahkan di dalam block server { }"]
        for k, v in needed.items():
            lines.append(f'add_header {k} "{v}" always;')
        content = "\n".join(lines) + "\n"

    elif platform == "apache":
        output_file = Path(".htaccess")
        lines = ["<IfModule mod_headers.c>"]
        for k, v in needed.items():
            lines.append(f'    Header always set {k} "{v}"')
        lines.append("</IfModule>")
        content = "\n".join(lines) + "\n"

    elif platform == "cloudflare":
        output_file = Path("cloudflare-headers.txt")
        lines = ["# Cloudflare Workers — Security Headers", ""]
        for k, v in needed.items():
            lines.append(f'{k}: {v}')
        content = "\n".join(lines) + "\n"

    elif platform == "express":
        output_file = Path("security-middleware.js")
        lines = ["app.use((req, res, next) => {"]
        for k, v in needed.items():
            lines.append(f'  res.setHeader("{k}", "{v}");')
        lines.append("  next();")
        lines.append("});")
        content = "\n".join(lines) + "\n"

    if output_file:
        output_file.write_text(content, encoding="utf-8")
        console.print()
        console.print(f"[green]OK Generated:[/green] [bold]{output_file}[/bold]")
        console.print(f"[dim]  Platform: {platform.upper()} | {len(needed)} headers[/dim]")


# ==========================================
# COMMAND: tech
# ==========================================
@cli.command()
@click.argument("target", required=False)
@click.option("--no-banner", is_flag=True, help="Sembunyikan banner")
@click.option("--json", "as_json", is_flag=True, help="Output JSON only")
def tech(target, no_banner, as_json):
    """Deteksi teknologi website."""
    if not target:
        show_banner()
        target = console.input("[bold]Masukkan URL target:[/bold] ").strip()
        if not target:
            console.print("[red]X Target wajib diisi[/red]")
            sys.exit(1)

    if not no_banner and not as_json:
        show_banner()

    target = normalize_url(target)
    if not is_valid_url(target):
        console.print(f"[red]X URL tidak valid: {target}[/red]")
        sys.exit(1)

    scanner = Scanner(target)

    if not as_json:
        from th0rsc4n.utils.loading import QuickSpinner
        spinner = QuickSpinner("Mendeteksi teknologi website...")
        spinner.start()
        try:
            async def _run():
                async with scanner as engine:
                    from th0rsc4n.modules import m00_tech_detect
                    if asyncio.iscoroutinefunction(m00_tech_detect.scan):
                        await m00_tech_detect.scan(engine)
                    else:
                        loop = asyncio.get_running_loop()
                        await loop.run_in_executor(None, m00_tech_detect.scan, engine)
            asyncio.run(_run())
        finally:
            spinner.stop()
    else:
        async def _run_q():
            async with scanner as engine:
                from th0rsc4n.modules import m00_tech_detect
                if asyncio.iscoroutinefunction(m00_tech_detect.scan):
                    await m00_tech_detect.scan(engine)
                else:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, m00_tech_detect.scan, engine)
        asyncio.run(_run_q())

    techs = getattr(scanner, "detected_tech", [])
    by_cat = getattr(scanner, "tech_by_category", {})

    if as_json:
        console.print(json.dumps({
            "target": target,
            "total": len(techs),
            "technologies": techs,
            "by_category": by_cat,
        }, indent=2))
        return

    console.print(f"\n[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]Total:[/bold cyan] {len(techs)} teknologi terdeteksi\n")

    if not techs:
        console.print("[yellow]! Tidak ada teknologi terdeteksi[/yellow]")
        return

    table = Table(title="Teknologi Terdeteksi", border_style="cyan", show_lines=True)
    table.add_column("Kategori", style="cyan", no_wrap=True)
    table.add_column("Teknologi", style="green", no_wrap=True)
    table.add_column("Evidence", style="dim")

    for t in sorted(techs, key=lambda x: (x["category"], x["name"])):
        table.add_row(t["category"], t["name"], t["evidence"][:60])

    console.print(table)


# ==========================================
# COMMAND: interactive
# ==========================================
@cli.command()
def interactive():
    """Mode interaktif dengan prompt."""
    show_banner()

    console.print(Panel(
        "[bold cyan]MODE INTERAKTIF[/bold cyan]\n\n"
        "[white]Mode ini cocok untuk kamu yang baru pertama kali pakai TH0RSC4N.[/white]\n"
        "[white]Cukup jawab beberapa pertanyaan, dan scan akan dimulai![/white]",
        title="[bold green]<< SELAMAT DATANG >>[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))
    console.print()

    # STEP 1
    console.print("[bold yellow]--- STEP 1: TARGET WEBSITE ---[/bold yellow]")
    console.print("[dim]Masukkan URL website yang mau di-scan.[/dim]\n")
    target = console.input("[bold cyan]URL target:[/bold cyan] ").strip()
    if not target:
        console.print("[red]X URL tidak boleh kosong[/red]")
        sys.exit(1)
    if not is_valid_url(target):
        target = "https://" + target
        if not is_valid_url(target):
            console.print("[red]X URL tidak valid[/red]")
            sys.exit(1)
    console.print(f"[green]OK Target: {target}[/green]\n")

    # STEP 2
    console.print("[bold yellow]--- STEP 2: MODE SCAN ---[/bold yellow]\n")
    table = Table(border_style="cyan", show_header=True, header_style="bold cyan")
    table.add_column("Pilihan", justify="center", style="bold")
    table.add_column("Mode", style="white")
    table.add_column("Deskripsi", style="dim")
    table.add_column("Waktu", style="yellow", justify="center")
    table.add_row("1", "Quick", "Cek header & kritikal", "~5 detik")
    table.add_row("2", "Normal", "OWASP Top 10 inti", "~15 detik")
    table.add_row("3", "Deep", "Semua 80+ skenario", "~60 detik")
    console.print(table)
    console.print()

    choice = console.input("[bold cyan]Pilih mode [1/2/3] (default: 2):[/bold cyan] ").strip() or "2"
    mode = {"1": "quick", "2": "normal", "3": "deep"}.get(choice, "normal")
    console.print(f"[green]OK Mode: {mode.upper()}[/green]\n")

    # STEP 3 - Format report
    console.print("[bold yellow]--- STEP 3: FORMAT REPORT ---[/bold yellow]")
    console.print("  [cyan]1.[/cyan] All (HTML + JSON + MD + PDF) [dim](recommended)[/dim]")
    console.print("  [cyan]2.[/cyan] HTML only")
    console.print("  [cyan]3.[/cyan] JSON only")
    console.print("  [cyan]4.[/cyan] Markdown only")
    console.print("  [cyan]5.[/cyan] PDF only")
    console.print("  [cyan]6.[/cyan] Tidak simpan report")

    fmt_choice = console.input("\n[bold cyan]Pilih [1-6] (default: 1):[/bold cyan] ").strip() or "1"
    fmt_map = {
        "1": "all", "2": "html", "3": "json",
        "4": "md", "5": "pdf", "6": None,
    }
    fmt = fmt_map.get(fmt_choice, "all")

    output = None
    if fmt:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"th0rsc4n_report_{timestamp}"
        console.print(f"[green]OK Report: {output}.[{fmt if fmt != 'all' else 'html|json|md|pdf'}][/green]\n")
    else:
        console.print("[green]OK Report tidak disimpan[/green]\n")

    # STEP 4 - Export config
    console.print("[bold yellow]--- STEP 4: EXPORT CONFIG ---[/bold yellow]")
    console.print("  [cyan]0.[/cyan] Skip")
    console.print("  [cyan]1.[/cyan] Vercel  [cyan]2.[/cyan] Netlify  [cyan]3.[/cyan] Nginx")
    console.print("  [cyan]4.[/cyan] Apache  [cyan]5.[/cyan] Cloudflare  [cyan]6.[/cyan] Express")
    cfg = console.input("\n[bold cyan]Pilih [0-6] (default: 0):[/bold cyan] ").strip() or "0"
    platform_map = {"0": None, "1": "vercel", "2": "netlify", "3": "nginx",
                    "4": "apache", "5": "cloudflare", "6": "express"}
    export_platform = platform_map.get(cfg)

    # Konfirmasi
    console.print("\n[bold yellow]--- KONFIRMASI ---[/bold yellow]\n")
    console.print(f"  Target: {target}")
    console.print(f"  Mode  : {mode.upper()}")
    console.print(f"  Format: {fmt or 'tidak ada'}")
    console.print(f"  Config: {export_platform or 'Tidak'}\n")

    confirm = console.input("[bold cyan]Mulai scan? [Y/n]:[/bold cyan] ").strip().lower()
    if confirm == "n":
        console.print("[yellow]! Scan dibatalkan[/yellow]")
        sys.exit(0)

    console.print()
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, mode=mode, output=output,
               fmt=fmt if fmt else "html",
               export_platform=export_platform, no_banner=True)


# ==========================================
# COMMAND: web
# ==========================================
@cli.command()
@click.option("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
@click.option("--port", default=5000, type=int, help="Port (default: 5000)")
@click.option("--no-browser", is_flag=True, help="Jangan auto-open browser")
def web(host, port, no_browser):
    """Jalankan Web UI di localhost."""
    show_banner()
    try:
        from th0rsc4n.web.server import start_server
        start_server(host=host, port=port, open_browser=not no_browser)
    except ImportError:
        console.print("[red]X Web UI belum di-setup. Butuh Flask.[/red]")
        console.print("[yellow]Install: pip install flask[/yellow]")
        sys.exit(1)


# ==========================================
# COMMAND: headers
# ==========================================
@cli.command()
@click.argument("target", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output JSON")
def headers(target, as_json):
    """Cek security headers saja."""
    import requests
    import urllib3
    urllib3.disable_warnings()

    if not target:
        show_banner()
        target = console.input("[bold]URL target:[/bold] ").strip()

    if not is_valid_url(target):
        target = "https://" + target
    target = normalize_url(target)

    try:
        r = requests.get(target, timeout=10, verify=False)
    except Exception as e:
        console.print(f"[red]X Error: {e}[/red]")
        sys.exit(1)

    if as_json:
        console.print(json.dumps(dict(r.headers), indent=2))
        return

    show_banner()
    console.print(f"[bold cyan]Security Headers - {target}[/bold cyan]\n")

    from th0rsc4n.modules.m05_misconfig import SECURITY_HEADERS
    for header, meta in SECURITY_HEADERS.items():
        severity, desc, recommended = meta[0], meta[1], meta[2]
        if header in r.headers:
            console.print(f"  [green]OK[/green] [bold]{header}[/bold]")
            console.print(f"      [dim]{r.headers[header][:120]}[/dim]")
        else:
            console.print(f"  [red]X[/red] [bold]{header}[/bold] [dim]({desc})[/dim]")
            console.print(f"      [yellow]Recommended: {recommended[:80]}[/yellow]")


# ==========================================
# COMMAND: modes
# ==========================================
@cli.command()
def modes():
    """Lihat semua mode scan."""
    show_banner()
    console.print("[bold cyan]<< AVAILABLE SCAN MODES >>[/bold cyan]\n")

    table = Table(border_style="cyan", show_lines=True)
    table.add_column("Mode", style="bold", no_wrap=True)
    table.add_column("Flag", style="cyan", no_wrap=True)
    table.add_column("Deskripsi", style="white")
    table.add_column("Modules", style="yellow", justify="center")
    table.add_column("ETA", style="green", justify="center")

    for key, info in SCAN_MODES.items():
        table.add_row(
            f"{info['icon']} {info['name']}",
            f"-m {key}",
            info["description"],
            str(len(info["modules"])),
            info["eta"],
        )
    console.print(table)


# ==========================================
# COMMAND: quick / deep
# ==========================================
@cli.command()
@click.argument("target")
@click.option("-o", "--output", default=None, help="Output path")
def quick(target, output):
    """Shortcut: Quick scan."""
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, mode="quick", output=output)


@cli.command()
@click.argument("target")
@click.option("-o", "--output", default=None, help="Output path")
def deep(target, output):
    """Shortcut: Deep scan."""
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, mode="deep", output=output)


# ==========================================
# COMMAND: init
# ==========================================
@cli.command()
def init():
    """Inisialisasi config."""
    config = load_config()
    save_config(config)
    path = Path.home() / ".th0rsc4n" / "config.yml"
    console.print(f"[green]OK Config:[/green] {path}")


# ==========================================
# MAIN
# ==========================================
def main():
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]! Dibatalkan[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()