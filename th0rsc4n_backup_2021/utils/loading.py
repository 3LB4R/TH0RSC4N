"""Animated loading screens untuk TH0RSC4N."""
import time
import threading
import random
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

console = Console()


# ==========================================
# SINIS HACKER QUOTES
# ==========================================
QUOTES = [
    "Hello, friend.",
    "Question everything.",
    "They're watching you.",
    "Trust no one.",
    "Stay paranoid.",
    "We are fsociety.",
    "Your password is 123456.",
    "Security is a joke.",
    "Firewall? More like wet paper.",
    "Nobody reads the logs.",
    "The weakest link is human.",
    "We don't break in. We log in.",
    "Privacy died in 2013.",
    "You call it hacking. I call it Tuesday.",
    "Access granted. You're welcome.",
    "Firewalls burn. Hackers adapt.",
    "The internet never forgets.",
    "If it's online, it's vulnerable.",
    "We are Legion.",
    "Expect us.",
]


class HackerLoading:
    """Loading hacker tegas — hijau neon matrix."""

    def __init__(self, message="SCANNING", submessage="accessing mainframe"):
        self.message = message
        self.submessage = submessage
        self.running = False
        self.thread = None
        self.frame = 0
        self.start_time = time.time()
        self.current_quote = ""
        self.last_quote_time = 0

    def _pick_quote(self):
        now = time.time()
        if now - self.last_quote_time > 1.5:
            self.current_quote = random.choice(QUOTES)
            self.last_quote_time = now
        return self.current_quote

    def _build_display(self):
        elapsed = time.time() - self.start_time
        quote = self._pick_quote()
        spinner = ["|", "/", "-", "\\"][self.frame % 4]
        dots = ["   ", ".  ", ".. ", "..."][(self.frame // 2) % 4]
        progress = min(100, int(elapsed * 3.5))
        filled = int(30 * progress / 100)
        bar = "█" * filled + "░" * (30 - filled)

        text = Text()
        text.append("  ██ ", style="bold bright_green")
        text.append("TH0RSC4N", style="bold bright_green")
        text.append(" ██  ", style="bold bright_green")
        text.append("// Security Researcher", style="bold white")
        text.append("\n\n")
        text.append(f'  "{quote}"', style="bright_green")
        text.append("\n\n")
        text.append("  [", style="bright_green")
        text.append(bar, style="bold bright_green")
        text.append("] ", style="bright_green")
        text.append(f"{progress:3}%", style="bold white")
        text.append("\n")
        text.append(f"  {spinner} ", style="bold bright_yellow")
        text.append(f"{self.message}{dots}", style="bold white")
        text.append("\n")
        text.append(f"  {self.submessage}", style="bright_green")

        return Panel(
            text,
            border_style="bright_green",
            padding=(1, 2),
            title="[bold bright_green]ENGINE[/bold bright_green]",
            title_align="left",
        )

    def _animate(self):
        with Live(
            self._build_display(),
            console=console,
            refresh_per_second=10,
            transient=True,
        ) as live:
            while self.running:
                live.update(self._build_display())
                time.sleep(0.15)
                self.frame += 1

    def start(self):
        self.running = True
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)


class QuickSpinner:
    def __init__(self, message="Loading..."):
        self.message = message
        self.status = None

    def start(self):
        self.status = console.status(
            f"[bold bright_green]{self.message}[/bold bright_green]",
            spinner="dots",
        )
        self.status.start()

    def stop(self, success=True):
        if self.status:
            self.status.stop()
        icon = "[bold bright_green]OK[/bold bright_green]" if success else "[bold bright_red]X[/bold bright_red]"
        console.print(f"{icon} [bold white]{self.message}[/bold white]")