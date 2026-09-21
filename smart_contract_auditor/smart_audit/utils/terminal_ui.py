"""
terminal_ui.py
Rich-based terminal presentation layer for ChainGuard's CLI output.

Two concerns kept deliberately separate:
- The polished, audience-facing output built here (banner, live per-agent
  status, verdict cards, summary table).
- api_router.py's raw dispatch diagnostics (role/provider/model/latency),
  gated behind CHAINGUARD_VERBOSE=1 rather than shown by default -- useful
  for real debugging, noise during a demo/presentation.
"""

import threading
import time
from datetime import timedelta

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.box import ROUNDED

from smart_audit.agents.schemas import DebateRecord, Verdict

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "banner": "bold magenta",
    "path": "bold cyan",
})

console = Console(theme=custom_theme)

VERDICT_STYLE = {
    Verdict.CONFIRMED: "bold red",
    Verdict.FALSE_POSITIVE: "bold green",
    Verdict.INCONCLUSIVE: "bold yellow",
}

VERDICT_LABEL = {
    Verdict.CONFIRMED: "CONFIRMED",
    Verdict.FALSE_POSITIVE: "FALSE POSITIVE",
    Verdict.INCONCLUSIVE: "INCONCLUSIVE",
}

ROLE_LABEL = {
    "prosecutor": "ProsecutorAgent",
    "defender": "DefenderAgent",
    "judge": "JudgeAgent",
}


# ---------- Intro (replaces the old step-by-step Phase 1 output) ----------

def print_banner():
    """Tool name banner. Everything else follows two blank lines later."""
    console.print("[banner]== Smart Contract Security Auditor ==[/banner]")
    console.print()
    console.print()


def print_analyzing(contract_path) -> None:
    console.print(f"[info]→[/info] Analyzing contract: [path]{contract_path}[/path]")


def print_findings_ready(count: int) -> None:
    plural = "y" if count == 1 else "ies"
    console.print(f"[success]✓[/success] Found {count} vulnerabilit{plural} to analyze")


def print_courtroom_header() -> None:
    console.print()
    console.print()
    console.print("[banner]== Running Courtroom Analysis ==[/banner]")
    console.print()


# kept for error paths / anything else in cli.py that still calls these
def print_info(message: str):
    console.print(f"[info][i][/info] {message}")


def print_success(message: str):
    console.print(f"[success][✓][/success] {message}")


def print_warning(message: str):
    console.print(f"[warning][!][/warning] {message}")


def print_error(message: str):
    console.print(f"[error][✘][/error] {message}")


# ---------- Live per-agent status (spinner + elapsed counter) ----------

class AgentStatus:
    """
    Context manager: shows a spinner with a live-updating elapsed-time
    counter while one agent call (prosecutor/defender/judge) is in flight,
    then replaces it with a single completed (or failed) line.

    The counter ticks on a background thread because the actual API call
    happening inside the `with` block is a blocking synchronous request --
    nothing else would advance the display on the main thread otherwise.
    """

    def __init__(self, role: str, detail: str):
        self.role = role
        self.label = ROLE_LABEL.get(role, role.title())
        self.detail = detail
        self._start = None
        self._stop_evt = threading.Event()
        self._thread = None
        self._live = None
        self._spinner = None

    def _elapsed_str(self) -> str:
        elapsed = time.monotonic() - self._start
        return str(timedelta(seconds=int(elapsed)))

    def _tick(self):
        while not self._stop_evt.wait(0.5):
            if self._spinner:
                self._spinner.update(text=f"{self.label}: analyzing {self.detail}... {self._elapsed_str()}")

    def __enter__(self):
        self._start = time.monotonic()
        self._spinner = Spinner("dots", text=f"{self.label}: analyzing {self.detail}... 0:00:00")
        self._live = Live(self._spinner, console=console, refresh_per_second=8, transient=True)
        self._live.start()
        self._thread = threading.Thread(target=self._tick, daemon=True)
        self._thread.start()
        return self

    def _stop_display(self):
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=1)
        if self._live:
            self._live.stop()

    def finish(self, provider: str | None = None, model: str | None = None, degraded: bool = False):
        """Call once the agent call succeeds, with route_meta's fields."""
        elapsed = self._elapsed_str()
        self._stop_display()
        model_part = f" — [dim]{provider}/{model}[/dim]" if provider and model else ""
        degraded_part = " [warning](degraded)[/warning]" if degraded else ""
        console.print(f"[success]✓[/success] {self.label} done in {elapsed}{model_part}{degraded_part}")

    def fail(self, error: str):
        elapsed = self._elapsed_str()
        self._stop_display()
        console.print(f"[error]✘[/error] {self.label} failed after {elapsed}: {error}")

    def __exit__(self, exc_type, exc, tb):
        # safety net: if finish()/fail() wasn't called before an exception
        # propagated out of the `with` block, stop the live display cleanly
        if not self._stop_evt.is_set():
            self._stop_display()
        return False


# ---------- Verdict cards + summary ----------

def _confidence_bar(confidence: float, width: int = 20) -> Text:
    """Colored by magnitude, not verdict -- confidence and verdict severity
    are independent axes per schemas.py's field description."""
    filled = round(confidence * width)
    color = "green" if confidence >= 0.7 else "yellow" if confidence >= 0.4 else "red"
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="dim")
    bar.append(f"  {confidence * 100:.0f}%", style=color)
    return bar


def print_verdict_card(record: DebateRecord, finding: dict):
    """
    One panel per finding. finding: the original finding dict (for
    check/contract_name/impact -- DebateRecord doesn't carry these itself,
    only finding_id + contract_hash).
    """
    verdict = record.judge.verdict
    style = VERDICT_STYLE[verdict]
    label = VERDICT_LABEL[verdict]

    body = Table.grid(padding=(0, 1))
    body.add_column(style="dim", justify="right")
    body.add_column()

    body.add_row("Detector:", finding.get("check", "?"))
    body.add_row("Contract:", finding.get("contract_name", "?"))
    body.add_row(
        "Severity:",
        (record.judge.final_severity.value if record.judge.final_severity else finding.get("impact", "?"))
    )
    body.add_row("Confidence:", _confidence_bar(record.judge.confidence))
    body.add_row("")
    body.add_row("Prosecutor:", record.prosecutor.charge_summary)
    body.add_row("Defender:", record.defender.rebuttal_summary)
    body.add_row("")
    body.add_row("Verdict reasoning:", record.judge.reasoning)

    if record.judge.patch_recommendation:
        body.add_row("")
        body.add_row("[bold]Patch:[/bold]", record.judge.patch_recommendation)

    if record.degraded_mode:
        body.add_row("")
        body.add_row("", "[warning]⚠ ran in degraded mode (fallback provider/model)[/warning]")

    console.print(
        Panel(
            body,
            title=f"[{style}]{label}[/{style}] — {record.finding_id}",
            border_style=style,
            box=ROUNDED,
            padding=(1, 2),
        )
    )
    console.print()


def print_summary_table(records: list[DebateRecord]):
    """Final run summary table + one-line verdict counts. Deliberately does
    NOT print a degraded-count line -- per-row ⚠ markers already cover it,
    and a repeated summary line was cut as redundant for a demo audience."""
    table = Table(title="Audit Summary", box=ROUNDED, show_lines=False)
    table.add_column("Finding ID", style="dim")
    table.add_column("Detector")
    table.add_column("Verdict", justify="center")
    table.add_column("Confidence", justify="right")
    table.add_column("Degraded", justify="center")

    counts = {Verdict.CONFIRMED: 0, Verdict.FALSE_POSITIVE: 0, Verdict.INCONCLUSIVE: 0}

    for r in records:
        v = r.judge.verdict
        counts[v] += 1
        style = VERDICT_STYLE[v]
        table.add_row(
            r.finding_id,
            r.prosecutor.charge_summary[:40] + ("…" if len(r.prosecutor.charge_summary) > 40 else ""),
            f"[{style}]{VERDICT_LABEL[v]}[/{style}]",
            f"{r.judge.confidence * 100:.0f}%",
            "⚠" if r.degraded_mode else "",
        )

    console.print(table)
    console.print()

    total = len(records)
    console.print(
        f"[bold red]{counts[Verdict.CONFIRMED]} confirmed[/bold red]  ·  "
        f"[bold green]{counts[Verdict.FALSE_POSITIVE]} false positive[/bold green]  ·  "
        f"[bold yellow]{counts[Verdict.INCONCLUSIVE]} inconclusive[/bold yellow]"
        f"  ({total} total)"
    )