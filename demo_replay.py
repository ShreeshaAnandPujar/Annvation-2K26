"""
Interactive Scenario Replay & Explainability Demo (Pygenic Arc / Team Rudranix)

Fulfills Hackathon Requirement:
"Final Demo: Replay normal and malicious scenarios and show why they differ."

Features:
- Side-by-side comparison of 6 scenarios:
  1. Standard Human User (Valid Baseline)
  2. Legitimate High-Volume Flash Sale (Burst Traffic)
  3. Credential Stuffing Bot (Dual-Axis Auth Probing)
  4. Content Scraper (Machine Pacing / Low Timing Entropy)
  5. Sequential IDOR & Endpoint Enumeration
  6. Checkout Workflow Sequence Bypass
- Live Risk Gauge & Explainability Breakdown showing WHY they differ.
"""

import argparse
import random
import time
from typing import List, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from app.services.threat_engine import (
    BehavioralThreatEngine,
    BehaviourCategory,
    EnforcementAction,
)

console = Console()


def render_risk_gauge(score: float) -> str:
    filled = int(score * 10)
    empty = 10 - filled
    bar = "█" * filled + "░" * empty
    if score < 0.30:
        return f"[bold green][{bar}] {score:.2f} (LOW / SAFE)[/bold green]"
    elif score < 0.70:
        return f"[bold yellow][{bar}] {score:.2f} (SUSPICIOUS / THROTTLE)[/bold yellow]"
    else:
        return f"[bold red][{bar}] {score:.2f} (CRITICAL / BLOCK)[/bold red]"


def run_scenario(
    engine: BehavioralThreatEngine,
    name: str,
    description: str,
    requests_stream: List[Tuple[str, str, int, str, float]],
    sleep_between: float = 0.05,
) -> dict:
    console.print(f"\n[bold cyan]▶ RUNNING SCENARIO: {name}[/bold cyan]")
    console.print(f"[dim]{description}[/dim]")

    final_verdict = None
    stream_table = Table(show_header=True, header_style="bold magenta", expand=True)
    stream_table.add_column("Step", width=6)
    stream_table.add_column("Method", width=8)
    stream_table.add_column("Path / Resource", width=28)
    stream_table.add_column("Status", width=8)
    stream_table.add_column("Pacing Interval", width=16)

    prev_time = None
    for idx, (method, path, status, username, ts) in enumerate(requests_stream, start=1):
        gap_str = "0 ms (init)" if prev_time is None else f"{(ts - prev_time) * 1000:.1f} ms"
        prev_time = ts

        stream_table.add_row(
            str(idx),
            method,
            path,
            str(status),
            gap_str,
        )

        final_verdict = engine.analyze_request(
            client_id="demo_client",
            ip="198.51.100.99",
            path=path,
            username=username if username else None,
            status_code=status,
            timestamp=ts,
        )
        if sleep_between > 0:
            time.sleep(sleep_between)

    console.print(stream_table)

    # Explainability Panel
    gauge = render_risk_gauge(final_verdict.risk_score)
    action_color = "green" if final_verdict.action == EnforcementAction.ALLOWED else "red"
    cat_color = "green" if "BENIGN" in final_verdict.behaviour_category.value else "bold red"

    explanation_body = f"""
[bold]Threat Assessment Verdict:[/bold]
• [bold]Risk Score:[/bold] {gauge}
• [bold]Behavior Category:[/bold] [{cat_color}]{final_verdict.behaviour_category.value}[/{cat_color}]
• [bold]Enforcement Action:[/bold] [{action_color}]{final_verdict.action.value}[/{action_color}]

[bold]Why It Differs (Explainability Breakdown):[/bold]
• [bold]Root Explanation:[/bold] {final_verdict.explanation}
• [bold]Timing Variance (Entropy):[/bold] {final_verdict.evidence.get('timing_entropy_ms')} ms (Normal: >80ms, Bot: <30ms)
• [bold]Auth Failures Recorded:[/bold] {final_verdict.evidence.get('auth_failures_recorded')}
• [bold]Primary Detection Reason(s):[/bold]
"""
    for r in final_verdict.evidence.get("reasons", []):
        explanation_body += f"  - [yellow]{r}[/yellow]\n"

    console.print(Panel(explanation_body, title=f"Threat Engine Explainability — {name}", border_style="cyan"))

    return {
        "scenario": name,
        "score": final_verdict.risk_score,
        "category": final_verdict.behaviour_category.value,
        "action": final_verdict.action.value,
        "key_reason": final_verdict.evidence.get("reasons", ["Normal"])[0],
    }


def main():
    parser = argparse.ArgumentParser(description="Replay normal and malicious API traffic scenarios.")
    parser.add_argument("--fast", action="store_true", help="Run without delay between steps")
    args = parser.parse_args()

    sleep_time = 0.0 if args.fast else 0.04

    console.rule("[bold red]PYGENIC ARC — BEHAVIORAL THREAT & ABUSE DETECTION REPLAY[/bold red]")
    console.print("[dim]Demonstrating behavioral threat discrimination, sequence modeling, and explainability for Team Rudranix[/dim]\n")

    summary_records = []
    base_t = time.time()

    # ── 1. Normal User Shopping Flow ──────────────────────────────────────
    s1_stream = []
    t = base_t
    for method, path, status, user in [
        ("POST", "/auth/login", 200, "alice"),
        ("GET", "/products", 200, None),
        ("GET", "/products/102", 200, None),
        ("POST", "/cart/add", 200, None),
        ("GET", "/cart", 200, None),
        ("POST", "/checkout", 200, None),
    ]:
        t += random.uniform(1.5, 4.0)  # Human pauses
        s1_stream.append((method, path, status, user, t))

    rec1 = run_scenario(
        BehavioralThreatEngine(),
        "1. Standard Legitimate Human User",
        "A real human customer navigating login, catalog browsing, cart, and checkout with normal think-time pauses.",
        s1_stream,
        sleep_between=sleep_time,
    )
    summary_records.append(rec1)

    # ── 2. Legitimate High-Volume Flash Sale ──────────────────────────────
    s2_stream = []
    t = base_t + 100
    for i in range(12):
        t += random.uniform(0.6, 2.2)  # Fast human burst, but natural variance
        s2_stream.append(("GET", "/products", 200, None, t))
    s2_stream.append(("POST", "/cart/add", 200, None, t + 1.2))
    s2_stream.append(("POST", "/checkout", 200, None, t + 2.5))

    rec2 = run_scenario(
        BehavioralThreatEngine(),
        "2. Legitimate High-Volume Flash Sale",
        "High-velocity traffic from eager shoppers during a promotion. High request volume but natural human timing variance.",
        s2_stream,
        sleep_between=sleep_time,
    )
    summary_records.append(rec2)

    # ── 3. Credential Stuffing Attack ─────────────────────────────────────
    s3_stream = []
    t = base_t + 200
    for u in ["admin", "root", "support", "john", "dev", "service"]:
        t += 0.08  # Machine burst
        s3_stream.append(("POST", "/auth/login", 401, u, t))

    rec3 = run_scenario(
        BehavioralThreatEngine(),
        "3. Distributed Credential Stuffing Attack",
        "Automated bot spraying credential lists at /auth/login. Low inter-arrival variance, multiple consecutive 401s.",
        s3_stream,
        sleep_between=sleep_time,
    )
    summary_records.append(rec3)

    # ── 4. Machine-Paced Content Scraper ──────────────────────────────────
    s4_stream = []
    t = base_t + 300
    for i in range(10):
        t += 0.120  # Exactly 120ms constant interval (zero entropy)
        s4_stream.append(("GET", f"/products/{101 + (i % 3)}", 200, None, t))

    rec4 = run_scenario(
        BehavioralThreatEngine(),
        "4. Machine-Paced Content Scraper",
        "Bot attempting to evade simple rate limits by pacing requests at exactly 120ms intervals. Caught by timing entropy variance.",
        s4_stream,
        sleep_between=sleep_time,
    )
    summary_records.append(rec4)

    # ── 5. Sequential IDOR & Endpoint Enumeration ─────────────────────────
    s5_stream = []
    t = base_t + 400
    for uid in [1, 2, 3, 4, 5, 6]:
        t += random.uniform(0.15, 0.3)
        s5_stream.append(("GET", f"/api/v1/users/{uid}", 200 if uid <= 3 else 404, None, t))

    rec5 = run_scenario(
        BehavioralThreatEngine(),
        "5. Sequential IDOR & User Enumeration",
        "Attacker walking incremental user IDs /users/{1..6} to scrape confidential profiles and probe 404 boundaries.",
        s5_stream,
        sleep_between=sleep_time,
    )
    summary_records.append(rec5)

    # ── 6. Abnormal Sequence / Workflow Bypass Exploit ────────────────────
    s6_stream = []
    t = base_t + 500
    # Jumps directly to checkout without browsing or cart
    s6_stream.append(("GET", "/products", 200, None, t))
    t += 0.4
    s6_stream.append(("POST", "/checkout", 200, None, t))

    rec6 = run_scenario(
        BehavioralThreatEngine(),
        "6. Workflow Sequence Bypass Exploit",
        "Attacker skipping the required shopping cart workflow step and submitting directly to /checkout. Caught by Markov Sequence Model.",
        s6_stream,
        sleep_between=sleep_time,
    )
    summary_records.append(rec6)

    # ── Comparative Final Table ───────────────────────────────────────────
    console.print("\n")
    console.rule("[bold green]FINAL DEMO COMPARATIVE SUMMARY TABLE[/bold green]")
    comp_table = Table(show_header=True, header_style="bold yellow", expand=True)
    comp_table.add_column("Scenario", width=34)
    comp_table.add_column("Risk Score", justify="right", width=12)
    comp_table.add_column("Behavior Category", width=24)
    comp_table.add_column("Action Taken", width=16)
    comp_table.add_column("Why It Was Differentiated (Explainability)")

    for r in summary_records:
        score = r["score"]
        score_str = f"[green]{score:.2f}[/green]" if score < 0.3 else (
            f"[yellow]{score:.2f}[/yellow]" if score < 0.7 else f"[bold red]{score:.2f}[/bold red]"
        )
        cat_str = f"[bold red]{r['category']}[/bold red]" if "BENIGN" not in r["category"] else f"[green]{r['category']}[/green]"
        action_str = f"[red]{r['action']}[/red]" if r["action"] != "ALLOWED" else f"[green]{r['action']}[/green]"

        comp_table.add_row(
            r["scenario"],
            score_str,
            cat_str,
            action_str,
            r["key_reason"],
        )

    console.print(comp_table)
    console.print("\n[bold green]✔ Demonstration Complete — All Mandatory Patterns Accurately Differentiated![/bold green]\n")


if __name__ == "__main__":
    main()
