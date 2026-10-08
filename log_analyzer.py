"""
Offline API Access Log & Sequence Threat Analyzer (Pygenic Arc)

Processes synthetic or open API access logs (JSON/CSV) and evaluates them against
the Behavioral Threat Engine.

Fulfills Hackathon Requirements:
- Input: Synthetic / open API access logs and request sequences.
- Output: Standardized schema with (risk_score, behaviour_category, evidence).
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List

from app.services.threat_engine import BehavioralThreatEngine, ThreatVerdict


def load_logs(file_path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    logs = []
    if file_path.endswith(".json"):
        with open(file_path, "r") as f:
            logs = json.load(f)
    elif file_path.endswith(".csv"):
        with open(file_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                logs.append({
                    "timestamp": float(row["timestamp"]),
                    "client_id": row["client_id"],
                    "client_ip": row["client_ip"],
                    "method": row["method"],
                    "path": row["path"],
                    "status_code": int(row["status_code"]),
                    "username": row.get("username", ""),
                    "label": row.get("label", "UNKNOWN"),
                })
    else:
        raise ValueError("Unsupported format. Please provide .json or .csv access logs.")

    logs.sort(key=lambda x: x["timestamp"])
    return logs


def analyze_log_stream(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    engine = BehavioralThreatEngine()
    client_verdicts: Dict[str, ThreatVerdict] = {}
    client_metadata: Dict[str, Dict[str, Any]] = defaultdict(dict)

    for entry in logs:
        client_id = entry["client_id"]
        ip = entry["client_ip"]
        path = entry["path"]
        status = entry.get("status_code", 200)
        ts = entry.get("timestamp")
        username = entry.get("username")

        verdict = engine.analyze_request(
            client_id=client_id,
            ip=ip,
            path=path,
            username=username,
            status_code=status,
            timestamp=ts,
        )
        client_verdicts[client_id] = verdict
        client_metadata[client_id]["ip"] = ip
        client_metadata[client_id]["ground_truth"] = entry.get("label", "UNKNOWN")
        client_metadata[client_id]["scenario"] = entry.get("scenario_name", "N/A")

    # Construct standardized output schema
    results = []
    for client_id, verdict in client_verdicts.items():
        results.append({
            "session_id": client_id,
            "client_ip": client_metadata[client_id]["ip"],
            "ground_truth_label": client_metadata[client_id]["ground_truth"],
            "risk_score": round(verdict.risk_score, 3),
            "behaviour_category": verdict.behaviour_category.value,
            "enforcement_action": verdict.action.value,
            "explanation": verdict.explanation,
            "evidence": verdict.evidence,
        })

    return results


def print_formatted_summary(results: List[Dict[str, Any]]):
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Pygenic Arc — API Abuse & Behavioral Threat Assessment", show_lines=True)
        table.add_column("Session / Client ID", style="cyan", no_wrap=True)
        table.add_column("Client IP", style="magenta")
        table.add_column("Risk Score", justify="right")
        table.add_column("Detected Category", style="bold")
        table.add_column("Action", style="bold")
        table.add_column("Key Explainable Evidence")

        for r in results:
            score = r["risk_score"]
            cat = r["behaviour_category"]
            action = r["enforcement_action"]

            score_str = f"[green]{score:.2f}[/green]" if score < 0.3 else (
                f"[yellow]{score:.2f}[/yellow]" if score < 0.7 else f"[bold red]{score:.2f}[/bold red]"
            )
            cat_str = f"[bold red]{cat}[/bold red]" if "BENIGN" not in cat else f"[green]{cat}[/green]"
            action_str = f"[red]{action}[/red]" if action != "ALLOWED" else f"[green]{action}[/green]"

            evidence_summary = r["evidence"]["reasons"][0] if r["evidence"].get("reasons") else "Normal baseline"

            table.add_row(
                r["session_id"],
                r["client_ip"],
                score_str,
                cat_str,
                action_str,
                evidence_summary,
            )

        console.print(table)
    except ImportError:
        print("\n=== Behavioral Threat Assessment Summary ===")
        for r in results:
            print(f"Session: {r['session_id']:<18} | IP: {r['client_ip']:<15} | Risk: {r['risk_score']:<5} | Category: {r['behaviour_category']:<22} | Action: {r['enforcement_action']}")


def main():
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent
    default_input = str(base_dir / "data" / "synthetic_api_logs.json")
    default_output = str(base_dir / "output" / "threat_assessment_results.json")

    parser = argparse.ArgumentParser(description="Analyze API access logs for behavioral abuse.")
    parser.add_argument(
        "file_pos",
        nargs="?",
        default=None,
        help="Positional path to access log file (JSON or CSV)",
    )
    parser.add_argument(
        "--file",
        "-f",
        default=None,
        help="Path to access log file (JSON or CSV)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=default_output,
        help="Path to save JSON evaluation report",
    )
    args = parser.parse_args()
    target_file = args.file_pos or args.file or default_input

    print(f"Loading and processing log dataset from: {target_file}...")
    logs = load_logs(target_file)
    results = analyze_log_stream(logs)

    # Save output JSON
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nEvaluated {len(logs)} log requests across {len(results)} distinct client sessions.")
    print(f"Results written to: {args.output}\n")
    print_formatted_summary(results)


if __name__ == "__main__":
    main()
