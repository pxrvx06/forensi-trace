#!/usr/bin/env python3
"""
analyze_experiment.py - Human Experiment Results Analyzer (Phase 3 Step 6).

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML), Page 12

Reads participant investigation logs (CSV), computes per-tool average completion time
and correct answer counts (out of 5), and generates a Markdown summary table.
Explicitly avoids statistical significance claims per Plan v2 sample-size guidance.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
logger = logging.getLogger("forensitrace.experiment")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

QUESTION_COLS = [
    "q1_usb_device",
    "q2_files_copied",
    "q3_user_account",
    "q4_logs_cleared",
    "q5_event_order",
]


def load_and_analyze_csv(csv_path: Path) -> Dict[str, Any]:
    """Parses experiment CSV rows and computes per-tool summary metrics."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Experiment CSV not found: {csv_path}")

    rows: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            tool = (raw.get("tool") or "").strip()
            if not tool:
                continue
            time_sec = float(raw["time_seconds"])
            score = sum(int(raw[col]) for col in QUESTION_COLS)
            rows.append({
                "participant_id": raw["participant_id"].strip(),
                "run_order": int(raw["run_order"]),
                "tool": tool,
                "scenario": raw["scenario"].strip(),
                "time_seconds": time_sec,
                "score": score,
            })

    by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_tool.setdefault(r["tool"], []).append(r)

    summary: Dict[str, Any] = {
        "total_runs": len(rows),
        "unique_participants": len({r["participant_id"] for r in rows}),
        "tools": {},
    }

    for tool, t_rows in sorted(by_tool.items()):
        avg_time = round(sum(r["time_seconds"] for r in t_rows) / len(t_rows), 2)
        avg_score = round(sum(r["score"] for r in t_rows) / len(t_rows), 2)
        accuracy_pct = round((avg_score / 5.0) * 100.0, 1)
        summary["tools"][tool] = {
            "runs": len(t_rows),
            "avg_time_seconds": avg_time,
            "min_time_seconds": round(min(r["time_seconds"] for r in t_rows), 2),
            "max_time_seconds": round(max(r["time_seconds"] for r in t_rows), 2),
            "avg_correct_out_of_5": avg_score,
            "accuracy_pct": accuracy_pct,
        }

    return summary


def format_markdown_summary(summary: Dict[str, Any]) -> str:
    """Formats analysis summary as a GitHub-flavored Markdown table."""
    lines = [
        "# ForensiTrace Human Experiment Results",
        "",
        f"- **Unique Participants:** {summary['unique_participants']}",
        f"- **Total Investigation Runs:** {summary['total_runs']}",
        "",
        "| Tool | Runs | Avg Time (s) | Min–Max Time (s) | Avg Correct (/5) | Accuracy (%) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for tool, m in summary["tools"].items():
        lines.append(
            f"| {tool} | {m['runs']} | {m['avg_time_seconds']:.2f} | "
            f"{m['min_time_seconds']:.1f}–{m['max_time_seconds']:.1f} | "
            f"{m['avg_correct_out_of_5']:.2f} | {m['accuracy_pct']:.1f}% |"
        )
    lines.extend([
        "",
        "> **Note (Plan v2 Reporting Rule):** Given the small participant sample (8–10 classmates), "
        "results report descriptive averages and counts only without claiming statistical significance.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze ForensiTrace Human Experiment CSV")
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path(__file__).resolve().parent / "results.csv",
        help="Path to recorded participant results CSV",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Optional path to save Markdown summary table",
    )
    args = parser.parse_args()

    summary = load_and_analyze_csv(args.csv)
    md = format_markdown_summary(summary)
    print(md)

    if args.output_md:
        args.output_md.write_text(md, encoding="utf-8")
        logger.info("[PRODUCED] Saved summary table to '%s'", args.output_md)


if __name__ == "__main__":
    main()
