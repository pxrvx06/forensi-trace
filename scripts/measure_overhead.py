#!/usr/bin/env python3
"""
measure_overhead.py - Empirical Agent & Hybrid ML Overhead Study (Phase 3 Step 5).

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 5

Measures CPU (%) and RSS memory (MB) of:
1. ForensiTrace Endpoint Agent (`agent.main`)
2. FastAPI Backend + PyTorch LSTM Autoencoder (`AnomalyScorer` + `CorrelationEngine`)

Measured across two phases:
- Idle: Agent and Backend+ML running with no artificial file activity.
- Active Copy + ML Scoring: Copying 50 files (~10 MB total) in a watched directory while
  the agent captures, batches, and ships events, and the Hybrid Correlation Engine scores windows.

Outputs:
- report/overhead_results.json
- report/overhead_study.md
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.db import get_events_in_window, init_db
from engine.correlator import CorrelationEngine
from engine.ml.scoring import AnomalyScorer

logger = logging.getLogger("forensitrace.overhead")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def wait_for_health(url: str, timeout_sec: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.3)
    return False


def sample_process_metrics(
    procs: Dict[str, psutil.Process],
    duration_sec: float,
    interval_sec: float = 0.5,
) -> Dict[str, Dict[str, float]]:
    """Samples CPU (%) and RSS memory (MB) for each named process over duration_sec."""
    cpu_samples: Dict[str, List[float]] = {name: [] for name in procs}
    mem_samples: Dict[str, List[float]] = {name: [] for name in procs}

    # Prime cpu_percent counters
    for proc in procs.values():
        try:
            proc.cpu_percent(interval=None)
        except psutil.NoSuchProcess:
            pass

    steps = max(1, int(duration_sec / interval_sec))
    for _ in range(steps):
        time.sleep(interval_sec)
        for name, proc in procs.items():
            try:
                cpu = proc.cpu_percent(interval=None)
                rss_mb = proc.memory_info().rss / (1024.0 * 1024.0)
                cpu_samples[name].append(cpu)
                mem_samples[name].append(rss_mb)
            except psutil.NoSuchProcess:
                pass

    stats: Dict[str, Dict[str, float]] = {}
    for name in procs:
        cpus = cpu_samples[name] or [0.0]
        mems = mem_samples[name] or [0.0]
        stats[name] = {
            "cpu_avg_pct": round(sum(cpus) / len(cpus), 2),
            "cpu_peak_pct": round(max(cpus), 2),
            "rss_avg_mb": round(sum(mems) / len(mems), 2),
            "rss_peak_mb": round(max(mems), 2),
            "samples": len(cpus),
        }
    return stats


def run_overhead_study(
    idle_sec: float = 5.0,
    copy_files: int = 50,
    file_size_kb: int = 200,
    api_port: int = 8011,
    output_json: Optional[Path] = None,
    output_md: Optional[Path] = None,
) -> Dict[str, Any]:
    """Executes the idle vs active-copy overhead benchmark and writes JSON + Markdown reports."""
    out_json = output_json or (REPO_ROOT / "report" / "overhead_results.json")
    out_md = output_md or (REPO_ROOT / "report" / "overhead_study.md")

    api_proc: Optional[subprocess.Popen] = None
    agent_proc: Optional[subprocess.Popen] = None

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "overhead.db"
        watch_dir = tmp_path / "watched_copy_target"
        watch_dir.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        env = os.environ.copy()
        env["FORENSITRACE_DB_PATH"] = str(db_path)
        env["FORENSITRACE_BACKEND_URL"] = f"http://127.0.0.1:{api_port}"
        env["FORENSITRACE_WATCH_PATHS"] = str(watch_dir)

        try:
            # 1. Start Backend API
            logger.info("[overhead] [RECEIVED] Starting FastAPI backend on port %d...", api_port)
            api_proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "backend.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(api_port),
                ],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if not wait_for_health(f"http://127.0.0.1:{api_port}/health"):
                raise RuntimeError("Backend API failed to start for overhead study.")

            # 2. Load ML Scorer in-process to represent model memory/CPU footprint during scoring
            artifacts_dir = REPO_ROOT / "engine" / "ml" / "artifacts"
            scorer = AnomalyScorer(artifacts_dir=artifacts_dir)
            engine = CorrelationEngine(ml_scorer=scorer)

            # 3. Start Endpoint Agent subprocess watching watch_dir
            logger.info("[overhead] Starting ForensiTrace Agent watching '%s'...", watch_dir)
            agent_runner_code = (
                "import os, signal, sys, time; "
                "from agent.config import load_config; "
                "from agent.main import ForensiTraceAgent; "
                "cfg = load_config(); "
                "agent = ForensiTraceAgent(cfg); "
                "watch_dir = os.environ['FORENSITRACE_WATCH_PATHS']; "
                "agent.start(); "
                "[c._schedule_watch(watch_dir) for c in agent.collectors if hasattr(c, '_schedule_watch')]; "
                "signal.signal(signal.SIGTERM, lambda *_: (agent.stop(), sys.exit(0))); "
                "exec('try:\\n while True: time.sleep(0.5)\\nexcept KeyboardInterrupt:\\n agent.stop()')"
            )
            agent_proc = subprocess.Popen(
                [sys.executable, "-c", agent_runner_code],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2.5)  # Allow collectors to initialize

            procs = {
                "agent": psutil.Process(agent_proc.pid),
                "backend_api": psutil.Process(api_proc.pid),
                "ml_scorer_host": psutil.Process(os.getpid()),
            }

            # 4. Measure IDLE phase
            logger.info("[overhead] Measuring IDLE phase (%.1fs)...", idle_sec)
            idle_stats = sample_process_metrics(procs, duration_sec=idle_sec, interval_sec=0.5)

            # 5. Measure ACTIVE FILE COPY + ML SCORING phase
            logger.info(
                "[overhead] Measuring ACTIVE COPY phase (%d files x %d KB = %.2f MB)...",
                copy_files,
                file_size_kb,
                (copy_files * file_size_kb) / 1024.0,
            )
            payload_bytes = b"A" * (file_size_kb * 1024)
            copy_start = time.monotonic()

            # Prime CPU counters
            for p in procs.values():
                try:
                    p.cpu_percent(interval=None)
                except psutil.NoSuchProcess:
                    pass

            copy_cpus: Dict[str, List[float]] = {k: [] for k in procs}
            copy_mems: Dict[str, List[float]] = {k: [] for k in procs}

            for i in range(copy_files):
                target_file = watch_dir / f"report_{i:03d}.txt"
                target_file.write_bytes(payload_bytes)
                if i % 10 == 0:
                    time.sleep(0.25)
                    for name, proc in procs.items():
                        try:
                            copy_cpus[name].append(proc.cpu_percent(interval=None))
                            copy_mems[name].append(proc.memory_info().rss / (1024.0 * 1024.0))
                        except psutil.NoSuchProcess:
                            pass

            # Wait briefly for agent batch flush (flush_interval_seconds=2.0) + run ML correlation
            time.sleep(3.0)
            ml_start = time.monotonic()
            stored = get_events_in_window(
                ts_start_utc="2000-01-01T00:00:00.000Z",
                ts_end_utc="2099-12-31T23:59:59.999Z",
                db_path=db_path,
            )
            correlated = engine.correlate_events(stored)
            ml_elapsed_ms = round((time.monotonic() - ml_start) * 1000.0, 2)

            for name, proc in procs.items():
                try:
                    copy_cpus[name].append(proc.cpu_percent(interval=None))
                    copy_mems[name].append(proc.memory_info().rss / (1024.0 * 1024.0))
                except psutil.NoSuchProcess:
                    pass

            copy_elapsed_sec = round(time.monotonic() - copy_start, 2)
            active_stats: Dict[str, Dict[str, float]] = {}
            for name in procs:
                cpus = copy_cpus[name] or [0.0]
                mems = copy_mems[name] or [0.0]
                active_stats[name] = {
                    "cpu_avg_pct": round(sum(cpus) / len(cpus), 2),
                    "cpu_peak_pct": round(max(cpus), 2),
                    "rss_avg_mb": round(sum(mems) / len(mems), 2),
                    "rss_peak_mb": round(max(mems), 2),
                    "samples": len(cpus),
                }

            results = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "system": {
                    "os": platform.platform(),
                    "python": platform.python_version(),
                    "cpu_logical_cores": psutil.cpu_count(logical=True),
                    "total_ram_gb": round(psutil.virtual_memory().total / (1024.0 ** 3), 2),
                },
                "workload": {
                    "idle_duration_sec": idle_sec,
                    "copy_files_count": copy_files,
                    "file_size_kb": file_size_kb,
                    "total_copied_mb": round((copy_files * file_size_kb) / 1024.0, 2),
                    "copy_phase_elapsed_sec": copy_elapsed_sec,
                    "events_ingested": len(stored),
                    "activities_correlated": len(correlated),
                    "ml_correlation_latency_ms": ml_elapsed_ms,
                    "ml_model_loaded": scorer.is_available,
                },
                "idle": idle_stats,
                "active_copy_with_ml": active_stats,
            }

            out_json.parent.mkdir(parents=True, exist_ok=True)
            out_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

            md_lines = [
                "# ForensiTrace Agent & Hybrid ML Overhead Study",
                "",
                f"- **Measured At (UTC):** `{results['timestamp_utc']}`",
                f"- **Host OS:** `{results['system']['os']}`",
                f"- **Hardware:** {results['system']['cpu_logical_cores']} logical CPU cores, {results['system']['total_ram_gb']} GB RAM",
                f"- **Workload:** Idle ({idle_sec:.1f}s) vs. Active Copy ({copy_files} files, {results['workload']['total_copied_mb']} MB total) + Hybrid ML Correlation ({ml_elapsed_ms} ms)",
                "",
                "## Measured Resource Overhead",
                "",
                "| Component | State | Avg CPU (%) | Peak CPU (%) | Avg Memory (MB) | Peak Memory (MB) |",
                "|---|---|---:|---:|---:|---:|",
            ]
            for label, key in [
                ("Endpoint Agent", "agent"),
                ("FastAPI Backend", "backend_api"),
                ("ML Scorer + Engine (PyTorch CPU)", "ml_scorer_host"),
            ]:
                i_row = idle_stats[key]
                a_row = active_stats[key]
                md_lines.append(
                    f"| {label} | Idle | {i_row['cpu_avg_pct']:.2f} | {i_row['cpu_peak_pct']:.2f} | {i_row['rss_avg_mb']:.2f} | {i_row['rss_peak_mb']:.2f} |"
                )
                md_lines.append(
                    f"| {label} | Active Copy + ML | {a_row['cpu_avg_pct']:.2f} | {a_row['cpu_peak_pct']:.2f} | {a_row['rss_avg_mb']:.2f} | {a_row['rss_peak_mb']:.2f} |"
                )

            md_lines.extend([
                "",
                "## Key Observations",
                "",
                f"- **Idle Agent Footprint:** Average {idle_stats['agent']['cpu_avg_pct']:.2f}% CPU and {idle_stats['agent']['rss_avg_mb']:.2f} MB RSS.",
                f"- **Active Copy Agent Footprint:** Average {active_stats['agent']['cpu_avg_pct']:.2f}% CPU (peak {active_stats['agent']['cpu_peak_pct']:.2f}%) and {active_stats['agent']['rss_avg_mb']:.2f} MB RSS while monitoring {copy_files} rapid file writes.",
                f"- **Hybrid ML Inference Latency:** Correlating and scoring {len(stored)} captured events completed in **{ml_elapsed_ms} ms** on CPU.",
                "",
            ])
            out_md.write_text("\n".join(md_lines), encoding="utf-8")

            logger.info("[overhead] [PRODUCED] Saved JSON to '%s' and table to '%s'", out_json, out_md)
            return results

        finally:
            for proc in (agent_proc, api_proc):
                if proc and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        proc.kill()


def main() -> None:
    parser = argparse.ArgumentParser(description="ForensiTrace Overhead Benchmark (Phase 3 Step 5)")
    parser.add_argument("--idle-sec", type=float, default=5.0, help="Idle measurement duration in seconds")
    parser.add_argument("--copy-files", type=int, default=50, help="Number of files to copy in active phase")
    parser.add_argument("--file-size-kb", type=int, default=200, help="Size of each copied file in KB")
    parser.add_argument("--api-port", type=int, default=8011, help="Temporary backend port for benchmark")
    args = parser.parse_args()

    res = run_overhead_study(
        idle_sec=args.idle_sec,
        copy_files=args.copy_files,
        file_size_kb=args.file_size_kb,
        api_port=args.api_port,
    )
    print("\n" + (REPO_ROOT / "report" / "overhead_study.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
