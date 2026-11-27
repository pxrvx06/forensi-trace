#!/usr/bin/env python3
"""
run_demo.py - One-Command End-to-End Demo Runner for ForensiTrace (Phase 3 Step 4).

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 4

Orchestrates a complete live demonstration from a fresh clone:
1. Reset SQLite database (backend/forensitrace.db)
2. Load trained PyTorch LSTM Autoencoder model & threshold (engine/ml/artifacts/)
3. Start FastAPI backend server (uvicorn backend.main:app)
4. Run Scenario A (or chosen scenario) and ingest telemetry into the backend
5. Run Hybrid Correlation Engine (Rules R1-R7 + ML AnomalyScorer) and persist activities
6. Install npm dependencies if missing, then start the React dashboard (dashboard/)
7. Open the dashboard in the default web browser and keep services running until Ctrl+C
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.db import (
    DEFAULT_DB_PATH,
    get_events_in_window,
    init_db,
    insert_activity,
    insert_events_batch,
    reset_db,
)
from engine.correlator import CorrelationEngine
from engine.ml.scoring import AnomalyScorer
from scenarios.normal_noise import generate_normal_noise_events
from scenarios.scenario_a import generate_scenario_a_events
from scenarios.scenario_a_prime import generate_scenario_a_prime_events
from scenarios.scenario_b import generate_scenario_b_events
from scenarios.scenario_c import generate_scenario_c_events

logger = logging.getLogger("forensitrace.run_demo")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SCENARIO_GENERATORS: Dict[str, Callable[[], List[Dict[str, Any]]]] = {
    "scenario_a": generate_scenario_a_events,
    "scenario_a_prime": generate_scenario_a_prime_events,
    "scenario_b": generate_scenario_b_events,
    "scenario_c": generate_scenario_c_events,
    "normal_noise": generate_normal_noise_events,
}


def wait_for_http(url: str, timeout_sec: float = 30.0, interval_sec: float = 0.5) -> bool:
    """Polls an HTTP endpoint until it returns status < 500 or timeout expires."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                if resp.status < 500:
                    return True
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            pass
        time.sleep(interval_sec)
    return False


def post_events_to_api(api_url: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Posts a list of normalized events to the running FastAPI /events endpoint."""
    payload = json.dumps({"events": events, "batch_size": len(events)}).encode("utf-8")
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/events",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_ml_scorer(artifacts_dir: Optional[Path] = None) -> AnomalyScorer:
    """Loads the trained LSTM autoencoder and threshold metadata from engine/ml/artifacts."""
    target_dir = artifacts_dir or (REPO_ROOT / "engine" / "ml" / "artifacts")
    logger.info("[load_ml_scorer] [RECEIVED] Loading ML artifacts from '%s'", target_dir)
    scorer = AnomalyScorer(artifacts_dir=target_dir)
    if scorer.is_available:
        threshold = scorer.threshold_metadata.threshold if scorer.threshold_metadata else None
        logger.info(
            "[load_ml_scorer] [PRODUCED] Trained LSTM Autoencoder loaded (threshold=%s)",
            threshold,
        )
    else:
        logger.warning(
            "[load_ml_scorer] [PRODUCED] Trained ML artifacts unavailable at '%s'; falling back to rules-only mode",
            target_dir,
        )
    return scorer


def run_correlation_and_persist(
    db_path: Path,
    scorer: Optional[AnomalyScorer],
) -> List[Any]:
    """Queries all events from SQLite, runs Hybrid CorrelationEngine, and persists activities."""
    events = get_events_in_window(
        ts_start_utc="2000-01-01T00:00:00.000Z",
        ts_end_utc="2099-12-31T23:59:59.999Z",
        db_path=db_path,
    )
    logger.info(
        "[run_correlation] [RECEIVED] Correlating %d event(s) from '%s'",
        len(events),
        db_path,
    )
    engine = CorrelationEngine(ml_scorer=scorer)
    correlated = engine.correlate_events(events)

    for res in correlated:
        insert_activity(res.activity, res.links, db_path=db_path)

    logger.info(
        "[run_correlation] [PRODUCED] Persisted %d correlated activity chain(s)",
        len(correlated),
    )
    return correlated


def ensure_dashboard_dependencies(dashboard_dir: Path) -> None:
    """Installs npm dependencies in dashboard/ if node_modules is missing (fresh clone support)."""
    node_modules = dashboard_dir / "node_modules"
    if node_modules.exists():
        return

    npm_cmd = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm_cmd:
        raise RuntimeError(
            "npm was not found on PATH. Install Node.js (v18+) to launch the React dashboard."
        )

    logger.info(
        "[ensure_dashboard_dependencies] [RECEIVED] Installing React dashboard dependencies in '%s'...",
        dashboard_dir,
    )
    subprocess.run([npm_cmd, "install"], cwd=str(dashboard_dir), check=True)
    logger.info("[ensure_dashboard_dependencies] [PRODUCED] Dashboard dependencies installed.")


def terminate_process(proc: Optional[subprocess.Popen], name: str) -> None:
    """Gracefully terminates a child subprocess."""
    if proc is None or proc.poll() is not None:
        return
    logger.info("[shutdown] Stopping %s (pid=%d)...", name, proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)


def run_demo(
    scenario: str = "scenario_a",
    db_path: Optional[Path] = None,
    api_port: int = 8000,
    dashboard_port: int = 5173,
    open_browser: bool = True,
    start_dashboard: bool = True,
    setup_only: bool = False,
) -> Dict[str, Any]:
    """
    Executes the full ForensiTrace Phase 3 demo workflow.
    Returns a summary dictionary of ingested events and reconstructed activities.
    """
    if scenario not in SCENARIO_GENERATORS:
        raise ValueError(f"Unknown scenario '{scenario}'. Valid options: {list(SCENARIO_GENERATORS.keys())}")

    target_db = Path(db_path or DEFAULT_DB_PATH)
    api_url = f"http://127.0.0.1:{api_port}"
    dashboard_url = f"http://127.0.0.1:{dashboard_port}"
    dashboard_dir = REPO_ROOT / "dashboard"

    # 1. Reset SQLite database
    logger.info("[run_demo] [RECEIVED] Resetting database at '%s'", target_db)
    init_db(target_db)
    reset_db(target_db)
    logger.info("[run_demo] [PRODUCED] Clean database ready")

    # 2. Load trained ML model
    scorer = load_ml_scorer()

    api_proc: Optional[subprocess.Popen] = None
    dash_proc: Optional[subprocess.Popen] = None

    try:
        env = os.environ.copy()
        env["FORENSITRACE_DB_PATH"] = str(target_db)

        # 3. Start FastAPI backend (unless setup_only)
        if not setup_only:
            logger.info("[run_demo] Starting FastAPI backend on %s ...", api_url)
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
            )
            if not wait_for_http(f"{api_url}/health", timeout_sec=25.0):
                raise RuntimeError(f"FastAPI backend failed to respond on {api_url}/health")
            logger.info("[run_demo] [PRODUCED] Backend API is healthy at %s", api_url)

        # 4. Generate and ingest scenario events
        events = SCENARIO_GENERATORS[scenario]()
        logger.info("[run_demo] Running '%s' (%d events)...", scenario, len(events))
        if not setup_only:
            ingest_resp = post_events_to_api(api_url, events)
            logger.info("[run_demo] [PRODUCED] API ingested events: %s", ingest_resp)
        else:
            inserted, dups = insert_events_batch(events, db_path=target_db)
            logger.info("[run_demo] [PRODUCED] Direct DB ingest: %d inserted, %d duplicates", inserted, dups)

        # 5. Run Hybrid Correlation Engine (Rules + ML) and persist activities
        correlated = run_correlation_and_persist(target_db, scorer)

        print("\n=== ForensiTrace Demo Summary ===")
        print(f"Scenario          : {scenario}")
        print(f"Events Ingested   : {len(events)}")
        print(f"ML Model Loaded   : {scorer.is_available}")
        print(f"Activities Found  : {len(correlated)}")
        for res in correlated:
            act = res.activity
            print(
                f"  - {act.activity_id} | Rule={act.rule_id} | "
                f"Confidence={act.confidence:.2f} | ML={act.ml_anomaly_score} | "
                f"Threat={act.threat_level}"
            )
        print("=================================\n")

        summary = {
            "scenario": scenario,
            "events_count": len(events),
            "ml_available": scorer.is_available,
            "activities_count": len(correlated),
            "activity_ids": [r.activity.activity_id for r in correlated],
            "rules_triggered": sorted({r.activity.rule_id for r in correlated}),
        }

        if setup_only:
            return summary

        # 6. Start React dashboard
        if start_dashboard:
            ensure_dashboard_dependencies(dashboard_dir)
            npm_cmd = shutil.which("npm.cmd") or shutil.which("npm")
            if not npm_cmd:
                raise RuntimeError("npm was not found on PATH.")
            logger.info("[run_demo] Starting React dashboard on %s ...", dashboard_url)
            dash_proc = subprocess.Popen(
                [npm_cmd, "run", "dev", "--", "--port", str(dashboard_port)],
                cwd=str(dashboard_dir),
                env=env,
            )
            if not wait_for_http(dashboard_url, timeout_sec=30.0):
                logger.warning("Dashboard dev server did not respond within 30s at %s", dashboard_url)
            else:
                logger.info("[run_demo] [PRODUCED] Dashboard ready at %s", dashboard_url)

            # 7. Open browser
            if open_browser:
                logger.info("[run_demo] Opening browser at %s ...", dashboard_url)
                webbrowser.open(dashboard_url)

        print(f"Backend API Docs : {api_url}/docs")
        if start_dashboard:
            print(f"React Dashboard  : {dashboard_url}")
        print("Press Ctrl+C to stop the demo servers.\n")

        # Keep alive until interrupted
        while True:
            if api_proc and api_proc.poll() is not None:
                raise RuntimeError(f"Backend API exited unexpectedly with code {api_proc.returncode}")
            if dash_proc and dash_proc.poll() is not None:
                raise RuntimeError(f"Dashboard dev server exited unexpectedly with code {dash_proc.returncode}")
            time.sleep(1.0)

    except KeyboardInterrupt:
        logger.info("[run_demo] Received Ctrl+C, shutting down...")
        return summary if "summary" in locals() else {}
    finally:
        terminate_process(dash_proc, "React dashboard")
        terminate_process(api_proc, "FastAPI backend")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ForensiTrace One-Command Demo Runner (Phase 3 Step 4)"
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIO_GENERATORS.keys()),
        default="scenario_a",
        help="Scenario to replay into the demo (default: scenario_a)",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help=f"Custom SQLite DB path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=8000,
        help="Port for FastAPI backend (default: 8000)",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=5173,
        help="Port for React Vite dashboard (default: 5173)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open the web browser",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Start only the backend API and skip the React dashboard",
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="Reset DB, load model, ingest scenario, correlate, and exit without starting servers",
    )
    args = parser.parse_args()

    run_demo(
        scenario=args.scenario,
        db_path=args.db,
        api_port=args.api_port,
        dashboard_port=args.dashboard_port,
        open_browser=not args.no_browser,
        start_dashboard=not args.no_dashboard,
        setup_only=args.setup_only,
    )


if __name__ == "__main__":
    main()
