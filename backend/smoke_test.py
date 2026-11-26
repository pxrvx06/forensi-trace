"""
ForensiTrace End-to-End Backend Smoke Test
Author: Purva (Backend & Data Layer Owner)
Contract: Execution Plan v2 Step 6

Validates the complete pipeline in one command using an isolated temporary SQLite database:
Scenario Events -> Schema Validation -> API Ingestion -> SQLite Storage ->
Hybrid Correlation Engine (Rules + LSTM ML) -> Activity Persistence ->
Unified /timeline API -> 3-Page Forensic PDF Report Generation.

Prints a clear PASS or FAIL result and exits 0 or 1.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.db import get_events_in_window, init_db, insert_activity
from backend.main import (
    download_activity_report,
    get_single_activity,
    get_unified_timeline,
    health_check,
    ingest_events,
)
from backend.schema import EventBatch
from engine.correlator import CorrelationEngine
from engine.ml.scoring import AnomalyScorer

logger = logging.getLogger("forensitrace.smoke_test")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def run_smoke_test() -> bool:
    """Executes the end-to-end backend + hybrid engine smoke test."""
    logger.info("[run_smoke_test] [RECEIVED] Starting end-to-end smoke test")
    scenario_path = REPO_ROOT / "scenarios" / "ground_truth" / "scenario_a.json"
    artifacts_dir = REPO_ROOT / "engine" / "ml" / "artifacts"

    if not scenario_path.exists():
        logger.error("[run_smoke_test] Missing Scenario A fixture at %s", scenario_path)
        return False

    with open(scenario_path, "r", encoding="utf-8") as f:
        scenario_data = json.load(f)
    raw_events = scenario_data.get("events", [])
    if not raw_events:
        logger.error("[run_smoke_test] Scenario A contains no events")
        return False

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "smoke_test.db"
        old_env = os.environ.get("FORENSITRACE_DB_PATH")
        os.environ["FORENSITRACE_DB_PATH"] = str(db_path)

        try:
            # 1. Initialize isolated SQLite DB & verify health endpoint
            init_db(db_path)
            health = health_check()
            assert health.get("status") == "ok", f"Health check failed: {health}"

            # 2. Schema validation & API Ingestion (/events)
            batch = EventBatch(events=raw_events)
            ingest_res = ingest_events(batch)
            assert ingest_res.inserted == len(raw_events), (
                f"Expected {len(raw_events)} inserted events, got {ingest_res.inserted}"
            )
            # Idempotency check
            dup_res = ingest_events(batch)
            assert dup_res.duplicates_ignored == len(raw_events), "Duplicate batch should be ignored"

            # 3. Query events back from SQLite window
            stored_events = get_events_in_window(
                ts_start_utc="2000-01-01T00:00:00.000Z",
                ts_end_utc="2099-12-31T23:59:59.999Z",
                db_path=db_path,
            )
            assert len(stored_events) == len(raw_events), "Window query count mismatch"

            # 4. Run Hybrid Correlation Engine (Rules + Trained ML Autoencoder)
            scorer = AnomalyScorer(artifacts_dir=artifacts_dir)
            assert scorer.is_available, "Trained ML AnomalyScorer must be available"
            engine = CorrelationEngine(ml_scorer=scorer)
            correlated = engine.correlate_events(stored_events)
            assert len(correlated) >= 1, "CorrelationEngine should reconstruct at least 1 activity for Scenario A"

            # Check expected rule R7 triggered with ML score and CRITICAL threat level
            triggered_rules = {c.activity.rule_id for c in correlated}
            assert "R7" in triggered_rules, f"Expected rule R7 in Scenario A, got {triggered_rules}"

            # 5. Persist reconstructed activities into SQLite
            for res in correlated:
                assert res.activity.ml_anomaly_score is not None, "Expected non-null ml_anomaly_score"
                assert res.activity.threat_level in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
                insert_activity(res.activity, res.links, db_path=db_path)

            # 6. Verify /timeline API returns merged chronological stream
            timeline_res = get_unified_timeline(limit=100, offset=0, source=None, order="asc")
            timeline_items = timeline_res.get("timeline", [])
            item_types = {item["type"] for item in timeline_items}
            assert "event" in item_types and "activity" in item_types, (
                f"Timeline must include both events and activities, got {item_types}"
            )
            # Check chronological sort invariant
            timestamps = [item["ts_utc"] for item in timeline_items]
            assert timestamps == sorted(timestamps), "Timeline items are not strictly sorted by ts_utc"

            # 7. Verify /activities/{id} and /report/{activity_id} 3-page PDF stream
            r7_act = next(c.activity for c in correlated if c.activity.rule_id == "R7")
            act_detail = get_single_activity(r7_act.activity_id)
            assert len(act_detail.get("evidence_chain", [])) >= 3, "Evidence provenance chain incomplete"

            pdf_response = download_activity_report(r7_act.activity_id)
            assert pdf_response.media_type == "application/pdf"
            assert pdf_response.body.startswith(b"%PDF-"), "Invalid PDF stream header"
            page_count = len(re.findall(rb"/Type\s*/Page(?!s)\b", pdf_response.body))
            assert page_count == 3, f"Expected 3-page forensic report, got {page_count} pages"

            logger.info(
                "[run_smoke_test] [PRODUCED] Verified %d events -> %d activities -> %d timeline items -> %d-byte 3-page PDF",
                len(stored_events),
                len(correlated),
                len(timeline_items),
                len(pdf_response.body),
            )
            return True

        except Exception as exc:
            logger.error("[run_smoke_test] Smoke test assertion failed: %s", exc, exc_info=True)
            return False

        finally:
            if old_env is None:
                os.environ.pop("FORENSITRACE_DB_PATH", None)
            else:
                os.environ["FORENSITRACE_DB_PATH"] = old_env


if __name__ == "__main__":
    passed = run_smoke_test()
    if passed:
        print("\n========================================")
        print("FORENSITRACE END-TO-END SMOKE TEST: PASS")
        print("========================================")
        sys.exit(0)
    else:
        print("\n========================================")
        print("FORENSITRACE END-TO-END SMOKE TEST: FAIL")
        print("========================================")
        sys.exit(1)
