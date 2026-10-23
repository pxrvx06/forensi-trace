# ForensiTrace Decisions & Findings Log

This log records architecture questions, team decisions, and technical findings agreed upon during development.

---

## Decision / Question Log

### [OPEN QUESTION] D-001: Observation Time (Collector Timestamp) for Rule R6
- **Date:** 2026-10-23
- **Owner:** Daksh Shaparia (Agent Core & Event Log Collector)
- **Status:** OPEN (Awaiting team review with Purva, Chetna, and Akash)
- **Affected Components:** `agent/collectors/`, `docs/schema.md`, `engine/` (Rule R6)

#### Context
Correlation Rule **R6** (Cross-source timestamp-consistency check) is specified as:
> *"Timestamp disagreement: a file's modified time differs from when the agent saw the event by more than a threshold (2 min)"*

This rule detects timestomping or clock tampering by comparing:
1. The file system modified timestamp recorded on disk (`mtime`).
2. The real-time timestamp when the collector / agent observed and recorded the event (`collected_at` / observation time).

#### The Problem
The current schema contract defines:
- `ts_utc`: Event time in UTC with millisecond precision (derived from the event itself, e.g. `TimeCreated` in Event Log, or filesystem modified time).
- There is **no top-level field** in the normalized schema for the agent's observation time (`collected_at` or `ts_observed_utc`).

Without an observation timestamp, the correlation engine will compare `mtime` against itself or have to fall back to the ingestion server's arrival time, which does not reflect client observation time when the agent is operating offline or buffering during network retries.

#### Proposed Options for Team Consensus
1. **Option 1 (Schema change):** Add `ts_collected_utc` (or `ts_observed_utc`) as an optional top-level ISO-8601 UTC string field in `docs/schema.md`.
2. **Option 2 (Details dictionary, schema-preserving):** Keep the top-level schema contract unchanged. Place observation time inside the `details` JSON field (e.g., `details.ts_observed_utc`). Both the File System collector and Event Log collector can inject this without altering top-level schema validation.

#### Recommendation for Phase 2
Do **not** edit `docs/schema.md`. Maintain the frozen schema contract. If the engine requires observation time prior to an official schema revision vote, store it under `details.ts_observed_utc`.
