# ForensiTrace Agent & Hybrid ML Overhead Study

- **Measured At (UTC):** `2026-11-27T04:17:53.947560+00:00`
- **Host OS:** `Windows-11-10.0.26300-SP0`
- **Hardware:** 20 logical CPU cores, 15.71 GB RAM
- **Workload:** Idle (5.0s) vs. Active Copy (50 files, 9.77 MB total) + Hybrid ML Correlation (28.05 ms)

## Measured Resource Overhead

| Component | State | Avg CPU (%) | Peak CPU (%) | Avg Memory (MB) | Peak Memory (MB) |
|---|---|---:|---:|---:|---:|
| Endpoint Agent | Idle | 0.31 | 3.10 | 39.30 | 39.30 |
| Endpoint Agent | Active Copy + ML | 8.05 | 12.50 | 42.04 | 42.05 |
| FastAPI Backend | Idle | 0.00 | 0.00 | 57.96 | 57.96 |
| FastAPI Backend | Active Copy + ML | 2.92 | 5.90 | 58.42 | 58.59 |
| ML Scorer + Engine (PyTorch CPU) | Idle | 0.00 | 0.00 | 211.55 | 211.55 |
| ML Scorer + Engine (PyTorch CPU) | Active Copy + ML | 5.08 | 7.20 | 213.06 | 220.28 |

## Key Observations

- **Idle Agent Footprint:** Average 0.31% CPU and 39.30 MB RSS.
- **Active Copy Agent Footprint:** Average 8.05% CPU (peak 12.50%) and 42.04 MB RSS while monitoring 50 rapid file writes.
- **Hybrid ML Inference Latency:** Correlating and scoring 50 captured events completed in **28.05 ms** on CPU.
