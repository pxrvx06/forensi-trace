# ForensiTrace project rules
- Python 3.x, FastAPI, SQLite, watchdog, pywin32, python-evtx; React for the dashboard. Do not add other frameworks.
- The event schema in docs/schema.md is a contract. Never change it; propose changes in a comment instead.
- Correlation rules live in rules.yaml, not in code. No machine learning.
- Every module gets clear, labeled print or log statements showing what it received and what it produced.
- Every rule or parser gets a test that must fire and a test that must not fire.
- Windows-only code is isolated in agent/. Never run auditpol, wevtutil clear or anything that edits system logging without asking.
- Keep each person's work inside their own folder: agent/, backend/, engine/, dashboard/.
