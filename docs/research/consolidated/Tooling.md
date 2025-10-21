# Scripts & Tooling (Consolidated)

Goal: fewer, clearer tools with predictable profiles.

## Target end-state
- ~35 essentials (from ~190):
  - scripts/mw05_run.py (profiles: quick, trace, e2e)
  - tools/mw05_analyze.py (PM4, threads, file I/O)
  - tools/mw05_find.py (addresses, symbols, logs)
  - scripts/archive/ (everything else)

## Day-to-day
- Console cmds: `status`, `heap.stats`, `thread.list`, `pm4.hist`, `pm4.scan`
- Env vars (minimal): MW05_DEBUG_*, MW05_PM4_*, MW05_HOST_TRACE_*
- Use CDB/WinDbg only for deep stepping; prefer self-debuggable console

## Keep for provenance (archive sources)
- SCRIPT_CONSOLIDATION_PROPOSAL.md
- SELF_DEBUGGABLE_APP_PLAN.md
- SELF_DEBUGGABLE_IMPLEMENTATION.md
- DEBUGGING_WORKFLOW.md
