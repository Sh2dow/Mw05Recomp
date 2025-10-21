# Threads & Synchronization (Consolidated)

Single source for thread fixes/state; older per-file notes are superseded.

## What’s fixed (kept brief)
- Params race: GuestThreadFunc copies `params` locally at entry → invalid entry 0x92AA0003 eliminated
- SEH guards: All kernel object access (dynamic_cast + Wait) wrapped in `__try/__except`
- Worker ctx init: Context[0x54]=callback func (0x8261A558), Context[0x58]=callback param (0x82A2B318)

## Current state
- 12/12 threads present; worker loop no longer exits early
- Render-related threads active; PM4 processing continuous

## Verify when debugging
- Compare thread creation/resume order against Xenia (main → #7 → others)
- Ensure thread contexts are heap-allocated and mapped; offsets 0x54/0x58 populated
- Watch SEH counters; no unhandled AVs during Wait()

## Minimal references
- THREAD_CONTEXT_ALLOCATION_STATUS.md, THREAD_CONTEXT_ALLOCATION_FIXED.md
- THREAD_CRASH_DEBUG_STATUS.md, THREAD_CRASH_FINAL_STATUS.md
- CRASH_ANALYSIS.md, CRASH_INVESTIGATION_sub_8215BA10.md
