# Mw05Recomp Wiki

Welcome to the consolidated documentation for the MW05 (NFS: Most Wanted) recompilation.

This Wiki replaces ad-hoc research notes in docs/research with concise, maintained pages. The old research folder is preserved as an archive; see docs/research/README.md.

## Quick Links
- Current Status: [Current-Status](Current-Status.md)
- Debugging Guide (Console, Env Vars, WinDbg/CDB): [Debugging-Guide](Debugging-Guide)
- Rendering Progress (PM4, VdSwap, “No Draws”): [Rendering-Progress](Rendering-Progress)
- Threads & Kernel (races, SEH, thread init): [Threads-and-Synchronization](Threads-and-Synchronization)
- Logging & Traces (where logs go): [Logging-and-Traces](Logging-and-Traces)
- Scripts & Tooling (consolidation plan): [Scripts-and-Tooling](Scripts-and-Tooling.md)

## TL;DR
- Game runs stable 10+ minutes; major initialization blocker fixed (static initializer hang).
- All 12 threads creation pattern understood; context init fixed; no draws yet.
- PM4 scanning active; VdSwap patched but not called by game path under investigation.

## How this Wiki is maintained
- Pages are generated from concise summaries of the research archive.
- Prefer updating these pages over adding new long-form notes; add links to archived docs when needed.
- See [Scripts-and-Tooling](Scripts-and-Tooling.md) for a publish script to GitHub Wiki.

