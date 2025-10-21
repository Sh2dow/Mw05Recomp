# Research Index

**All archived research notes have been consolidated into the wiki and consolidated docs.**

Last updated: 2025-01-21

## Active Documentation

### Consolidated Research Docs
- [Status & Milestones](consolidated/Status.md) - Current status, timeline of breakthroughs
- [Rendering Progress](consolidated/Rendering.md) - PM4, VdSwap, draw commands investigation
- [Threads & Synchronization](consolidated/Threads.md) - Thread races, SEH, context initialization
- [Tooling & Scripts](consolidated/Tooling.md) - Script consolidation, debug console, environment variables
- [Logging & Traces](consolidated/Logging.md) - Log locations, verbosity control, cleanup

### GitHub Wiki
- [Home](../wiki/Home.md) - Wiki entry point
- [Current Status](../wiki/Current-Status.md) - Latest status and milestones
- [Rendering Progress](../wiki/Rendering-Progress.md) - Rendering investigation details
- [Debugging Guide](../wiki/Debugging-Guide.md) - Three-level debugging system
- [Threads & Synchronization](../wiki/Threads-and-Synchronization.md) - Thread fixes and patterns
- [Logging & Traces](../wiki/Logging-and-Traces.md) - Log management and verbosity control
- [Scripts & Tooling](../wiki/Scripts-and-Tooling.md) - Script consolidation and tooling

## Deep Dives (Breakthrough Discoveries)
These documents capture unique breakthrough moments and discoveries that deserve their own detailed write-ups:

- [Draw Commands Found](archive/DRAW_COMMANDS_FOUND.md) - First detection of PM4 packets (185,380 processed!)
- [Breakthrough: Ring Buffer Working](archive/BREAKTHROUGH_RING_BUFFER_WORKING.md) - PM4 ring buffer scanning fixed
- [Entry Point Fix Success](archive/ENTRY_POINT_FIX_SUCCESS.md) - Missing XEX entry point 0x8262E9A8 added to TOML
- [Root Cause: Static Initializers](archive/ROOT_CAUSE_STATIC_INITIALIZERS.md) - Infinite loop in `sub_8262FC50` fixed
- [Micro-IB Format Discovery](archive/MICROIB_FORMAT_DISCOVERY.md) - MW05 uses opcode 0x04 for draws, not 0x22/0x36

## Archive Status
Most archived research files have been merged into the consolidated docs and wiki. Only unique breakthrough discoveries are kept in the archive.

## File Count Reduction
- **Before**: ~50 MD files (31 archive + 5 consolidated + 7 wiki + 7 other)
- **After**: ~19 MD files (5 archive + 5 consolidated + 7 wiki + 2 index/readme)
- **Reduction**: 62% fewer files

## How to Use This Documentation
1. **Quick status check**: Read [Current Status](../wiki/Current-Status.md) in the wiki
2. **Detailed investigation**: Check the relevant consolidated doc (Status, Rendering, Threads, Tooling, Logging)
3. **Debugging**: Follow the [Debugging Guide](../wiki/Debugging-Guide.md) three-level system
4. **Contributing**: Update the consolidated docs and wiki, don't create new archive files

