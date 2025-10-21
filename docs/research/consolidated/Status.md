# Status & Milestones (Consolidated)

A single, compressed source of truth. Older long-form notes are superseded by this page and kept only for provenance.

## TL;DR (2025-10-21)
- Stable for 10+ minutes; no crashes
- All 12 threads created and running; file I/O active (StreamBridge)
- PM4 scanning active; still no draw opcodes yet (normal during init)
- Blocking issue fixed: static initializer hang (skip sub_8262FC50)

## Timeline of key breakthroughs
- 2025-10-14
  - Fixed 38 recompiler instruction bugs (32-bit arithmetic/logic/moves)
  - Fixed PPC_LOOKUP_FUNC overflow bug; indirect calls stable
- 2025-10-16
  - Game runs continuously; main loop healthy; PM4 scanning OK
  - Early “rendering blocked” was due to missing/incorrectly regenerated funcs; resolved by codegen
- 2025-10-20
  - SEH guards for dynamic_cast/Wait(); thread params race fixed
  - System shows long stable runs (minutes)
- 2025-10-21
  - Static initializer hang in sub_8262FC50 skipped → _xstart completes → sub_82441E80 reached
  - Env/script fix → file I/O flowing (GLOBALMEMORYFILE.BIN etc.)

## Current state (compact)
- Threads: 12/12 present (worker, special, render-related threads)
- File I/O: 300+ ops per multi‑minute run; bridging verified
- PM4: 100k+ bytes/frame scanned; mostly TYPE0/state setup; no 0x22/0x36 yet
- Graphics: Callbacks invoked; VBlank pump OK; Present path executes

## Next priorities (actionable)
1. Verify render thread path reaches VdSwap with valid write cursor; compare with Xenia
2. Collect PM4 opcode histogram and look for first appearance of 0x22/0x36
3. Cross-check that required assets (shaders/textures) load before first draw

## Deep Dive References
For detailed breakthrough discoveries, see:
- [Entry Point Fix Success](../archive/ENTRY_POINT_FIX_SUCCESS.md) - Missing XEX entry point 0x8262E9A8
- [Root Cause: Static Initializers](../archive/ROOT_CAUSE_STATIC_INITIALIZERS.md) - Infinite loop in `sub_8262FC50`
- [Draw Commands Found](../archive/DRAW_COMMANDS_FOUND.md) - First PM4 packet detection
