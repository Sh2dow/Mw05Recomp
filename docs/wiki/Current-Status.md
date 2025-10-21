# Current Status

**Last updated**: 2025-10-21

## TL;DR
- ✅ **Game runs stable 10+ minutes** without crashes
- ✅ **File I/O WORKING** - Successfully loaded GLOBALMEMORYFILE.BIN (6.3 MB)
- ✅ **All 12 threads created** - Worker contexts properly initialized
- ✅ **PM4 processing active** - Millions of packets (114,616 bytes/frame)
- ✅ **Rendering function called 7 times** - VdSwap invoked, then stopped
- ⚠️ **NO draws yet** (draws=0) - Game stuck in initialization

## Major Milestones

### 2025-10-14: Recompiler Bugs Fixed
- Fixed 38 PowerPC instructions (32-bit vs 64-bit: ADDI, MR, AND, OR, XOR, etc.)
- Fixed function table bug (PPC_LOOKUP_FUNC macro calculation error)
- Result: Indirect function calls work, game progresses much further

### 2025-10-16: XEX Relocation Bug Fixed
- Problem: MW05 XEX has NO BASE REFERENCE HEADER, loader skipped relocations
- Solution: Assume baseRef=0x00000000, apply delta=0x82000000
- Result: Applied 5,666 relocations, static initializers work, game runs

### 2025-10-20: Thread Races & Heap Corruption Fixed
- Thread params race: Local copy in `GuestThreadFunc` (invalid entry 0x92AA0003 eliminated)
- Dynamic cast race: SEH __try/__except wraps kernel object access
- Heap corruption: Removed environment variables (MW05_UNBLOCK_MAIN, etc.) causing invalid states
- Result: Game runs 120+ seconds without crashes (was crashing at 5-29 seconds)

### 2025-10-21: Static Initializer & File I/O Fixed
- Static initializer hang: Skip `sub_8262FC50` during C runtime startup
- File I/O: Streaming bridge fallback loads GLOBALMEMORYFILE.BIN (6.3 MB)
- Result: Main thread progresses, file I/O working, 269+ operations

### 2025-10-21: Rendering Function Called
- Function `sub_82598A20` called 7 times (rendering function that calls VdSwap)
- VdSwap invoked 7 times (GPU command buffer submission working)
- Then stopped: Function pointer gate at offset +0x3CEC cleared to NULL
- Result: Rendering infrastructure works, but game logic stops calling it

## Current State
- ✅ Game runs 10+ minutes without crashes
- ✅ All 12 threads created (same as Xenia)
- ✅ Worker contexts initialized (callback pointers at +84, +88)
- ✅ File I/O working (269+ operations, loaded GLOBALMEMORYFILE.BIN)
- ✅ PM4 processing (millions of packets, 114,616 bytes/frame)
- ✅ Graphics callbacks working (41,908 invocations at 60 FPS)
- ✅ Rendering function called 7 times (VdSwap invoked)
- ⚠️ NO draws yet (draws=0) - Game stuck in initialization
- ⚠️ Rendering stopped after 7 calls - Function pointer gate issue


## Memory
- Heap layout (guest address space):
  - User heap: 0x00020000–0x7FEA0000 (~2.0 GiB)
  - Physical heap: 0xA0000000–0x100000000 (1.5 GiB)
  - XEX image: 0x82000000–0x82CD0000
  - System PM4 cmd buffer: 0x00F00000 (fixed)
- Allocators:
  - User: o1heap (no assertions observed in long runs)
  - Physical: bump allocator; over-allocate for alignment, store original ptr at aligned[-1], size from header at [-2]
- Signals/Stats:
  - PhysicalAllocated counter added (display fixed); typical debug runs: ~350–400 MiB physical, ~100–250 MiB user (varies by content)
  - No fragmentation issues expected (bump allocator); watch high-water marks
- How to check quickly:
  - Console: `heap.stats`
  - Env: `MW05_DEBUG_HEAP=2|3`
  - Logs: `out/build/.../Mw05Recomp/mw05_host_trace.log`
- Pitfalls:
  - Over‑aligned physical allocations must be freed via our Free() path (restores original pointer)
  - Do not mix host new/delete with guest heaps
  - Avoid `MW05_UNBLOCK_MAIN` (previously caused memory corruption)

## Known Issues
1. **Function pointer gate** - Rendering stops after 7 calls (pointer at +0x3CEC cleared to NULL)
2. **Game stuck in initialization** - Never progresses to rendering, even after 10+ minutes
3. **Missing draw commands** - PM4 processing millions of packets but no DRAW_INDX (0x22) or DRAW_INDX_2 (0x36)

## Next Priorities
1. Investigate function pointer gate - Find what clears pointer at +0x3CEC
2. Extended runtime testing - Run game for 30+ minutes
3. Simulate user input - Try controller/keyboard to see if game progresses
4. Compare with Xenia - Check what triggers first draw

