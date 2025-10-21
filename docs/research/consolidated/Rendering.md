# Rendering (PM4 / VdSwap / Draws)

Compressed narrative of the “no draws” track; supersedes scattered notes.

## TL;DR
- PM4 scanning works; initially saw only TYPE0/state packets
- Present path calls VdSwap; early runs passed an invalid pWriteCur (0x00000004) → skipped scan
- Fixes applied: correct shim for sub_82595FC8; now VdSwap receives valid pWriteCur and scans packets
- Still no 0x22/0x36 yet → game is likely still in state setup/asset load phase

## What actually happened (deduped)
1) Early hypothesis: VdSwap not called → Later disproven; it is called by sub_82598A20 (present)
2) Real blocker: invalid write cursor pointer (pWriteCur) due to wrong shim; range check failed
3) After fixing shim to call original recompiled func, pWriteCur valid → ring buffer scan active (24+ packets)
4) Packets scanned are non-draw (TYPE0/other TYPE3) during initialization

## Current evidence (concise)
- Ring buffer base=0x000202E0 size=64KiB; write-back pointer set
- VdSwap logs show GuestOffsetInRange=1; PM4_OnRingBufferWrite invoked
- Opcode histogram: no 0x22/0x36 yet; predominately NOP/REG writes

## Why draws may still be absent
- Assets not fully loaded (watch StreamBridge ops; shaders/textures)
- Missing worker threads previously; now 12/12 created — continue to verify activity
- Game may require several seconds/minutes of setup before first draw (matches Xenia timeline)

## What to do next
1. Add/enable PM4 opcode histogram (MW05_PM4_TRACE=1) and capture first appearance of 0x22/0x36
2. Instrument render-thread path around 0x825AA970 to confirm VdSwap cadence and parameters
3. Correlate file I/O completion (shader/texture loads) with onset of draw opcodes

## Deep Dive References
For detailed breakthrough discoveries, see:
- [Draw Commands Found](../archive/DRAW_COMMANDS_FOUND.md) - First PM4 packet detection (185,380 processed!)
- [Breakthrough: Ring Buffer Working](../archive/BREAKTHROUGH_RING_BUFFER_WORKING.md) - VdSwap shim fix
- [Micro-IB Format Discovery](../archive/MICROIB_FORMAT_DISCOVERY.md) - MW05 uses opcode 0x04, not 0x22/0x36
