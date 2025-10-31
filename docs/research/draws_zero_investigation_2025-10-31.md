# MW05 Recomp - Zero Draw Commands Investigation (2025-10-31)

## Summary

Game runs stably for 60+ seconds without crashes, writing **31.7 million TYPE3 PM4 packets**, but issues **ZERO draw commands** (`draws=0`). The game is stuck in initialization phase and never progresses to asset loading or rendering.

## Key Findings

### 1. Game State
- ✅ Runs 60+ seconds without crashes
- ✅ Writes 31.7M TYPE3 packets (same as commit 95b7282d)
- ✅ Worker threads created and running
- ✅ BaseHeap allocations working correctly
- ✅ VdSwap and Present calls happening
- ❌ **ZERO draw commands** (opcodes 0x04, 0x22, 0x36)
- ❌ **NO file I/O attempts** (StreamBridge never triggered)
- ❌ **Invalid viewport** [0,0,0,0]
- ❌ **Display dimensions zero** (forced to 1280x720)

### 2. TYPE3 Packets Analysis
- **31.7 million TYPE3 packets** written
- These are **NOT draw commands** - they are initialization commands
- Primary opcode: **0x3E (PM4_CONTEXT_UPDATE)** - GPU state setup
- Game is continuously writing GPU state but never issuing draw commands

### 3. File I/O System
- **StreamBridge system exists** (`Mw05Recomp/cpu/mw05_streaming_bridge.cpp`)
- **StreamBridge is NEVER triggered** - no file I/O attempts
- Game has NOT tried to load any assets (textures, models, etc.)
- Without assets, game cannot render

### 4. Historical Context
- **Commit 95b7282d** (with o1heap): 900K TYPE3 in 60s = 1.8M in 120s
- **Current HEAD** (with BaseHeap): 31.7M TYPE3 in 60s
- **BOTH commits have `draws=0`** - game has NEVER been rendering!
- The "1.4 million TYPE3 packets" claim in commit 95b7282d was misleading - those were NOT draw commands

## Root Cause

**Game is stuck in initialization phase and never progresses to asset loading.**

The initialization sequence is incomplete - the game is missing some critical initialization step that would trigger it to:
1. Start loading assets through StreamBridge
2. Set up valid display dimensions and viewports
3. Begin issuing draw commands

## Evidence from Logs

### Invalid Viewport
```
[sub_825A7A40] INVALID VIEWPORT #1: input bounds [0,0,0,0] -> size (0 x 0)
[sub_825A7A40]   r6=0015B4AC r7=00157BA0 lr=825A7EC0
```

### Display Dimensions Forced
```
[sub_825A7EA0] FORCE-INIT: Display dimensions at r3+0x4FD4 are zero, initializing to 1280x720
```

### No File I/O
```
# Search for StreamBridge activity:
Get-Content traces/auto_test_stderr.txt | Select-String -Pattern 'StreamBridge|HOST\.Stream'
# Result: ZERO matches
```

### PM4 Statistics
```
[PM4-TYPE-DIST] TYPE0=2049794 TYPE1=0 TYPE2=0 TYPE3=31750206 total=33800000
```

## Next Steps

### 1. Investigate Initialization Sequence
- What triggers StreamBridge file I/O?
- What initialization must complete before asset loading?
- Why are display dimensions zero?
- What is the game waiting for?

### 2. Compare with Working Xbox 360 Version
- Use IDA Pro API (port 5050) to analyze initialization sequence
- Identify what initialization steps are missing
- Find the trigger point for asset loading

### 3. Check Display Initialization
- Why are display dimensions zero?
- What sets up the viewport?
- Is there a missing graphics initialization step?

### 4. Investigate StreamBridge Trigger
- What calls the StreamBridge system?
- When should file I/O start?
- Is there a missing callback or event?

## Technical Details

### Memory Layout
- User heap: 0x00100000-0x7FEA0000 (2045 MB)
- Physical heap: 0xA0000000-0x100000000 (800 MB)
- Ring buffer: 0x00102000 (64 KB)
- System command buffer: 0x00F00000 (64 KB)
- XEX data section: 0x82A2B000+ (worker pool slots)

### PM4 Command Types
- **TYPE0**: GPU register writes (2.0M packets)
- **TYPE3**: GPU commands (31.7M packets)
  - Opcode 0x3E: PM4_CONTEXT_UPDATE (GPU state setup)
  - Opcode 0x04: MICRO_IB (draw command) - **ZERO**
  - Opcode 0x22: DRAW_INDX (draw command) - **ZERO**
  - Opcode 0x36: DRAW_INDX_2 (draw command) - **ZERO**

### File I/O System
- **Kernel functions**: NtCreateFile, NtReadFile (in import table)
- **Game functions**: XCreateFileA, XReadFile (NOT registered - linker stripped)
- **StreamBridge**: `Mw05Recomp/cpu/mw05_streaming_bridge.cpp` (exists but never triggered)

## Conclusion

The game is NOT broken by the BaseHeap migration. The game has NEVER been rendering - it's been stuck in initialization since the beginning. The issue is NOT about file I/O hooks or memory allocation - it's about a missing initialization step that prevents the game from progressing to the asset loading and rendering phases.

The next step is to investigate the initialization sequence to find what's blocking the game from progressing.

