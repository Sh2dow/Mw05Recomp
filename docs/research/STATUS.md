# MW05 Current Status

## Test Run Summary (15 seconds)

**Total trace lines**: 132,689
**File loads**: 1 (GLOBALMEMORYFILE.BIN - 1 MB of 6 MB file)
**Draw commands**: DrawCount=1 (stuck at 1, not progressing)
**StreamBridge calls**: 55 (but only 1 successful file load)
**VBlank ticks**: 1,369 (running at ~91 FPS)

## What's Working

✅ Entry point executes
✅ All threads created
✅ Graphics callbacks registered and invoked
✅ VBlank pump running
✅ PM4 command buffers being scanned
✅ Streaming bridge detecting scheduler blocks
✅ File I/O working (XCreateFileA, XReadFile)
✅ Game files present in `out/build/x64-Clang-Debug/Mw05Recomp/game/GLOBAL/`

## What's NOT Working

❌ **Only 1 file loaded** - Game loaded `GLOBALMEMORYFILE.BIN` (1 MB) and stopped
❌ **DrawCount stuck at 1** - Game issues 1 draw command per frame, nothing more
❌ **No progression** - Game doesn't request more files after first load
❌ **Main thread sleeping** - Thread sleeping at `lr=0x8262F300` (KeDelayExecutionThread)

## File Load Details

**Successful load**:
```
[HOST] import=HOST.StreamBridge.io.try.fallback cand='game:\GLOBAL\GLOBALMEMORYFILE.BIN' buf=820E95D8 size=1048576
[HOST] import=HOST.FileSystem.XCreateFileA.enter guest="game:\GLOBAL\GLOBALMEMORYFILE.BIN"
[HOST] import=HOST.StreamBridge.io.read.fallback ok=1 bytes=1048576
```

**File details**:
- Path: `out/build/x64-Clang-Debug/Mw05Recomp/game/GLOBAL/GLOBALMEMORYFILE.BIN`
- Size on disk: 6,292,096 bytes (6 MB)
- Bytes read: 1,048,576 bytes (1 MB)
- **Problem**: Only read 1 MB of 6 MB file!

## Available Files (Not Loaded)

The following files exist but were NOT loaded:
- `PERMANENTMEMORYFILE.BIN`
- `FRONTENDMEMORYFILE.BIN`
- `INGAMEMEMORYFILE.BIN`
- `GLOBALB.BUN`
- `GLOBALA.BUN`
- `INGAMEB.BUN`
- `INGAMEA.BUN`
- And 20+ more files

## StreamBridge Behavior

**Scheduler blocks detected**: 55
**File paths found**: 0 (all blocks contain game action strings, not file paths)
**Fallback attempts**: 1 (only tried first file in fallback list)

**Example non-file blocks**:
```
[HOST] import=HOST.StreamBridge.io.no_path.ascii ea=82084610 "GAMEACTION_GAMEBREAKER"
[HOST] import=HOST.StreamBridge.io.no_path.ascii ea=820845FC "GAMEACTION_SHIFTUP"
```

## Root Cause Analysis

### Problem 1: Partial File Read
The game requested 1 MB but the file is 6 MB. The streaming bridge read only what was requested, but the game may need the full file.

### Problem 2: No More File Requests
After loading the first file, the game doesn't request more files. This could mean:
1. The partial file load didn't complete properly
2. The game is waiting for a different event (not file I/O)
3. The file loading system is broken

### Problem 3: Scheduler Blocks Don't Contain File Paths
Most scheduler blocks contain game action strings, not file paths. The streaming bridge can't decode file paths from these blocks, so it falls back to trying known boot files. But it only tries the first file and stops.

## Next Steps to Investigate

1. **Check if file load completed properly**
   - Did the game acknowledge the file load?
   - Is there a completion callback or event?

2. **Check why game doesn't request more files**
   - Is the game stuck waiting for something?
   - Is there a missing initialization step?

3. **Check if partial file read is the problem**
   - Should the streaming bridge read the full file instead of just what's requested?
   - Or should it continue reading until the game signals completion?

4. **Check Xenia behavior**
   - How does Xenia handle file loading?
   - Does it load all files at startup or on-demand?
   - What's the file loading sequence?

## Comparison with Xenia

Need to check Xenia log for:
- How many files are loaded at startup
- What's the file loading sequence
- Are files loaded fully or partially
- What events trigger file loads

## Environment Variables (Current)

```batch
MW05_FILE_LOG=1                    # File I/O logging enabled
MW05_HOST_TRACE_HOSTOPS=1          # Host operation tracing enabled
MW05_TRACE_KERNEL=1                # Kernel tracing enabled
MW05_STREAM_BRIDGE=1               # Streaming bridge enabled
MW05_STREAM_ANY_LR=1               # Allow streaming from any link register
MW05_STREAM_FALLBACK_BOOT=1        # Try boot files when path unknown
MW05_FORCE_PRESENT=0               # Disabled (was blocking streaming)
```

## Key Trace Patterns

**Main thread sleeping**:
```
[HOST] import=HOST.Wait.observe.KeDelayExecutionThread tid=7974 lr=0x8262F300
[HOST] import=sub_8262F2A0.lr=82849DB0 r3=00000014 r4=00000000 r5=002B9250
```

**VBlank callbacks running**:
```
[HOST] import=HOST.VblankPump.timing tick=1369 loop_ms=6 sleep_ms=9 total_ms=15
[HOST] import=HOST.VdCallGraphicsNotificationRoutines source=0
[HOST] import=HOST.VdInterruptEvent.dispatch cb=825979A8 ctx=00061000
```

**Draw commands stuck**:
```
[HOST] import=HOST.PM4.SysBufDrawCount=0  # Initial
[HOST] import=HOST.PM4.SysBufDrawCount=1  # First draw
[HOST] import=HOST.PM4.SysBufDrawCount=1  # Stuck at 1
[HOST] import=HOST.PM4.SysBufDrawCount=1  # Still stuck
```

## Hypothesis

The game's file loading system works differently than expected:
1. Game writes sentinel (0x0A000000) to scheduler block
2. Streaming bridge detects sentinel and tries to load file
3. Streaming bridge reads 1 MB (as requested by game)
4. **Missing step**: Game should acknowledge completion and request next file
5. **Problem**: Game doesn't acknowledge or request more files

Possible causes:
- Completion callback not being called
- Event not being signaled
- Scheduler block not being cleared properly
- Game waiting for different event (not file I/O)

