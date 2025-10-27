# 2025-10-27: File Loading Investigation

## ROOT CAUSE: Game Stuck Loading GLOBALA.BUN

**Status**: Game starts loading `GLOBAL\GLOBALA.BUN` but never completes. This blocks all further initialization and prevents rendering from starting.

## Evidence

1. **File load starts but never completes**:
   ```
   [FILE_LOAD_823B1298] ENTER count=0 r3=82087F80 (GLOBAL\GLOBALA.BUN) r4=00000001 r5=00000000 r6=00000000 r7=00000000 tid=5bf0
   ```
   - No corresponding "EXIT" or "COMPLETE" message
   - Game never proceeds past this point

2. **Game never polls input**:
   - `XamInputGetState` is never called
   - Game hasn't reached main game loop

3. **No draw commands**:
   - `draws=0` throughout entire run
   - Only PM4 opcode 0x3E (context updates) written
   - Render queue empty (`qtail=0 qhead=0`)

4. **Alertable waits are NOT used**:
   - All sleep calls have `alertable=0`
   - Game uses events for I/O completion, not APCs
   - Restoring alertable parameter didn't fix the issue

## Investigation Path

### Initial Hypothesis (INCORRECT)
- Thought game was waiting for APCs to be delivered
- Forced `alertable=FALSE` was blocking APC delivery
- **WRONG**: Game doesn't use alertable waits at all

### Actual Problem
- File loading function `sub_823B1298` is stuck
- Game is waiting for file I/O to complete
- File I/O completion mechanism is broken or incomplete

## DEEP INVESTIGATION RESULTS (2025-10-27 18:30)

### File Loading Architecture DISCOVERED

**Virtual Filesystem**:
- Xbox 360 version uses `NFS\ZDIR.BIN` (virtual FS index) to access BUN files
- Extracted PC assets don't include ZDIR.BIN - files are extracted as regular files
- Game checks for ZDIR.BIN and correctly returns "file not found"
- Game should fall back to direct file access when ZDIR.BIN is missing

**Call Chain**:
```
sub_823B1298 (FILE_LOAD) - Creates loader object, adds to list
  ↓
sub_823B0D20 - Initializes loader object
  ↓
Worker loop (sub_823B0190) - Runs continuously
  ↓
sub_823AFFA8 - Main game update function
  ↓
sub_823B1408 - Processes file loader list
  ↓
sub_823B10C8 - Should process each loader ← NEVER PROCESSES
  ↓
sub_823BCA68 (FILE_OPEN) - Should open file ← NEVER CALLED
  ↓
sub_823BBC48 - Creates file handle object
  ↓
sub_823BBEB0 - Opens file via NtCreateFile
```

### ROOT CAUSE IDENTIFIED

**Problem**: Loader object is created but never processed by `sub_823B10C8`

**Why**: From IDA decompilation of `sub_823B10C8`:
```c
if ( !result[12] && !result[11] ) {
    // Process loader - open and read file
    // ...
}
```

The loader object has `result[12]` or `result[11]` set to non-zero, causing processing to be skipped.

**Evidence**:
- ✅ FILE_LOAD_823B1298 is called (creates loader object)
- ✅ Worker loop is running (sub_823B0190)
- ✅ Game update function is running (sub_823AFFA8)
- ✅ File loader list processor is running (sub_823B1408)
- ❌ FILE_OPEN_823BCA68 is **NEVER** called
- ❌ NtCreateFile is **NEVER** called
- ❌ File loading never completes

### File Open Bypass (ATTEMPTED FIX - FAILED)

**Previous Issue**: `sub_823BCA68` had a bypass that returned NULL handle for GLOBALA.BUN
- Comment said "File causes blocking"
- Bypass prevented file from being opened

**Fix Attempted**: Removed the bypass to allow file to be opened normally

**Result**: NO CHANGE - file open function is still never called
- The bypass was preventing file open, but file open isn't being called anyway
- The real problem is earlier in the chain - loader object isn't being processed

### Why This Blocks Everything

1. Game initialization waits for GLOBALA.BUN to load
2. GLOBALA.BUN contains critical game data (textures, models, etc.)
3. Without this file, game can't progress past loading screen
4. No rendering initialization occurs
5. No draw commands are issued
6. Game stuck in infinite loop waiting for file to load

## Next Steps (PRIORITY ORDER)

### 1. URGENT: Fix Loader Object State Flags
**Goal**: Ensure loader object is created with correct state so it gets processed

**Actions**:
1. Add logging to `sub_823B0D20` (loader initialization) to see what flags are set
2. Add logging to `sub_823B1408` (loader list processor) to see if loader is in the list
3. Add logging to `sub_823B10C8` to see why it skips processing
4. Check values of `result[11]` and `result[12]` after initialization
5. Fix initialization to set flags correctly

### 2. Implement Direct File Access Fallback
**Goal**: Bypass virtual FS when ZDIR.BIN is missing

**Actions**:
1. Detect when ZDIR.BIN is not available
2. Modify file loader to use NtCreateFile directly
3. Skip virtual FS logic entirely
4. Read file synchronously and mark loader as complete

**Benefit**: Simpler code path, avoids complex virtual FS logic

### 3. Alternative: Create Virtual FS from Extracted Files
**Goal**: Build ZDIR.BIN from directory structure

**Actions**:
1. Analyze ZDIR.BIN format from Xbox 360 version
2. Build index from extracted file structure
3. Implement virtual FS read operations

**Benefit**: Game uses native code path
**Downside**: More complex, requires understanding ZDIR format

### 4. Debug Loader Processing with Detailed Logging
**Goal**: Understand exact point where loader processing fails

**Actions**:
1. Add logging to every function in the call chain
2. Log loader object state at each step
3. Identify exact condition that causes processing to be skipped
4. Fix the condition

## Files Modified

- `Mw05Recomp/gpu/mw05_trace_shims.cpp`: Restored alertable parameter (line 666)
  - This was the correct fix (don't force alertable=FALSE)
  - But it didn't solve the file loading issue

## Performance Investigation

### FPS Regression Analysis
- **Before VdGetSystemCommandBuffer fix**: 15 FPS
- **After fix (with PM4_ScanLinear in EnsureSystemCommandBuffer)**: 0.9 FPS
- **After removing PM4_ScanLinear from EnsureSystemCommandBuffer**: 3.3 FPS

### Root Cause of FPS Drop
The VdGetSystemCommandBuffer fix allocated the system command buffer at 0x00F00000, which enabled auto-scan code in VdSwap that was previously disabled (because `g_VdSystemCommandBuffer` was 0). This auto-scan runs 289 times in 30 seconds, scanning 64KB each time, which is expensive.

However, **this is a symptom, not the root cause**. The real problem is:
1. Game is stuck loading GLOBALA.BUN
2. Game hasn't started rendering yet
3. Only PM4 opcode 0x3E (context updates) is being written, no draw commands (0x04, 0x22, 0x36)
4. The auto-scans are wasteful because the game isn't rendering

### PM4 Command Analysis
- **2.88M PM4 packets detected** (1.54M TYPE0 + 1.34M TYPE3)
- **All TYPE3 packets are opcode 0x3E** (PM4_CONTEXT_UPDATE)
- **NO draw commands detected** (opcodes 0x04, 0x22, 0x36)
- Ring buffer at 0x001002E0 is initialized and being written to
- System command buffer at 0x00F00000 is allocated but mostly unused

## Current Status

- Game runs stably for 30+ seconds
- Memory usage normal (~1.76 GB)
- PM4 commands being written (2.88M packets, all context updates)
- **BLOCKED**: Stuck loading GLOBALA.BUN, can't proceed to rendering
- **FPS**: 3.3 FPS (down from 15 FPS due to wasteful auto-scans)

