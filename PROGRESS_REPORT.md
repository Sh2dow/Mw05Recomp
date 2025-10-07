# MW05 Initialization Investigation Summary

## Problem Statement
The game gets stuck during initialization because:
1. Main thread waits for flag at `0x82A2CF40` (currently worked around with `MW05_UNBLOCK_MAIN=1`)
2. Video thread is never created (only 2 threads created instead of expected 3+)

## Key Findings

### ✅ Scheduler Context Fix - WORKING
- **Issue**: `sub_825968B0` was being called with `r3=0` instead of valid scheduler context pointer
- **Root Cause**: In `sub_825960B8` at `0x82596104`, code loads r3 from `0x10(r30)`, but r30 is 0/invalid
- **Fix Implemented**: Modified shim for `sub_825968B0` to seed scheduler context from `MW05_SCHED_R3_EA` environment variable
- **Status**: ✅ WORKING - Log shows:
  ```
  [HOST] import=sub_825968B0.lr=82596110 r3=00000000
  [HOST] import=HOST.825968B0.invalid_r3 r3=00000000 - attempting to seed
  [HOST] import=HOST.825968B0.seeded_from_env r3=00060E30
  [HOST] import=HOST.SchedR3.Captured r3=00060E30
  ```

### ❌ Missing Initialization Chain - NOT TRIGGERED
The following functions are NEVER called during initialization:
- `sub_82849DE8` - Should trigger video thread creation chain
- `sub_82881020` - Part of video thread creation chain
- `sub_82880FA0` - Part of video thread creation chain
- `sub_824411E0` - Should trigger main thread unblock
- `sub_8284F548` - Video thread creation function (called by chain above)

**Evidence**: None of these addresses appear in any `lr=` fields in the 89,369 log lines.

### ✅ Thread Creation - PARTIALLY WORKING
- **Function**: `sub_8284F548` at `0x8284F548`
- **Status**: ✅ WORKING - Creates 2 threads successfully:
    - Thread 1: Entry point `0x828508A8` (created at line 8729)
    - Thread 2: Entry point `0x82812ED0` (created at line 9041)
- **Caller**: Both threads created from `lr=0x8284F590` (inside `sub_8284F548`)
- **Problem**: Video thread (3rd thread) is never created because the chain to call `sub_8284F548` again is not triggered

## Call Chains (from IDA analysis)

### Video Thread Creation Chain (NOT TRIGGERED)
```
sub_82849DE8 → sub_82881020 → sub_82880FA0 → sub_82885A70 → sub_8284F548 → ExCreateThread
```
**Status**: ❌ `sub_82849DE8` is never called, so entire chain is blocked

### Main Thread Unblock Chain (NOT TRIGGERED)
```
sub_824411E0 → checks flag at 0x828FBB50 → sub_82442080 → sets flag at 0x82A2CF40
```
**Status**: ❌ `sub_824411E0` is never called, so main thread stays blocked
**Workaround**: `MW05_UNBLOCK_MAIN=1` continuously sets the flag in background thread

## Invalid Instructions in MW05.toml
```toml
invalid_instructions = [ 
    { data = 0x82621640, size = 232 }, # Padding
    { data = 0x825968B0, size = 0xC8 }, # sub_825968B0 - replaced by PPC_FUNC in mw05_trace_shims.cpp
]
```

### sub_825968B0 (0x825968B0)
- **Status**: ✅ Shimmed and working
- **Calls**: 21 times total in log
- **Fix**: Scheduler context seeding implemented and working

### sub_82621640 (0x82621640)
- **Status**: ⚠️ Installed but never called
- **Log**: Only appears once: `HOST.sub_82621640.install`
- **Potential**: May be related to missing initialization trigger

## Root Cause Analysis

The scheduler context fix is working correctly, but it's not triggering the missing initialization chain. The problem is that **something should call `sub_82849DE8`** to start the video thread creation, but that trigger is missing.

Possible causes:
1. **Event Handler Not Registered**: `sub_82849DE8` might be a callback that should be registered during initialization
2. **Missing Function Call**: Some initialization function should call `sub_82849DE8` directly but isn't
3. **Conditional Logic**: The code path that calls `sub_82849DE8` might be gated by a condition that's not being met
4. **Timing Issue**: The function might be called via a timer/event that hasn't fired yet

## Next Steps

### Option 1: Find What Should Call sub_82849DE8
- Search IDA export for all references to `sub_82849DE8`
- Check if it's stored in function pointer tables
- Look for initialization functions that might call it

### Option 2: Check sub_82621640
- Investigate what `sub_82621640` does (currently just padding)
- Check if it should be calling initialization functions
- Implement a proper shim if needed

### Option 3: Compare with Xenia
- Run game in Xenia with full logging
- Trace when `sub_82849DE8` and `sub_824411E0` are called
- Identify the trigger mechanism

### Option 4: Force Call the Missing Functions
- Add hooks to force-call `sub_82849DE8` at appropriate time
- Add hooks to force-call `sub_824411E0` at appropriate time
- Test if this unblocks initialization

## Files Modified

### Mw05Recomp/gpu/mw05_trace_shims.cpp
- Lines 884-918: Added scheduler context seeding logic to `MW05Shim_sub_825968B0`
- Checks `MW05_SCHED_R3_EA` environment variable
- Falls back to last known scheduler context
- Successfully seeds `r3=0x00060E30` when invalid

### tools/test_scheduler_fix.py
- Python script to test scheduler context fix
- Runs game for 20 seconds with environment variables
- Analyzes log for seeding messages

### tools/analyze_825968B0.py
- Analyzes sub_825968B0 calls in log
- Confirms new code is working

### tools/find_init_trigger.py
- Searches for initialization patterns
- Extracts unique function addresses from lr= fields
- Identifies missing functions

## Environment Variables

### Current Test Configuration
```
MW05_TRACE_KERNEL=1
MW05_SCHED_R3_EA=0x00060E30
MW05_UNBLOCK_MAIN=1
MW05_FORCE_PRESENT=1
```

### Results
- Scheduler context seeding: ✅ Working
- Main thread unblock: ✅ Working (via workaround)
- Video thread creation: ❌ Still missing
- Missing initialization chain: ❌ Not triggered

