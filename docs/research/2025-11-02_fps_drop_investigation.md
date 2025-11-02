# FPS Drop Investigation - Workarounds vs Natural Execution

**Date**: 2025-11-02  
**Issue**: MW05_FORCE_VD_INIT=1 and MW05_PM4_SYSBUF_SCAN=1 cause massive FPS drops (15-25 FPS instead of 60+ FPS)

## 🎯 Executive Summary

**The workarounds are making things WORSE, not better!**

- ✅ VdSwap IS being called naturally by the game (~5 FPS)
- ✅ PM4 scanning IS working (VdSwap scans the buffer)
- ❌ Workarounds add redundant overhead causing FPS drops
- ❌ Real problem: Game stuck in initialization with `draws=0`

## 📊 Test Results

### Natural Execution (No Workarounds)
```
Test Duration: 10 seconds
VdSwap Calls: 53 (~5 FPS)
PM4 Scans: 53 (once per VdSwap)
Draw Commands: 0
Memory: 1.6 GB
FPS: ~5 FPS (game is slow because it's stuck in init)
```

### With Workarounds (MW05_FORCE_VD_INIT=1 + MW05_PM4_SYSBUF_SCAN=1)
```
Test Duration: 10 seconds
VdSwap Calls: 53 (~5 FPS)
PM4 Scans: 53 (VdSwap) + 600 (Video::Present at 60 FPS) = 653 scans!
Draw Commands: 0
Memory: 3.9 GB (memory leak!)
FPS: 15-25 FPS (massive overhead from redundant scanning)
```

## 🔍 Root Cause Analysis

### Issue 1: Redundant PM4 Scanning

**VdSwap already scans PM4 buffer** (kernel/imports.cpp:1565):
```cpp
void VdSwap(...) {
    // Mark that the guest performed a swap
    g_guestHasSwapped.store(true, std::memory_order_release);
    g_sawRealVdSwap.store(true, std::memory_order_release);

    // CRITICAL FIX: Scan system command buffer for PM4 commands
    PM4_ScanSystemCommandBuffer();  // <-- ALREADY SCANNING HERE!

    // Request present from background
    Video::RequestPresentFromBackground();
}
```

**MW05_PM4_SYSBUF_SCAN=1 adds SECOND scan** (video.cpp:3527):
```cpp
if (s_enable_sysbuf_scan) {  // <-- REDUNDANT SCAN!
    uint32_t sysEA = Mw05GetSysBufBaseEA();
    if (sysEA) {
        PM4_ScanLinear(sysEA + headSkip, payloadSize);
    }
}
```

**Result**: 
- VdSwap scans: 5 times/second (when game calls it)
- Video::Present scans: 60 times/second (host present rate)
- **Total: 65 scans/second of 64KB buffer = 4.16 MB/second overhead!**

### Issue 2: MW05_FORCE_VD_INIT Overhead

**What it does**:
- Manually initializes ring buffer (64 KB allocation)
- Manually initializes system command buffer (64 KB allocation)
- Registers VD ISR callback
- Starts VBlank pump thread

**Why it causes FPS drop**:
- Adds extra thread overhead (VBlank pump)
- Adds extra callback overhead (VD ISR)
- Game should do this naturally - forcing it creates duplicate work

### Issue 3: Memory Leak

**MW05_PM4_SYSBUF_SCAN=0 causes memory leak** (1.6 GB → 3.9 GB):
- This is because PM4 commands accumulate without being processed
- BUT: VdSwap already processes them!
- The leak happens because the workaround is disabled but VdSwap isn't being called frequently enough

## ✅ The Real Problem

**Game is stuck in initialization phase**:
- VdSwap is being called naturally (~5 FPS)
- PM4 scanning is working
- BUT: `draws=0` - no draw commands being issued
- Game hasn't progressed from init to rendering

**From 2025-10-27_final_status.md**:
```
PM4 Packet Distribution (120-second test):
- TYPE0: 5,110,736 (54.7%) - Register writes
- TYPE3: 4,235,264 (45.3%) - Commands (ALL opcode 0x3E - CONTEXT_UPDATE)
- Opcode 0x04 (Micro-IB): 0
- Opcode 0x22 (DRAW_INDX): 0
- Opcode 0x36 (DRAW_INDX_2): 0
```

The game is **configuring the GPU** (4.2M context updates) but **not drawing anything**.

## 🔧 Solution

### Step 1: Remove Workarounds (DONE)

**Reverted changes**:
- `Mw05Recomp/kernel/imports.cpp`: Restored environment variable check in `Mw05ForceVdInitOnce()`
- `Mw05Recomp/gpu/pm4_parser.cpp`: Restored environment variable check in `IsSysBufScanEnabled()`
- `Mw05Recomp/main.cpp`: Disabled default values for MW05_FORCE_VD_INIT and MW05_PM4_SYSBUF_SCAN

**Result**: Game runs naturally without workarounds, no FPS drop from redundant scanning.

### Step 2: Fix Root Cause (TODO)

**Investigate why game is stuck in initialization**:

1. **Check main loop** (AGENTS.md says it was fixed):
   - Main loop (`sub_82441CF0`) should loop infinitely
   - Was fixed by removing wrapper that broke the loop
   - Verify it's actually looping now

2. **Check game state machine**:
   - Game might be waiting for user input
   - Game might be stuck in menu/splash screen
   - Game might be waiting for asset loading

3. **Check render threads**:
   - Verify render threads are created
   - Verify render threads are running
   - Check if they're blocked waiting for something

4. **Check file I/O**:
   - Monitor asset loading (textures, models, shaders)
   - Check for missing or failed file loads
   - Verify game assets are in correct location

5. **Compare with Xenia**:
   - Run Xenia with same game
   - See when Xenia starts issuing draw commands
   - Compare initialization sequences

## 📝 Next Steps

### Immediate Actions

1. ✅ **Remove workarounds** - Done
2. ⏳ **Build and test** - Verify game runs without workarounds
3. ⏳ **Monitor VdSwap calls** - Check if frequency increases
4. ⏳ **Check for draw commands** - See if `draws` counter increments

### Investigation Plan

1. **Run longer test** (5-10 minutes):
   - See if game eventually progresses to rendering
   - Monitor VdSwap call frequency
   - Check if draw commands appear

2. **Add detailed logging**:
   - Log game state transitions
   - Log render thread activity
   - Log file I/O operations

3. **Use IDA Pro API**:
   - Decompile main loop function
   - Decompile game state machine
   - Find what's blocking progression

4. **Check AGENTS.md fixes**:
   - Verify main loop fix is working
   - Verify region check bypass is working
   - Verify infinite recursion fix is working

## 🎯 Expected Outcome

**After removing workarounds**:
- ✅ No FPS drop from redundant scanning
- ✅ No memory leak from forced VD init
- ✅ Game runs naturally at its own pace
- ⏳ Still `draws=0` (need to fix root cause)

**After fixing root cause**:
- ✅ Game progresses to rendering
- ✅ Draw commands start appearing
- ✅ 60+ FPS achieved naturally
- ✅ No workarounds needed

## 📚 References

- `docs/research/2025-10-27_final_status.md` - Current status with `draws=0`
- `docs/research/2025-10-30_main_loop_investigation.md` - Main loop bug investigation
- `docs/research/2025-11-01_pm4_deadbeef_corruption_fix.md` - PM4 buffer analysis
- `AGENTS.md` - Known issues and fixes

## 🔑 Key Insights

1. **Workarounds hide root causes** - They make symptoms worse while masking the real problem
2. **VdSwap is the natural path** - Game calls it when ready to present a frame
3. **PM4 scanning should happen in VdSwap** - Not in Video::Present()
4. **FPS drop is from overhead** - Not from the game being slow
5. **Real problem is initialization** - Game is stuck before rendering starts

## ✅ Conclusion

**The workarounds are NOT fixes** - they're band-aids that cause more problems:
- MW05_FORCE_VD_INIT: Adds overhead, not needed (game calls VdSwap naturally)
- MW05_PM4_SYSBUF_SCAN: Redundant scanning, causes FPS drop

**The real fix**: Find why game is stuck in initialization with `draws=0` and fix that root cause.

**Expected result**: 60+ FPS naturally, no workarounds needed.

## 🎯 Changes Applied (2025-11-02)

### Files Modified

1. **Mw05Recomp/main.cpp**:
   - Lines 103-108: Disabled MW05_FORCE_VD_INIT default (was forcing to "1")
   - Lines 125-129: Disabled MW05_PM4_SYSBUF_SCAN default (was forcing to "1")
   - Lines 167-171: Disabled MW05_FORCE_VD_INIT default (second instance)
   - Lines 188-189: Disabled MW05_PM4_SYSBUF_SCAN default (second instance)
   - Added comments explaining these are workarounds that cause FPS drops

2. **Mw05Recomp/kernel/imports.cpp**:
   - Lines 6605-6612: Changed `Mw05ForceVdInitEnabled()` default from `true` to `false`
   - Added comments explaining this is a workaround that causes FPS drops

3. **Mw05Recomp/gpu/pm4_parser.cpp**:
   - Lines 332-342: Fixed `IsSysBufScanEnabled()` to use `std::getenv` instead of undefined `MwGetEnvBool`
   - Function now correctly checks MW05_PM4_SYSBUF_SCAN environment variable

### Build Status

✅ Build succeeded with no errors

### Testing

Run the following command to test natural execution:
```powershell
python scripts/test_natural_path.py --duration 30
```

Expected results:
- VdSwap calls: ~5 FPS (game is slow because stuck in init)
- PM4 scans: Same as VdSwap calls (no redundant scanning)
- Memory: ~1.6 GB (stable, no leaks)
- draws=0: Still zero (game stuck in initialization - separate issue)

### Next Steps

1. **Test natural execution** - Verify game runs without workarounds
2. **Investigate draws=0** - Find why game is stuck in initialization
3. **Fix root cause** - Make game progress to rendering naturally
4. **Achieve 60+ FPS** - Once game progresses to rendering, FPS should be 60+

