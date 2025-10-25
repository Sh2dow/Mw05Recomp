# MAJOR BREAKTHROUGH: Callback Offset Fix SUCCESS!

**Date**: 2025-10-24  
**Status**: ✅ CALLBACK INITIALIZATION FIXED - Game now progresses much further!

## Executive Summary

We discovered and fixed a CRITICAL BUG in the callback initialization code. The callback function and parameter offsets were swapped, causing NULL-CALL errors. After fixing the offsets based on IDA disassembly analysis, the game now:

✅ Initializes the callback successfully  
✅ Executes the entire initialization chain  
✅ Completes game initialization  
✅ Runs the main game loop  

However, the game still doesn't call CreateDevice or create the main render thread, so draws=0 persists.

## The Bug

### Original (WRONG) Code
```cpp
struct_u32[88/4] = be<uint32_t>(0x8261A558);  // +0x58 (88) - callback function
struct_u32[92/4] = be<uint32_t>(0x82A2B318);  // +0x5C (92) - callback parameter
```

### IDA Disassembly Evidence (sub_82850820)
```assembly
0x82850844: lwz r3, 0x58(r11)    # Load callback PARAMETER from offset +0x58 (88)
0x82850848: lwz r11, 0x54(r11)   # Load callback FUNCTION from offset +0x54 (84)
0x8285084C: mtspr CTR, r11       # Move function to CTR
0x82850850: bctrl                # Call through CTR
```

**The assembly clearly shows:**
- Callback FUNCTION is at offset +0x54 (84)
- Callback PARAMETER is at offset +0x58 (88)

But our code had them swapped!

### Fixed Code
```cpp
struct_u32[84/4] = be<uint32_t>(0x8261A558);  // +0x54 (84) - callback function ✅
struct_u32[88/4] = be<uint32_t>(0x82A2B318);  // +0x58 (88) - callback parameter ✅
```

## Results After Fix

### What's Now Working ✅

1. **Callback Initialization**
   ```
   [826BE3E8] Callback function at +84: 0x00000000, parameter at +88: 0x00000000
   [826BE3E8] FIXING: Initializing callback at +84 to 0x8261A558, parameter at +88 to 0x82A2B318!
   [826BE3E8] FIXED: Callback pointers initialized in REAL structure at 0x00227560!
   ```

2. **Callback Execution**
   ```
   [CALLBACK_8261A558] ENTER: count=0 r3=82A2B318 tid=59d0
   ```

3. **Work Function Execution**
   ```
   [THREAD_828508A8] Work function pointer: 0x82441E58
   ```

4. **Initialization Chain**
   ```
   [WORKER_LOOP_823B0190] ENTER: count=0 tid=59d0
   [INIT_823AF590] ENTER: count=0 tid=59d0
   ```

5. **Initialization Complete**
   ```
   [INIT-MGR] Initialization complete: 6 succeeded, 0 failed
   [MAIN] Initialization complete! 6 callbacks registered.
   ```

6. **Main Loop Running**
   ```
   [MAIN-LOOP] Entering main event loop, present_main=1
   [MAIN-LOOP] Iteration #1
   [MAIN-LOOP] Iteration #2
   ...
   [MAIN-LOOP] Iteration #10
   ```

7. **VBLANK Pump Active**
   ```
   [VBLANK] Main loop flag: was=0x00000000 now=0x00000001 (tick=1139 count=1140)
   ```

8. **PM4 Processing**
   ```
   [PM4-TYPE-DIST] TYPE0=2170750 TYPE1=0 TYPE2=0 TYPE3=1626250 total=3797000
   ```

### What's Still NOT Working ❌

1. **CreateDevice Never Called**
   - Function sub_82598230 is never executed
   - None of its callers (0x82439EF8, 0x82440510, 0x825A8748, 0x825A8B38, 0x820D01E8) are called

2. **Main Render Thread Never Created**
   - Thread 0x825AA970 is never created
   - None of the functions that create it (0x82439790, 0x824404CC, 0x820D04F0) are called

3. **Draws Still = 0**
   ```
   [DRAWS] draws=0
   ```

4. **Render Threads Have NULL Function Pointers**
   ```
   [NULL-CALL] lr=826E7BAC target=00020000 r3=B59017C0 r31=13CAF300 r4=00000000
   [NULL-CALL] lr=826E7BDC target=00032394 r3=B59018F0 r31=13DAF300 r4=00000000
   ```

## Analysis

### Progress Made

The callback offset fix was **THE RIGHT FIX**! It unlocked the entire initialization chain:

```
Callback 0x8261A558 (FIXED!)
    ↓
Work Function 0x82441E58
    ↓
Worker Loop 0x823B0190
    ↓
Initialization 0x823AF590
    ↓
Game Initialization Complete
    ↓
Main Loop Running
```

### Current Bottleneck

The game is now stuck in a **waiting state**. It has completed initialization and is running its main loop, but it hasn't progressed to the point where it would call CreateDevice.

Possible reasons:
1. **Waiting for splash screen/video to finish**
2. **Waiting for profile/save data to load**
3. **Waiting for user input (menu selection)**
4. **Waiting for Xbox system notification**
5. **Waiting for some state machine to progress**

### Evidence

1. **Main loop is running** - Game is not frozen
2. **No XNotifyGetNext calls** - Game is not polling for notifications
3. **No TitleState messages** - State machine not logging
4. **Worker threads waiting** - Thread 0x75C0 repeatedly waiting on handle 0xB5901C80
5. **Render threads created but inactive** - Threads 826E7B90, 826E7BC0, 826E7BF0, 826E7C20 created but have NULL function pointers

## Next Steps

### Immediate Investigation

1. **Find what triggers CreateDevice**
   - Trace backwards from CreateDevice callers
   - Identify the state machine or event that should trigger it
   - Check if there's a menu or splash screen blocking progression

2. **Check for missing notifications**
   - The game might be waiting for a system notification we're not sending
   - Check XamNotifyEnqueueEvent usage
   - See if we need to send a specific notification to unblock progression

3. **Investigate render thread NULL pointers**
   - Threads 826E7B90, etc. are created but have NULL function pointers
   - Find where these function pointers should be initialized
   - This might be related to CreateDevice not being called

4. **Check for file I/O blocking**
   - The game might be waiting for a file to load
   - Check StreamBridge logs
   - See if there are any pending file operations

### Long-term Strategy

The callback offset fix proves that **careful analysis of assembly code is the key to finding bugs**. We should:

1. Use IDA Pro HTTP API more aggressively to verify our assumptions
2. Always cross-reference our code against the actual PowerPC assembly
3. Look for similar offset bugs in other initialization code
4. Document all structure layouts we discover

## Conclusion

**This is MAJOR PROGRESS!** We went from:
- ❌ Callback never initialized → ✅ Callback initialized and called
- ❌ Initialization chain never runs → ✅ Full initialization chain executes
- ❌ Game stuck at boot → ✅ Game running main loop

The callback offset fix was the breakthrough we needed. Now we need to figure out what's blocking the game from progressing to CreateDevice. The game is much closer to rendering than before!

## Files Modified

- `Mw05Recomp/cpu/mw05_trace_threads.cpp` (lines 1093-1111) - Fixed callback offsets
- `Mw05Recomp/gpu/video.cpp` (lines 8428, 8451-8452) - Commented out missing function references

## Test Command

```powershell
python scripts/auto_handle_messageboxes.py --duration 60
```

## Log Analysis Commands

```powershell
# Check callback initialization
Get-Content 'traces/auto_test_stderr.txt' | Select-String '826BE3E8.*FIXING|826BE3E8.*FIXED'

# Check callback execution
Get-Content 'traces/auto_test_stderr.txt' | Select-String '8261A558|CALLBACK_8261A558'

# Check initialization chain
Get-Content 'traces/auto_test_stderr.txt' | Select-String '82441E58|823B0190|823AF590|INIT_823AF590'

# Check for CreateDevice
Get-Content 'traces/auto_test_stderr.txt' | Select-String 'CreateDevice|82598230'

# Check for render thread creation
Get-Content 'traces/auto_test_stderr.txt' | Select-String '825AA970'

# Check draws
Get-Content 'traces/auto_test_stderr.txt' | Select-String 'draws=' | Select-Object -Last 10
```

