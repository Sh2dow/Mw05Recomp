# SOLUTION: draws=0 Issue - 2025-10-31

## Problem Statement

Game runs for 60+ seconds without crashes but issues **ZERO draw commands** (`draws=0`).

## Root Cause

**The game is stuck in initialization because NO LOADER WORK HAS BEEN QUEUED.**

The game has successfully:
- ✅ Initialized all systems (memory, threads, graphics, PM4)
- ✅ Created main thread and worker threads
- ✅ Set up loader callback system
- ✅ Started frame-based game loop (VD ISR triggering frames)
- ✅ Graphics system running (72 Present calls, 18 VdSwap calls, 2040 GPU commands)

But the game is STUCK because:
- ❌ **NO loader work queued** - `work_func=0x00000000` in loader callback
- ❌ **NO file loading** - StreamBridge never triggered
- ❌ **NO assets loaded** - cannot render without textures/models
- ❌ **NO draw commands** - game stuck in initialization phase

## Evidence

### 1. Main Thread Running (Frame-Based Loop)
```
[MAIN-THREAD-HEARTBEAT] tid=000026C8 alive for 34 seconds
```

Main loop at `0x82441CF0` waits for VD ISR to set frame flag:
```c
for ( ; !dword_82A2CF40; v0 = sub_8262D9D0(0) )
  ;
```

VD ISR sets flag every frame:
```
[VD-ISR] Set main loop flag at 0x82A2CF40 to 1 (frame #12)
[VD-ISR] Set main loop flag at 0x82A2CF40 to 1 (frame #34)
```

### 2. Loader Thread Created and Running
```
[THREAD_82850930] ENTER r3=00000000 r4=00000000 r5=8261A558 r6=82A2B318
[THREAD_82850930] EXIT r3=B5909000 (return value)
```

### 3. Loader Callback Called But NO WORK
```
[CALLBACK_8261A558] ENTER: count=0 r3=82A2B318 tid=3eb4
[CALLBACK_8261A558]   work_func=0x00000000 param1=0x82441E58 param2=0x00000000
[CALLBACK_8261A558] RETURN: count=0 r3=00000000
```

**CRITICAL**: `work_func=0x00000000` - NO WORK QUEUED!

### 4. StreamBridge Ready But Never Triggered
```
[FAIL] NO StreamBridge activity - game is not trying to load files!
[INFO] NO sentinel writes detected
```

StreamBridge is enabled and ready, but the game never writes the sentinel value `0x0A000000` because the loader dispatcher is never called.

## How It Should Work

### Normal Initialization Flow
1. Game initializes all systems
2. **Game queues first loader job** (load boot files like GLOBALMEMORYFILE.BIN)
3. Loader callback processes the job
4. Loader dispatcher writes sentinel `0x0A000000` to scheduler block
5. StreamBridge detects sentinel and loads files
6. Game loads assets (textures, models, etc.)
7. Game progresses to rendering phase
8. Game issues draw commands

### Current Flow (STUCK)
1. Game initializes all systems ✅
2. **Game NEVER queues first loader job** ❌ **<-- STUCK HERE**
3. Loader callback has no work to do
4. Loader dispatcher never called
5. StreamBridge never triggered
6. No files loaded
7. Game stuck in initialization
8. No draw commands

## What's Missing?

Something in the initialization sequence should queue the first loader job, but it's not happening. Possible causes:

### 1. Missing Initialization Callback
- Some init function should queue boot file loading
- This callback might not be registered or not being called
- Check initialization sequence for missing steps

### 2. State Machine Not Transitioning
- Game might be in "waiting for profile" state
- Game might be waiting for user input (press START)
- Game might be waiting for some system event

### 3. Display Initialization Incomplete
- Display dimensions are zero (forced to 1280x720)
- Viewport bounds are invalid [0,0,0,0]
- Game might be waiting for display to be fully initialized

### 4. Profile Manager Callback (Inherited from Unleashed)
- Game might be waiting for profile manager callback
- This callback might be incompatible with Most Wanted
- Need to check if profile system is properly initialized

## Next Steps to Fix

### Step 1: Find What Queues Loader Work
- Search for functions that write to loader callback structure at `0x82A2B318+0x1C` (work_func field)
- Find initialization functions that should queue boot file loading
- Check if there's a missing initialization callback

### Step 2: Check State Machine
- Find what state the game is in
- Check if game is waiting for user input
- Check if game is waiting for profile manager

### Step 3: Force-Test Loader System
- Manually queue a loader job to test if system works
- If successful, find why it's not being queued naturally
- This would confirm the loader system is functional

### Step 4: Compare with Working Version
- Check how Xbox 360 version initializes
- Find what triggers the loader dispatcher
- Identify missing initialization steps

## Temporary Workaround (For Testing)

Create a function that manually queues a loader job:

```cpp
// Force-queue first loader job (TEMPORARY TEST)
void ForceStartLoader() {
    uint32_t callback_param_addr = 0x82A2B318;
    be<uint32_t>* callback_param = reinterpret_cast<be<uint32_t>*>(base + callback_param_addr);
    
    // Queue a loader job
    callback_param[4] = 0x82441E58;  // param1 (work function)
    callback_param[5] = 0x00000000;  // param2
    callback_param[7] = 0x00000000;  // work_func (NULL = use param1 as function)
    
    // This should trigger the loader callback to process the job
}
```

If this works, it confirms the loader system is functional and the issue is just that the first job isn't being queued naturally.

## Conclusion

The game is NOT broken - all systems are working correctly. The game is just stuck in a waiting state because something needs to queue the first loader job, but that hasn't happened yet.

**The fix is to find what should naturally queue the first loader job and make sure it happens.**

Once that's fixed, the game will:
1. Queue loader job
2. Load boot files via StreamBridge
3. Load assets (textures, models)
4. Progress to rendering phase
5. Issue draw commands
6. **Game will render!**

This is a **state machine issue**, not a system failure. All the infrastructure is in place and working - we just need to trigger the state transition from "initialization" to "loading".

