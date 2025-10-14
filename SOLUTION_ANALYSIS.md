# MW05 Stale Launch Issue - Root Cause Analysis and Solution

## Problem Statement
The application launches but is completely stale - even the FPS overlay is frozen. It requires multiple environment variable workarounds (`MW05_UNBLOCK_MAIN`, `MW05_FORCE_GFX_NOTIFY_CB`, etc.) to function, but these are hacks that interfere with the game's natural flow.

## Root Cause Analysis

### The Main Game Loop (`sub_82441CF0` at 0x82441CF0)
```c
while (1) {
    // Wait for dword_82A2CF40 to become non-zero, sleeping while waiting
    for ( ; !dword_82A2CF40; v0 = sub_8262D9D0(0) )
        ;  // Calls sleep function
    
    // Do frame update work
    // ...
    
    dword_82A2CF40 = 0;  // Clear the flag at the end
    
    sub_8262DE60(...);  // Frame update function
}
```

**Key Points**:
1. Main thread waits for `dword_82A2CF40` (at 0x82A2CF40) to become 1
2. After doing frame work, it clears the flag back to 0
3. This repeats every frame - something must set the flag EVERY frame

### The VD Interrupt Callback (`sub_825979A8` at 0x825979A8)
```c
void sub_825979A8(int source, DWORD *context) {
    if (source == 1) {
        // Handle CPU interrupt
        // ...
    }
    else if (source == 0 && (MEMORY[0x7FE86544] & 1) != 0) {
        // This is the path that should set dword_82A2CF40 each frame!
        // But it only runs if the flag at 0x7FE86544 is set
        
        // Update frame counters
        ++context[3900];  // Increment frame counter
        
        // Check if should call the frame callback
        if (context[3899]) {  // If callback is registered
            // Call the callback function
            v23[0] = context[3900];  // Frame number
            v23[1] = context[3903];  // Some parameter
            v23[2] = 0;
            callback_function(v23);  // This eventually sets dword_82A2CF40 = 1
        }
    }
}
```

**Key Points**:
1. VD ISR is called every VBlank (60 Hz) with `source=0` or `source=1`
2. When `source=0`, it checks flag at `0x7FE86544`
3. If flag is set AND callback is registered (`context[3899]`), it calls the callback
4. The callback eventually sets `dword_82A2CF40 = 1` to wake the main thread

### The Initialization Function (`sub_82442080` at 0x82442080)
```c
int sub_82442080(int a1) {
    // ... initialization code ...
    
    dword_82A2CF40 = 1;  // Set the flag ONCE during initialization
    
    // ... more initialization ...
    
    return result;
}
```

**Key Points**:
1. This function is called ONCE during initialization
2. It sets `dword_82A2CF40 = 1` to unblock the main thread initially
3. But it doesn't set the flag at `0x7FE86544` that enables the VD ISR callback

## The Problem

**What's Missing**:
The flag at `0x7FE86544` is NEVER set during initialization, so the VD ISR callback never calls the function that sets `dword_82A2CF40` each frame.

**Result**:
1. `sub_82442080` sets `dword_82A2CF40 = 1` ONCE during init
2. Main thread wakes up, does ONE frame of work
3. Main thread clears `dword_82A2CF40 = 0` at the end of the frame
4. Main thread waits forever for the flag to be set again
5. VD ISR is called every VBlank, but does nothing because `0x7FE86544` is not set
6. Game is stuck forever

## Current Workarounds (HACKS)

### `MW05_UNBLOCK_MAIN` Workaround
Does THREE things:
1. Calls `sub_82442080` once to set the flag initially
2. Forces `LoadBE32_Watched` to ALWAYS return 1 when reading `0x82A2CF40`
3. Blocks `StoreBE32_Watched` from writing 0 to `0x82A2CF40`

**Problem**: This prevents the game from ever clearing the flag, breaking the frame pacing system.

### Other Workarounds
- `MW05_FORCE_GFX_NOTIFY_CB`: Forces graphics callback registration
- `MW05_FORCE_RENDER_THREAD`: Force-creates the render thread
- `MW05_BREAK_SLEEP_LOOP`: Breaks sleep loops
- Many others...

**Problem**: All of these are band-aids that force things to happen instead of fixing the root cause.

## The Real Solution

### Option 1: Set the VD ISR Flag During Initialization
Set the flag at `0x7FE86544` during initialization so the VD ISR callback will work naturally.

**Implementation**:
```cpp
// In KiSystemStartup() or similar early init function
void InitializeVdIsrFlag() {
    const uint32_t vd_flag_ea = 0x7FE86544;
    uint32_t* vd_flag_ptr = static_cast<uint32_t*>(g_memory.Translate(vd_flag_ea));
    if (vd_flag_ptr) {
        *vd_flag_ptr = __builtin_bswap32(1);  // Set flag (big-endian)
        fprintf(stderr, "[INIT] Set VD ISR flag at 0x%08X to 1\n", vd_flag_ea);
    }
}
```

### Option 2: Call the Frame Callback from VD ISR
Modify the VD ISR to call the frame callback even if the flag at `0x7FE86544` is not set.

**Implementation**:
```cpp
// In VdCallGraphicsNotificationRoutines or similar
void CallFrameCallback(uint32_t source, uint32_t context) {
    if (source == 0) {
        // Check if callback is registered
        uint32_t* ctx_u32 = static_cast<uint32_t*>(g_memory.Translate(context));
        if (ctx_u32 && ctx_u32[3899]) {  // context[3899] = callback registered flag
            // Call the callback function
            uint32_t callback_fn = ctx_u32[...];  // Get callback function pointer
            GuestToHostFunction<void>(callback_fn, ...);
        }
    }
}
```

### Option 3: Set the Main Thread Flag from VD ISR
Directly set `dword_82A2CF40 = 1` from the VD ISR each frame.

**Implementation**:
```cpp
// In VD ISR callback (called every VBlank)
void VdIsrCallback(uint32_t source, uint32_t context) {
    if (source == 0) {
        // Set the main thread flag to wake it up
        const uint32_t flag_ea = 0x82A2CF40;
        uint32_t* flag_ptr = static_cast<uint32_t*>(g_memory.Translate(flag_ea));
        if (flag_ptr) {
            *flag_ptr = __builtin_bswap32(1);  // Set flag (big-endian)
        }
    }
}
```

## Recommended Solution

**Use Option 1**: Set the VD ISR flag at `0x7FE86544` during initialization.

**Why**:
1. Minimal intervention - just sets one flag
2. Allows the game's natural flow to work
3. No need to modify the VD ISR callback
4. No need to force-read/write the main thread flag

**Where to implement**:
- In `KiSystemStartup()` after VBlank pump is started
- OR in `UnblockMainThreadEarly()` if `MW05_UNBLOCK_MAIN` is enabled (as a proper fix instead of the current hack)

## Testing Plan

1. Remove ALL environment variable workarounds from `run_with_debug.ps1`
2. Implement Option 1 (set VD ISR flag during init)
3. Build and run the application
4. Verify that:
   - Main thread wakes up and runs frame loop
   - VD ISR callback is called every VBlank
   - Main thread flag is set/cleared naturally each frame
   - FPS overlay updates (not frozen)
   - Game progresses to draw commands

## Next Steps

1. Implement the fix (Option 1)
2. Test without workarounds
3. If successful, remove all the hack code:
   - `LoadBE32_Watched` flag forcing
   - `StoreBE32_Watched` flag blocking
   - `UnblockThreadFunc` background thread
   - All the `MW05_FORCE_*` environment variables
4. Clean up the codebase

