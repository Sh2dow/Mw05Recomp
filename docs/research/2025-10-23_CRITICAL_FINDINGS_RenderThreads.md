# CRITICAL FINDINGS: Render Thread Creation Blocked

## Executive Summary

The game is **stuck in initialization** and never reaches the point where it creates the main render thread (0x825AA970). This is why draws=0 even after 90+ seconds of runtime.

## Root Cause

**CreateDevice (sub_82598230) is NEVER called!**

From `Mw05Recomp/gpu/video.cpp` line 8553:
```cpp
// CRITICAL: If CreateDevice fails (r3 != 0), the game won't create render threads!
// This blocks progression to file I/O and rendering
```

The game's initialization flow is:
1. Initialize graphics context ✅ (DONE - gfx_ctx at 0x00445EE0)
2. Progress through TitleState machine ❌ (STUCK in loop: 0x6ED → 0x100 → 0x11C → repeat)
3. Call CreateDevice (sub_82598230) ❌ (NEVER CALLED)
4. Create render thread 0x825AA970 ❌ (NEVER CREATED)
5. Start file I/O and asset loading ❌ (NEVER STARTED)
6. Issue draw commands ❌ (draws=0)

## Evidence

### 1. CreateDevice Never Called
```bash
$ grep -i "CreateDevice\|82598230" traces/auto_test_stderr.txt
# NO RESULTS

$ grep -i "CreateDevice\|82598230" out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log
# NO RESULTS
```

### 2. Render Thread 0x825AA970 Never Created
```bash
$ grep "825AA970" traces/auto_test_stderr.txt | grep "created"
# NO RESULTS
```

Worker threads (0x826E7B90, 0x826E7BC0, 0x826E7BF0, 0x826E7C20) ARE created naturally but exit immediately because their contexts are not properly initialized.

### 3. TitleState Stuck in Loop
From trace log (last 30 lines):
```
TitleState w0=000006ED  # State 1
TitleState w0=00000100  # State 2
TitleState w0=0000011C  # State 3
TitleState w0=000006EE  # State 1 (incremented)
TitleState w0=00000100  # State 2
TitleState w0=0000011C  # State 3
TitleState w0=000006EF  # State 1 (incremented)
... (repeats forever)
```

The game is cycling through states but never progressing to the CreateDevice state.

### 4. No File I/O
```bash
$ grep "StreamBridge\|FILE" out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log
# NO RESULTS
```

The StreamBridge file I/O system is not being used at all. The game hasn't started loading assets.

### 5. Render Thread Entry Function Analysis

From `IDA_dumps/sub_825AA970_decompile.txt`:
```c
void __fastcall sub_825AA970(struct _KEVENT *a1)
{
  v4 = *(_DWORD *)&a1->Header.Type;  // v4 = gfx_ctx pointer (0x00445EE0)
  ...
  if ( !*(_DWORD *)(v4 + 4) )  // if (*(gfx_ctx + 4) == 0)
    break;  // EXIT THE THREAD!
  ...
}
```

The render thread checks `gfx_ctx+4` and exits if it's 0. This field must be set to a non-zero value by CreateDevice or some other initialization function. Since CreateDevice is never called, this field is never set, so even if we force-create the thread, it exits immediately.

## What's Working

1. ✅ Game is running and stable (90+ seconds without crashes)
2. ✅ Main loop is running (no sleep calls)
3. ✅ VBLANK pump is running at 60 Hz (tick 1500+)
4. ✅ PM4 scanner is processing commands (8+ million packets)
5. ✅ VdSwap is being called (130+ times)
6. ✅ Present is being called (104+ times)
7. ✅ Graphics context allocated and initialized (0x00445EE0)
8. ✅ Profile files exist and are loaded
9. ✅ Heap allocation is healthy (6 MB allocated)

## What's NOT Working

1. ❌ CreateDevice never called
2. ❌ Render thread 0x825AA970 never created
3. ❌ TitleState stuck in loop (never progresses)
4. ❌ File I/O never starts
5. ❌ Draw commands never issued (draws=0)

## Why Force-Creating Threads Doesn't Work

We tried force-creating the render thread at 0x825AA970, and it was created successfully:
```
[RENDER-THREAD] Render thread created successfully!
Entry: 0x825AA970
TID: 0x0001212C
Handle: 0xB5901010
```

But the thread **exited immediately**:
```
[GUEST_THREAD] Thread tid=0001212C entry=825AA970 COMPLETED
```

This is because:
1. The thread checks `gfx_ctx+4` and exits if it's 0
2. CreateDevice is supposed to set `gfx_ctx+4` to a non-zero value
3. Since CreateDevice is never called, `gfx_ctx+4` remains 0
4. The thread exits immediately

## What's Blocking CreateDevice?

The game is stuck in the TitleState loop and never progresses to the state where it calls CreateDevice. Possible causes:

1. **Missing user input**: The game might be waiting for a button press to start (e.g., "Press START" screen)
2. **Missing profile data**: Some profile setting or save data might be missing or invalid
3. **Missing game files**: Some critical asset file might be missing
4. **Initialization dependency**: Some other system needs to be initialized first
5. **State machine bug**: The recompiled state machine code might have a bug

## Next Steps

### Option 1: Find What's Blocking State Progression
- Instrument the TitleState functions (0x825972B0, 0x82596978, 0x825A97B8) to see what they're waiting for
- Check if there's a "Press START" screen or similar user input requirement
- Verify all required profile settings are present

### Option 2: Force Call CreateDevice
- Manually call CreateDevice (sub_82598230) from host code after graphics init
- This might skip the blocked state and allow the game to progress
- Risk: Might cause crashes if prerequisites aren't met

### Option 3: Debug State Machine
- Attach debugger and trace through the TitleState functions
- Find the condition that's preventing progression
- Fix the condition or bypass it

## Recommendation

**Start with Option 1**: Instrument the TitleState functions to understand what the game is waiting for. This is the safest approach and will give us the most information.

If that doesn't work, try **Option 2**: Force-call CreateDevice after a delay (e.g., 5 seconds after graphics init). This is more aggressive but might unblock the game.

**Avoid force-creating threads** - this treats the symptom, not the cause. The threads will just exit immediately anyway because their contexts aren't initialized.

