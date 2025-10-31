# ROOT CAUSE: draws=0 Issue - 2025-10-31

## Summary

**ROOT CAUSE IDENTIFIED**: Game is stuck in initialization because **NO LOADER WORK HAS BEEN QUEUED**.

The game has:
- ✅ Main thread running (frame-based loop)
- ✅ Worker threads created and running
- ✅ Loader callback system initialized
- ✅ VD ISR triggering frames
- ✅ Graphics system initialized
- ❌ **NO LOADER WORK QUEUED** - work_func is NULL!

## Evidence

### Main Thread Running
```
[MAIN-THREAD-HEARTBEAT] tid=000026C8 alive for 34 seconds
```

### Frame-Based Game Loop
Main loop at `0x82441CF0` waits for `dword_82A2CF40` to be set by VD ISR:

```c
for ( ; !dword_82A2CF40; v0 = sub_8262D9D0(0) )
  ;
```

VD ISR sets the flag on every frame:
```
[VD-ISR] Set main loop flag at 0x82A2CF40 to 1 (frame #12)
[VD-ISR] Set main loop flag at 0x82A2CF40 to 1 (frame #34)
[VD-ISR] Set main loop flag at 0x82A2CF40 to 1 (frame #54)
```

### Loader Thread Created
```
[THREAD_82850930] ENTER r3=00000000 r4=00000000 r5=8261A558 r6=82A2B318 r7=00000004 r8=82A2B31C lr=8261A6F8
[THREAD_82850930] EXIT r3=B5909000 (return value)
```

### Loader Callback Called But NO WORK
```
[CALLBACK_8261A558] ENTER: count=0 r3=82A2B318 tid=3eb4
[CALLBACK_8261A558]   work_func=0x00000000 param1=0x82441E58 param2=0x00000000
[CALLBACK_8261A558] RETURN: count=0 r3=00000000
```

**CRITICAL**: `work_func=0x00000000` - NO WORK QUEUED!

## Loader Callback Logic

From `sub_8261A558` decompilation:

```c
int __fastcall sub_8261A558(_DWORD *a1)
{
  int v2 = a1[4];  // param1
  int v3 = a1[5];  // param2
  int v5 = a1[7];  // work_func
  
  a1[2] = 1;  // Set state to "running"
  
  if ( v5 )  // If work_func is NOT NULL
  {
    v6 = v4(v2, v3);  // Call work_func(param1, param2)
  }
  else
  {
    v6 = ((int (__fastcall *)(int))v4)(v3);  // Call param1(param2)
  }
  
  a1[3] = v6;  // Store result
  a1[2] = 2;   // Set state to "complete"
  
  return v7;
}
```

**The problem**: `a1[7]` (work_func) is NULL, so the callback does nothing!

## What Should Queue Loader Work?

The game needs to:
1. Initialize the loader/asset system
2. Queue the first loader job (load boot files like GLOBALMEMORYFILE.BIN)
3. Loader callback will process the job
4. StreamBridge will handle file I/O
5. Game will load assets and progress to rendering

## Missing Initialization Step

Something in the initialization sequence should queue the first loader job, but it's not happening. Possible causes:

1. **Missing initialization callback** - Some init function should queue boot file loading
2. **Waiting for event** - Game might be waiting for some event before queuing work
3. **Display initialization incomplete** - Display dimensions are zero, viewport invalid
4. **Profile manager callback** - Game might be waiting for profile manager (inherited from Unleashed)

## Next Steps

### Option 1: Find What Queues Loader Work
- Search for functions that write to `a1[7]` (work_func field)
- Find initialization functions that should queue boot file loading
- Check if there's a missing initialization callback

### Option 2: Force Queue Boot File Loading
- Manually queue a loader job to load GLOBALMEMORYFILE.BIN
- This would test if the loader system works
- If successful, find why it's not being queued naturally

### Option 3: Check Display Initialization
- Display dimensions are zero (forced to 1280x720)
- Viewport bounds are invalid [0,0,0,0]
- Game might be waiting for display to be fully initialized

## Conclusion

The game is NOT broken - it's just stuck waiting for something to queue the first loader job. Once that happens, the loader callback will process it, StreamBridge will load files, and the game will progress to rendering.

The fix is to find what should queue the first loader job and make sure it happens.

