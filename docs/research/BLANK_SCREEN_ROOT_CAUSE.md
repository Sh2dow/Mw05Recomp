# ROOT CAUSE: Game Never Calls VdSwap

**CRITICAL FINDING**: The game is NOT calling VdSwap, which means it's not trying to present frames.

## Evidence

### Xenia (Working)
- VdSwap calls: **759**
- Graphics callback registered: YES (cb=0x825979A8, ctx=0x40007180)
- Graphics callback invoked: YES (thousands of times)
- Game renders and displays frames

### Our Implementation (Blank Screen)
- VdSwap calls: **0** (ZERO!)
- Graphics callback registered: YES (cb=0x825979A8, ctx=0x00061000)
- Graphics callback invoked: **0** (ZERO!)
- Blank screen

## Why Graphics Callback Is Not Being Invoked

The VBlank pump code has a `cb_on` flag that controls whether guest ISR callbacks are invoked. This flag is set to FALSE when certain environment variables are set:

```cpp
static const bool cb_on = [](){
    bool force_present = is_enabled("MW05_FORCE_PRESENT");
    bool force_present_bg = is_enabled("MW05_FORCE_PRESENT_BG");
    bool kick_video = is_enabled("MW05_KICK_VIDEO");
    
    if (force_present || force_present_bg || kick_video) {
        return false; // DISABLED
    }
    return true; // ENABLED
}();
```

**Solution**: Make sure these environment variables are NOT set (or set to "0").

## Why Game Doesn't Call VdSwap

Even if graphics callbacks are invoked, the game still needs to call VdSwap to present frames. The game is stuck somewhere and never reaches the code that calls VdSwap.

### Possible Causes

1. **Missing Threads**: Xenia creates 9 threads, we only create 3 (missing 6 threads)
   - One of the missing threads might be responsible for calling VdSwap

2. **Graphics Callback Context Wrong**: 
   - Xenia uses context `0x40007180`
   - We use context `0x00061000`
   - The function pointer at `ctx[3899]` (offset 0x3CEC) might be NULL or invalid

3. **Waiting for Event**: Game might be waiting for a synchronization event that never fires

4. **Missing Initialization**: Some initialization step is incomplete

## Next Steps

1. **Enable graphics callbacks** - Set environment variables to allow VBlank pump to invoke guest ISR
2. **Check callback context** - Verify that `ctx[3899]` contains a valid function pointer
3. **Investigate missing threads** - Find out which threads Xenia creates that we don't
4. **Add logging to graphics callback** - See if it's being called and what it does

