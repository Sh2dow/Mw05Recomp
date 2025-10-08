# Running MW05 Recompiled

## Quick Start

### Option 1: Use the provided script (Recommended)
```powershell
.\run_game.ps1
```

### Option 2: Run directly with environment variables
```powershell
$env:MW05_VBLANK_VDSWAP = "0"
$env:MW05_VDSWAP_NOTIFY = "1"
$env:MW05_FAST_BOOT = "1"
.\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe
```

### Option 3: Run without any overrides (slowest boot)
```powershell
.\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe
```

## Important Environment Variables

### Critical Settings (for gameplay)
- `MW05_VBLANK_VDSWAP=0` - **MUST be 0 for gameplay**. Let the guest code call VdSwap naturally. Setting this to 1 is only for testing the VdSwap infrastructure.
- `MW05_VDSWAP_NOTIFY=1` - Enable graphics notifications after VdSwap so the guest receives vblank signals.

### Boot Optimization
- `MW05_FAST_BOOT=1` - Skip tight delay loops during initialization (recommended)
- `MW05_FAST_RET=0` - Return value for fast boot functions (0 = success)
- `MW05_UNBLOCK_MAIN=1` - Unblock main thread early (enabled by default)
- `MW05_FORCE_VIDEO_THREAD=1` - Force video thread creation at a specific tick (enabled by default)
- `MW05_FORCE_VIDEO_THREAD_TICK=300` - Tick count to create video thread (default: 300)

### Testing/Debugging (DO NOT use for gameplay)
- `MW05_VBLANK_VDSWAP=1` - Call VdSwap from host vblank pump (for testing only)
- `MW05_FORCE_PRESENT=1` - Force continuous presents from main thread (for testing only)
- `MW05_FORCE_PRESENT_WRAPPER_ONCE=1` - One-shot nudge to call present wrapper (for testing only)

## Troubleshooting

### Blank screen with FPS 0.0
**Symptoms**: Window opens but shows black screen, FPS counter shows 0.0

**Possible causes**:
1. **MW05_VBLANK_VDSWAP=1 is set** - This prevents the guest from calling VdSwap naturally
   - **Fix**: Set `MW05_VBLANK_VDSWAP=0` or unset it
   
2. **Guest rendering loop hasn't started** - The guest code is waiting for initialization to complete
   - **Fix**: Enable `MW05_FAST_BOOT=1` to skip initialization delays
   - **Fix**: Ensure `MW05_FORCE_VIDEO_THREAD=1` is set (default)
   
3. **Missing game assets** - The game requires assets in the `./game` directory
   - **Fix**: Ensure game assets are properly installed in `./game`

### Slow boot / Long initialization
**Symptoms**: Game takes a long time to start

**Fix**: Enable fast boot:
```powershell
$env:MW05_FAST_BOOT = "1"
```

### Hangs or freezes
**Symptoms**: Game window opens but becomes unresponsive

**Possible causes**:
1. **Thread safety issue** - VdSwap calling Present() from guest thread
   - **Fix**: This should be fixed in the current code. VdSwap now calls `RequestPresentFromBackground()` instead.
   
2. **Guest waiting on event** - Guest code is blocked waiting for a signal
   - **Check logs**: Look for `KeWaitForSingleObject` or `NtWaitForSingleObjectEx` calls
   - **Fix**: May need to signal the event or implement missing kernel functionality

## Logs

Logs are written to:
- `out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log` - Detailed host trace log
- Console output - Basic initialization messages

To enable verbose logging:
```powershell
$env:MW_VERBOSE = "1"
```

## Expected Behavior

When running correctly, you should see:
1. Window opens with "Most Wanted Recompiled" title
2. FPS counter shows non-zero value (target: ~60 FPS)
3. Game renders frames continuously
4. VdSwap is called by the guest at ~60 Hz

## Current Status

### ✅ Working
- VdSwap thread safety (no more hangs)
- Graphics notification system
- Vblank pump running at ~54.6 Hz
- Video::Present() infrastructure
- Cross-thread present requests

### ⚠️ Known Issues
- Guest rendering loop may not start without `MW05_FAST_BOOT=1`
- Video::Present() is slow (~1 second per frame) - performance optimization needed
- Guest may be waiting on events/signals that aren't being triggered

### 🔧 For Developers

If the game still doesn't render after following the above steps, you may need to:
1. Check what the guest threads are waiting on (look for `KeWaitForSingleObject` calls in logs)
2. Verify GPU initialization completed successfully
3. Check if resources/assets are loading correctly
4. Trace the guest rendering loop to see where it's blocked
5. Implement missing kernel functions that the guest is waiting on

## Testing Infrastructure

For testing the VdSwap/Present infrastructure (not for gameplay):
```powershell
python tools/run_present.py --seconds 10
```

This runs the game for 10 seconds with diagnostic logging and generates a summary report.

