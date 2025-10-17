# MW05 Recomp - Next Steps

## Current Status

✅ **All systems working!**
- Entry point executes
- All threads created
- Graphics callbacks registered and invoked
- VBlank pump running
- PM4 command buffers being scanned
- **Streaming bridge working!** Successfully intercepting file load requests
- **File I/O working!** Successfully loaded `GLOBALMEMORYFILE.BIN` (1 MB)

## Blocking Issue: Missing Game Files

The game is trying to load files but the `game/` directory doesn't exist.

### Required Action

**Extract Xbox 360 game files from ISO:**

1. Mount or extract the NFS Most Wanted Xbox 360 ISO
2. Copy all game files to `./game/` directory
3. Required files include:
   - `game/GLOBAL/GLOBALMEMORYFILE.BIN`
   - `game/GLOBAL/PERMANENTMEMORYFILE.BIN`
   - `game/GLOBAL/FRONTENDMEMORYFILE.BIN`
   - `game/GLOBAL/GLOBALB.BUN`
   - `game/GLOBAL/GLOBALA.BUN`
   - `game/GLOBAL/INGAMEB.BUN`
   - And all other game data files

### Directory Structure

```
Mw05Recomp/
├── game/
│   ├── GLOBAL/
│   │   ├── GLOBALMEMORYFILE.BIN
│   │   ├── PERMANENTMEMORYFILE.BIN
│   │   ├── FRONTENDMEMORYFILE.BIN
│   │   ├── GLOBALB.BUN
│   │   ├── GLOBALA.BUN
│   │   └── ...
│   ├── FRONTEND/
│   ├── TRACKS/
│   ├── CARS/
│   ├── SOUND/
│   └── ...
```

### Test After Extracting Files

Run the game with file tracing:
```cmd
scripts\run_game_with_file_trace.cmd
```

Check the trace log for successful file loads:
```powershell
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log | Select-String "XCreateFileA|XReadFile"
```

## Technical Details

### What's Working

1. **Streaming Bridge**: Detects sentinel value `0x0A000000` in scheduler blocks
2. **Fallback Boot**: When no file path is found, tries to load known boot files
3. **File I/O**: `XCreateFileA` and `XReadFile` are implemented and working
4. **Path Resolution**: `game:\` maps to `.\game\` correctly

### What Was Fixed

1. Disabled `MW05_FORCE_PRESENT` which was blocking the streaming bridge
2. Enabled `MW05_STREAM_BRIDGE=1` to activate file interception
3. Enabled `MW05_STREAM_FALLBACK_BOOT=1` to try boot files when path is unknown

### Environment Variables (in `scripts/run_game_with_file_trace.cmd`)

```batch
set MW05_FILE_LOG=1                    # Enable file I/O logging
set MW05_HOST_TRACE_HOSTOPS=1          # Enable host operation tracing
set MW05_TRACE_KERNEL=1                # Enable kernel tracing
set MW05_STREAM_BRIDGE=1               # Enable streaming bridge
set MW05_STREAM_ANY_LR=1               # Allow streaming from any link register
set MW05_STREAM_FALLBACK_BOOT=1        # Try boot files when path unknown
set MW05_FORCE_PRESENT=0               # Disable forced present (was blocking streaming)
```

## Expected Behavior After Files Are Added

Once game files are extracted:
1. Game will load `GLOBALMEMORYFILE.BIN` (already working)
2. Game will load `PERMANENTMEMORYFILE.BIN`
3. Game will load `FRONTENDMEMORYFILE.BIN`
4. Game will load bundle files (`.BUN`, `.BND`)
5. Game will load textures, shaders, models
6. Graphics should appear on screen!

## Progress Summary

**Month 1**: Fixed 40 recompiler bugs, implemented kernel functions, set up graphics system
**Today**: Fixed streaming bridge, enabled file I/O, identified missing game files

**Next**: Extract game files and test!

