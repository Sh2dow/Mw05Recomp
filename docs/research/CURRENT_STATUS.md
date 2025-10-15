# MW05 Recompilation - Current Status

**Date**: 2025-10-15  
**Last Updated**: After Entry Point Fix

## ✅ Major Achievements

### 1. Entry Point Fix (COMPLETE)
- **Problem**: XEX entry point `0x8262E9A8` was missing from TOML configuration
- **Solution**: Added entry point to `Mw05RecompLib/config/MW05.toml`
- **Result**: Game now runs naturally without workarounds!

### 2. Game Initialization (WORKING)
- ✅ Entry point `0x8262E9A8` executes
- ✅ Main initialization `sub_82441E80` called
- ✅ Thread #1 (0x828508A8) created
- ✅ All 4 render threads created:
  - 0x826E7B90
  - 0x826E7BC0
  - 0x826E7BF0
  - 0x826E7C20

### 3. Graphics System (WORKING)
- ✅ VdInitializeEngines called
- ✅ Graphics callback registered (0x825979A8)
- ✅ VBlank pump running
- ✅ VdSwap being called repeatedly
- ✅ PM4 command buffers being scanned (185,000+ packets)

### 4. Recompiler Fixes (COMPLETE)
- ✅ 38 PowerPC instruction bugs fixed (`.u64`/`.s64` → `.u32`)
- ✅ LIS instruction formatting bug fixed
- ✅ Function table bug fixed (`PPC_LOOKUP_FUNC`)
- ✅ All 40 recompiler bugs resolved

## ❌ Current Issues

### 1. No Draw Commands (PRIMARY ISSUE)
**Status**: Under investigation

**Symptoms**:
- PM4 packets are being processed (185,000+)
- VdSwap is being called
- But `draws=0` in all scans

**Possible Causes**:
1. Missing file I/O - game can't load assets
2. Graphics state not fully initialized
3. Game waiting for some event
4. Missing shader/texture resources

### 2. Heap Corruption with Debug Tracing (NEW)
**Status**: Blocking investigation

**Error**:
```
Assertion failed: ((size_t)frag) <= (((size_t)handle) + ...), 
file D:/Repos/Games/Mw05Recomp/thirdparty/o1heap/o1heap.c, line 396
```

**Trigger**: Enabling debug profile (`MW05_DEBUG_PROFILE=1` or `--mwdebug`)

**Impact**: Cannot enable detailed tracing to investigate draw commands issue

**Possible Causes**:
- Buffer overflow in trace logging
- Heap corruption from increased memory allocation
- Use-after-free in trace buffer
- Double-free in logging code

## 📁 File Organization

### Cleaned Up
- ✅ Moved all `.md` research docs to `docs/research/`
- ✅ Moved all scripts to `scripts/`
- ✅ IDA dumps in `IDA_dumps/`
- ✅ App logs/traces in `Traces/`

### Key Files
- `Mw05RecompLib/config/MW05.toml` - Function configuration
- `Mw05Recomp/main.cpp` - Entry point and debug profile
- `Mw05Recomp/kernel/trace.cpp` - Tracing system
- `Mw05Recomp/gpu/video.cpp` - Graphics/PM4 handling
- `scripts/run_and_analyze.ps1` - Run game and analyze results
- `tools/analyze_no_draws.py` - Analyze why draws=0

## 🔧 Environment Variables

### Tracing (Currently Broken - Heap Corruption)
- `MW05_DEBUG_PROFILE=1` - Enable all debug tracing (CAUSES CRASH)
- `MW05_HOST_TRACE_FILE=path` - Trace log path (default: mw05_host_trace.log)
- `MW05_HOST_TRACE_IMPORTS=1` - Trace import calls
- `MW05_HOST_TRACE_HOSTOPS=1` - Trace host operations
- `MW05_TRACE_KERNEL=1` - Trace kernel calls
- `MW05_PM4_TRACE=1` - Trace PM4 commands
- `MW05_FILE_LOG=1` - Trace file I/O

### Workarounds (No Longer Needed)
- ~~`MW05_UNBLOCK_MAIN=1`~~ - Not needed after entry point fix
- ~~`MW05_FORCE_RENDER_THREADS=1`~~ - Not needed after entry point fix

## 📊 Current Metrics (Without Debug Tracing)

From last successful run:
- **VdSwap calls**: ~100+ per run
- **PM4 packets**: 185,380 processed
- **Draw commands**: 0 (ISSUE)
- **Graphics callbacks**: 785+ invocations
- **Threads active**: All threads running
- **Crashes**: None (when debug tracing disabled)

## 🎯 Next Steps

### Immediate Priority
1. **Fix heap corruption issue** to enable debug tracing
   - Investigate o1heap assertion failure
   - Check trace buffer allocation
   - Look for buffer overflows in logging code
   - May need to increase heap size or fix memory leak

### After Heap Fix
2. **Enable debug tracing** to investigate draws=0
   - Analyze PM4 command types
   - Check graphics state initialization
   - Monitor file I/O for resource loading
   - Compare with Xenia execution

3. **Investigate why no draws**
   - Check if shaders are loaded
   - Check if textures are loaded
   - Check if vertex/index buffers are set
   - Check if render targets are configured

## 📝 Technical Notes

### Entry Point Call Chain
```
0x8262E9A8 (XEX entry point)
  → sub_82630068() - Early init
  → sub_8262FDA8(1)
  → sub_826BE558()
  → sub_8262FD30()
  → sub_8262FC50(1)
  → sub_8262E7F8() - Command line parsing
  → sub_82441E80(argc, argv, 0) - MAIN INITIALIZATION
    → Creates Thread #1 (0x828508A8)
    → Populates work queue (0x829091C8)
    → Thread #1 creates 4 render threads
```

### PM4 Command Buffer Flow
```
Game writes PM4 commands → Ring buffer (0x00040300)
  → VdSwap called
  → PM4_ScanLinear scans buffer
  → Should find draw commands (but doesn't)
  → Present frame
```

### Heap Corruption Details
- **Location**: `thirdparty/o1heap/o1heap.c:396`
- **Assertion**: Fragment pointer out of bounds
- **Trigger**: Debug tracing enabled
- **Frequency**: After ~627 graphics callbacks
- **Impact**: Blocks all debug investigation

## 🔍 Investigation Tools

### Scripts
- `scripts/run_and_analyze.ps1` - Run game and show summary
- `tools/analyze_no_draws.py` - Analyze why draws=0
- `tools/analyze_mw05_init.py` - Analyze initialization sequence

### IDA Pro HTTP Server
- Running on `http://127.0.0.1:5050`
- Endpoints: `/decompile`, `/disasm`, `/bytes`
- All dumps saved to `IDA_dumps/`

### Xenia Emulator
- Located at `f:\XBox\xenia-canary\`
- Can run with: `.\xenia_canary.exe --trace_gpu_stream=true F:\XBox\ISO\MWEurope\default.xex`
- Use for comparison with working execution

## 🏆 Success Criteria

### Completed ✅
- [x] Fix recompiler bugs
- [x] Add XEX entry point to TOML
- [x] Game runs naturally without workarounds
- [x] All threads created
- [x] Graphics system initialized
- [x] VdSwap being called
- [x] PM4 buffers being scanned

### In Progress 🔄
- [ ] Fix heap corruption to enable tracing
- [ ] Investigate why draws=0
- [ ] Get first draw command to appear

### Future Goals 🎯
- [ ] Display graphics on screen
- [ ] Load game assets
- [ ] Render game UI
- [ ] Full gameplay working

## 📚 References

- [ENTRY_POINT_FIX_SUCCESS.md](ENTRY_POINT_FIX_SUCCESS.md) - Entry point fix details
- [RENDER_THREAD_ROOT_CAUSE.md](RENDER_THREAD_ROOT_CAUSE.md) - Thread investigation
- [MW05.toml](../../Mw05RecompLib/config/MW05.toml) - Function configuration
- [trace.cpp](../../Mw05Recomp/kernel/trace.cpp) - Tracing implementation

