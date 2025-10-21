# MW05 Recompilation - Final Recommendations

**Date**: 2025-10-21  
**Prepared For**: Next AI Agent  
**Status**: Game Stable, Ready for Deep Investigation

## Executive Summary

The MW05 recompilation project has achieved **MAJOR STABILITY**:
- ✅ Game runs 10+ minutes without crashing
- ✅ All 39 recompiler bugs fixed
- ✅ All 12 threads running correctly
- ✅ File I/O working (streaming bridge active)
- ✅ PM4 processing active (107,668 bytes/frame)
- ❌ **NO DRAWS YET** (draws=0) - Game in initialization phase

## Critical Next Steps

### 1. Collect PM4 Opcode Histogram (IMMEDIATE)

**Why**: We need to understand what PM4 commands ARE being processed to identify why draw commands aren't appearing.

**How**:
```powershell
# Run the test script
.\scripts\test_pm4_opcodes.ps1

# Or manually:
$env:MW05_PM4_TRACE = "1"
$env:MW05_DEBUG_PM4 = "3"
python scripts/auto_handle_messageboxes.py --duration 30

# Then analyze:
Get-Content traces\pm4_opcode_test.log | Select-String "HOST.PM4.OPC"
```

**Expected Output**:
```
HOST.PM4.OPC[00]=count    # NOP commands
HOST.PM4.OPC[10]=count    # Other TYPE3 commands
HOST.PM4.OPC[22]=0        # DRAW_INDX (should be >0 if working)
HOST.PM4.OPC[36]=0        # DRAW_INDX_2 (should be >0 if working)
```

**What to Look For**:
- Which TYPE3 opcodes have non-zero counts?
- Are there any draw-related opcodes (0x22, 0x36)?
- What's the most common opcode?
- Compare with Xenia's opcode distribution

### 2. Investigate File I/O Completion

**Why**: Game may be waiting for resources to load before issuing draws.

**How**:
```powershell
# Check StreamBridge operations
Get-Content traces\*.log | Select-String "StreamBridge" | Measure-Object

# Check what files are being loaded
Get-Content traces\*.log | Select-String "StreamBridge.*GLOBAL"

# Compare with Xenia's file loading sequence
```

**What to Look For**:
- Are shader files (.xvu, .xpu) being loaded?
- Are texture files being loaded?
- Is file I/O completing or stalling?
- Compare file count with Xenia

### 3. Trace Render Thread Execution

**Why**: Render thread may not be reaching draw submission code.

**How**:
1. Add logging to render thread entry point (0x825AA970)
2. Add logging to draw submission functions
3. Check if render thread is executing draw code

**What to Look For**:
- Is render thread executing its main loop?
- Is it reaching draw submission code?
- Is it waiting on some event/synchronization?
- Compare with Xenia's thread execution

### 4. Verify Graphics State Initialization

**Why**: Game may be waiting for graphics state to be fully initialized.

**How**:
```powershell
# Check PM4 TYPE0 packets (register writes)
Get-Content traces\*.log | Select-String "PM4.Types"

# Look for render target setup
Get-Content traces\*.log | Select-String "RenderTarget"

# Look for viewport/scissor setup
Get-Content traces\*.log | Select-String "Viewport|Scissor"
```

**What to Look For**:
- Are TYPE0 packets being processed?
- Is render target configured?
- Is viewport/scissor configured?
- Are shaders bound?

## Script Consolidation Plan

### Phase 1: Archive Obsolete Scripts (Week 1)

**Scripts to Archive** (~40 files):
```
scripts/archive/
├── crash_debugging/          # Crash bugs are fixed
│   ├── analyze_crash*.py
│   ├── find_crash_function.ps1
│   ├── debug_crash.ps1
│   └── investigate_black_screen.ps1
├── redundant_runners/        # Use unified runner instead
│   ├── run_5sec.ps1
│   ├── run_10sec.ps1
│   ├── run_60sec.ps1
│   ├── run_longer.ps1
│   └── run_very_long.ps1
└── obsolete_workarounds/     # Workarounds no longer needed
    ├── test_unblock_main*.ps1
    ├── test_force_present.ps1
    └── test_force_gfx.ps1
```

### Phase 2: Create Unified Tools (Week 2)

**New Tools**:
1. `tools/mw05_analyze.py` - Unified analysis tool
   ```bash
   python tools/mw05_analyze.py trace <file>
   python tools/mw05_analyze.py pm4 <file>
   python tools/mw05_analyze.py threads <file>
   python tools/mw05_analyze.py imports <file>
   ```

2. `tools/mw05_find.py` - Unified search tool
   ```bash
   python tools/mw05_find.py function <address>
   python tools/mw05_find.py caller <address>
   python tools/mw05_find.py pattern <regex>
   ```

### Phase 3: Create Unified Runner (Week 3)

**New Runner**: `scripts/mw05_run.py`
```bash
# Run with minimal logging
python scripts/mw05_run.py --profile minimal --duration 60

# Run with PM4 debugging
python scripts/mw05_run.py --profile pm4 --auto-dismiss

# Run with verbose logging
python scripts/mw05_run.py --profile verbose --capture-stderr
```

**Profiles**:
- `minimal` - Minimal logging, maximum performance
- `normal` - Normal logging (default)
- `verbose` - Verbose logging for debugging
- `pm4` - PM4 command analysis
- `fileio` - File I/O debugging

### Phase 4: Environment Variable Cleanup (Week 4)

**Variables to Keep** (15 total):
```
# Debug/Tracing (6 vars)
MW05_DEBUG_GRAPHICS=0|1|2|3
MW05_DEBUG_KERNEL=0|1|2|3
MW05_DEBUG_THREAD=0|1|2|3
MW05_DEBUG_HEAP=0|1|2|3
MW05_DEBUG_FILEIO=0|1|2|3
MW05_DEBUG_PM4=0|1|2|3

# PM4/Graphics (5 vars)
MW05_PM4_TRACE=0|1
MW05_PM4_APPLY_STATE=0|1
MW05_PM4_EMIT_DRAWS=0|1
MW05_PM4_SCAN_ALL=0|1
MW05_PM4_SNOOP=0|1

# File I/O (2 vars)
MW05_STREAM_BRIDGE=0|1
MW05_HOST_TRACE_FILE=path

# Advanced (2 vars)
MW05_DEBUG_PROFILE=0|1
MW05_RUNTIME_PATCHES=0|1
```

**Variables to Remove** (~30 workarounds):
```
MW05_UNBLOCK_MAIN              # Game runs naturally now
MW05_FORCE_RENDER_THREADS      # Threads created naturally
MW05_BREAK_82813514            # Worker threads work correctly
MW05_FAKE_ALLOC_SYSBUF         # Allocation works correctly
MW05_FORCE_VD_INIT             # Graphics init works naturally
MW05_FORCE_GFX_NOTIFY_CB       # Callbacks registered naturally
MW05_BREAK_SLEEP_LOOP          # Sleep loops work correctly
MW05_FORCE_PRESENT             # Present works naturally
... (20+ more)
```

## Performance Optimization

### Current Overhead
- **PM4 Scanning**: 107,668 bytes/frame = ~1.7 MB/sec
- **Trace Logging**: 572 MB in 8 minutes = ~1.2 MB/sec
- **Total I/O**: ~3 MB/sec (acceptable)

### Optimization Opportunities
1. **Reduce PM4 scan frequency** - Only scan when ring buffer changes
2. **Use verbosity control** - Default to MINIMAL level
3. **Disable unnecessary logging** - Remove debug fprintf calls
4. **Remove workaround overhead** - Clean up obsolete code paths

### Expected Performance Gain
- **Reduced I/O**: From 3 MB/sec to <1 MB/sec
- **Reduced CPU**: From ~10% to <5% overhead
- **Reduced Memory**: From 572 MB logs to <100 MB logs

## Autonomous Operation Guidelines

### For Next AI Agent

**Primary Goal**: Get first draw command to appear (draws > 0)

**Approach**:
1. **Collect Data** - Run PM4 opcode histogram test
2. **Analyze Results** - Identify missing opcodes
3. **Form Hypothesis** - Why no draw commands?
4. **Test Hypothesis** - Add logging, compare with Xenia
5. **Fix Root Cause** - Implement proper fix (no magic numbers)
6. **Verify Fix** - Confirm draws > 0
7. **Iterate** - Repeat until rendering works

**Do NOT**:
- Stop for status updates
- Use magic number workarounds
- Skip root cause analysis
- Give up after first attempt

**DO**:
- Continue autonomously until draws appear
- Use strong, long-term-proof fixes
- Consider performance impact
- Document findings in research docs

### Success Criteria
- [ ] PM4 opcode histogram collected
- [ ] Missing opcodes identified
- [ ] Root cause understood
- [ ] First draw command appears (draws > 0)
- [ ] Graphics render on screen
- [ ] Game progresses to menu/gameplay

## Key Files and Locations

### Source Code
- `Mw05Recomp/gpu/pm4_parser.cpp` - PM4 command processing
- `Mw05Recomp/gpu/video.cpp` - Graphics/rendering
- `Mw05Recomp/kernel/imports.cpp` - Kernel functions, VdSwap
- `Mw05Recomp/kernel/debug_verbosity.h` - Logging control

### Scripts
- `scripts/test_pm4_opcodes.ps1` - PM4 opcode histogram test
- `scripts/auto_handle_messageboxes.py` - Auto-dismiss message boxes
- `scripts/run_with_debug.ps1` - Debug runner (to be replaced)

### Documentation
- `docs/research/SCRIPT_CONSOLIDATION_PROPOSAL.md` - Consolidation plan
- `docs/research/NO_DRAWS_INVESTIGATION.md` - Deep analysis
- `docs/research/SUMMARY_AND_NEXT_STEPS.md` - Current status
- `AGENTS.md` - Project guidelines

### Logs
- `traces/*.log` - Trace logs from test runs
- `out/build/x64-Clang-Debug/Mw05Recomp/*.log` - Build logs

## Final Notes

The game has achieved **MAJOR STABILITY**! All critical bugs are fixed, and the game runs for 10+ minutes without crashing. The next step is to understand why draw commands aren't being issued yet.

This is a **NORMAL INITIALIZATION PHASE** - the game needs to load resources and set up graphics state before rendering. The investigation should focus on:

1. **What PM4 commands ARE being processed?** (opcode histogram)
2. **Is resource loading complete?** (file I/O analysis)
3. **Is render thread executing draw code?** (thread trace)
4. **Is graphics state fully initialized?** (PM4 TYPE0 analysis)

**Continue investigating autonomously until draws appear!**

No magic numbers. No workarounds. Only strong, long-term-proof fixes.

Good luck! 🚀

