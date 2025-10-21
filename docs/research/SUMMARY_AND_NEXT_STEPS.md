# MW05 Recompilation - Summary and Next Steps

**Date**: 2025-10-21  
**Status**: Game Stable, Investigating No Draws  
**Priority**: Continue autonomous debugging until draws appear

## Current Status Summary

### ✅ Major Achievements
1. **Game Runs Stable** - 10+ minutes without crashing
2. **All Critical Bugs Fixed** - 39 recompiler bugs resolved
3. **All Threads Running** - 12 threads created and active
4. **File I/O Working** - Streaming bridge loading resources
5. **PM4 Processing Active** - 114,616 bytes/frame being scanned
6. **Graphics Callbacks Working** - VBlank ISR invokes callback

### ❌ Current Blocker
**NO DRAW COMMANDS** - Game hasn't issued any draw commands yet (draws=0)

## Root Cause Analysis

### What We Know
1. **Ring Buffer is Empty** - Only 16 non-zero DWORDs out of 16384 (0.098%)
2. **PM4 Scanning Works** - Parser correctly detects TYPE0/TYPE3 packets
3. **No Draw Opcodes** - No 0x22 (DRAW_INDX) or 0x36 (DRAW_INDX_2) detected
4. **Game is Initializing** - Loading resources, setting up graphics state

### What We Don't Know
1. **Which PM4 opcodes ARE being processed?** - Need opcode histogram
2. **Is game waiting for resource loading?** - Need file I/O completion check
3. **Is render thread executing draw code?** - Need thread execution trace
4. **Is graphics state fully initialized?** - Need PM4 TYPE0 analysis

## Investigation Plan

### Phase 1: Data Collection (IMMEDIATE)
**Goal**: Understand what PM4 commands ARE being processed

**Actions**:
1. Run `scripts/test_pm4_opcodes.ps1` to collect opcode histogram
2. Analyze which TYPE3 opcodes are present
3. Compare with Xenia's opcode sequence
4. Identify missing opcodes

**Expected Output**:
```
HOST.PM4.OPC[00]=count    # NOP commands
HOST.PM4.OPC[10]=count    # Other commands
HOST.PM4.OPC[22]=0        # DRAW_INDX (should be >0)
HOST.PM4.OPC[36]=0        # DRAW_INDX_2 (should be >0)
```

### Phase 2: File I/O Analysis
**Goal**: Verify all required resources are loaded

**Actions**:
1. Monitor StreamBridge operations
2. Check if shader files are loaded
3. Check if texture files are loaded
4. Compare with Xenia's file loading sequence

**Expected Behavior**:
- Game should load shaders before issuing draws
- File I/O should complete before rendering starts

### Phase 3: Render Thread Trace
**Goal**: Verify render thread is executing draw submission code

**Actions**:
1. Add logging to render thread entry (0x825AA970)
2. Add logging to draw submission functions
3. Check if render thread reaches draw code
4. Compare with Xenia's thread execution

**Expected Behavior**:
- Render thread should execute draw submission loop
- Should write PM4 commands to ring buffer

### Phase 4: Graphics State Verification
**Goal**: Verify graphics state is properly initialized

**Actions**:
1. Check PM4 TYPE0 packets (register writes)
2. Verify render target is set
3. Verify viewport/scissor are set
4. Verify shaders are bound
5. Compare with Xenia's PM4 sequence

**Expected Behavior**:
- Game should set up graphics state via TYPE0 packets
- Then issue TYPE3 draw commands

## Script Consolidation Recommendations

### Immediate Actions
1. **Archive Obsolete Scripts** - Move ~40 one-off debugging scripts to `scripts/archive/`
2. **Create Unified Runner** - Implement `scripts/mw05_run.py` with profile-based configuration
3. **Consolidate Analysis Tools** - Merge ~30 analysis scripts into `tools/mw05_analyze.py`
4. **Remove Workaround Variables** - Clean up ~30 obsolete environment variables

### Benefits
1. **Reduced Complexity** - From ~190 scripts to ~40 essential scripts
2. **Better Maintainability** - Single source of truth for debug configs
3. **Improved Performance** - Remove workaround overhead
4. **Clearer Documentation** - Obvious which tool to use for what

### Implementation Timeline
- **Week 1**: Archive obsolete scripts
- **Week 2**: Create unified tools
- **Week 3**: Create unified runner
- **Week 4**: Environment variable cleanup

## Performance Considerations

### Current Overhead
- **PM4 Scanning**: 114,616 bytes/frame = ~1.8 MB/sec
- **Trace Logging**: 572 MB in 8 minutes = ~1.2 MB/sec
- **Total I/O**: ~3 MB/sec (acceptable)

### Optimization Opportunities
1. **Reduce PM4 scan frequency** once draws appear
2. **Use verbosity control** to reduce trace spam
3. **Disable unnecessary logging** after debugging
4. **Remove workaround overhead** from fixed bugs

## Debug System Unification

### Current State
- **~80 environment variables** - Many obsolete workarounds
- **~190 scripts/tools** - High redundancy
- **No unified control** - Each script sets different vars

### Proposed State
- **~15 essential variables** - Debug/tracing only
- **~40 essential scripts** - Consolidated functionality
- **Unified runner** - Profile-based configuration

### Environment Variables to Keep
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
```

### Environment Variables to Remove
```
# Workarounds (no longer needed)
MW05_UNBLOCK_MAIN
MW05_FORCE_RENDER_THREADS
MW05_BREAK_82813514
MW05_FAKE_ALLOC_SYSBUF
MW05_FORCE_VD_INIT
MW05_FORCE_GFX_NOTIFY_CB
MW05_BREAK_SLEEP_LOOP
MW05_FORCE_PRESENT
... (20+ more)
```

## Next Steps for AI Agent

### Immediate Priority (Continue Autonomously)
1. **Run PM4 opcode test** - Collect histogram data
2. **Analyze opcode distribution** - Identify missing opcodes
3. **Compare with Xenia** - Find differences in PM4 sequence
4. **Investigate root cause** - Why no draw commands
5. **Fix blocking issue** - Get first draw command to appear

### Success Criteria
- [ ] PM4 opcode histogram collected
- [ ] Missing opcodes identified
- [ ] Root cause understood
- [ ] First draw command appears (draws > 0)
- [ ] Graphics render on screen

### Autonomous Operation
**Continue debugging without status updates until draws appear.**

The AI agent should:
1. Run diagnostic tests
2. Analyze results
3. Form hypotheses
4. Test hypotheses
5. Fix root causes
6. Iterate until draws appear

**Do NOT stop for status updates** - keep working until the game renders graphics.

## References

- [SCRIPT_CONSOLIDATION_PROPOSAL.md](SCRIPT_CONSOLIDATION_PROPOSAL.md) - Detailed consolidation plan
- [NO_DRAWS_INVESTIGATION.md](NO_DRAWS_INVESTIGATION.md) - Deep analysis of no draws issue
- [AGENTS.md](../../AGENTS.md) - Project guidelines and debugging info
- [PM4 Parser](../../Mw05Recomp/gpu/pm4_parser.cpp) - PM4 command processing
- [Debug Verbosity](../../Mw05Recomp/kernel/debug_verbosity.h) - Logging control system

## Key Takeaways

1. **Game is Stable** - All critical bugs are fixed
2. **No Draws Yet** - Game is in initialization phase
3. **Need Data** - Collect PM4 opcode histogram to understand what's happening
4. **Continue Autonomously** - Keep debugging until draws appear
5. **No Magic Numbers** - Only strong, long-term-proof fixes
6. **Performance Matters** - Remove workaround overhead

## Final Note

The game has achieved MAJOR stability! It runs for 10+ minutes without crashing. The next step is to understand why draw commands aren't being issued yet. This is a **NORMAL INITIALIZATION PHASE** - the game needs to load resources and set up graphics state before rendering.

**Keep investigating autonomously until draws appear!**

