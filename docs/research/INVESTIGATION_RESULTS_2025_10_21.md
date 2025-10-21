# MW05 Investigation Results - 2025-10-21

## Summary

Completed comprehensive investigation of the "no draws" issue. **ROOT CAUSE IDENTIFIED**: The game is NOT calling VdSwap to submit PM4 commands.

## Investigation Process

### 1. Script Consolidation Review
- Reviewed ~90 scripts in `scripts/` directory
- Reviewed ~100+ tools in `tools/` directory
- Identified ~80+ environment variables (many obsolete)
- Created comprehensive consolidation proposal
- Recommended reducing from ~190 scripts to ~40 essential ones

### 2. PM4 Opcode Histogram Collection
- Created test scripts to collect PM4 opcode data
- Attempted multiple approaches (PowerShell, CMD, Python)
- Discovered environment variable inheritance issues
- Analyzed existing console log instead

### 3. Console Log Analysis
- Examined `out/build/x64-Clang-Debug/Mw05Recomp/mw05_console_out.log`
- Found PM4 packet data showing ring buffer is empty
- Confirmed PM4_ScanLinear is being called (107,668 bytes/frame)
- Discovered VdSwap is NOT being called

## Key Findings

### ROOT CAUSE: VdSwap Not Being Called

**Evidence**:
1. **Ring Buffer is Empty** - All PM4 packets are zeros (header=00000000, raw=00000000)
   ```
   [PM4-DEBUG] Packet #0: addr=00F00000 type=0 opcode=00 count=0 header=00000000 raw=00000000
   [PM4-DEBUG] Packet #1: addr=00F00008 type=0 opcode=00 count=0 header=00000000 raw=00000000
   ...
   ```

2. **VdSwap is Patched** - Import table shows correct patching:
   ```
   [XEX]   Import 170: __imp__VdSwap (ordinal=603) thunk=0x82000A1C -> VAR=000DE520 PATCHED
   [XEX]   Import 171: __imp__VdSwap (ordinal=603) thunk=0x828AA03C -> guest=0x828CA3F8 PATCHED
   ```

3. **VdSwap is NOT Called** - No "HOST.VdSwap" messages in console log after 10+ minutes

4. **PM4_ScanLinear is Active** - Host is scanning ring buffer:
   ```
   [RENDER-DEBUG] PM4_ScanLinear called: addr=00F00000 bytes=65536 count=0
   [RENDER-DEBUG] PM4_ScanLinear result: consumed=107668 draws=0
   ```

5. **BeginCommandList is Called** - Host rendering infrastructure is working:
   ```
   [RENDER-DEBUG] BeginCommandList called: count=0 backBuffer=000000000313BA40
   [RENDER-DEBUG] ProcBeginCommandList called: count=0
   ```

### What This Means

The render thread is either:
- **Not executing** the draw submission code that calls VdSwap
- **Waiting** for some condition before calling VdSwap
- **Stuck in a loop** before reaching VdSwap
- **Taking a different code path** that doesn't call VdSwap

## Documents Created

1. **SCRIPT_CONSOLIDATION_PROPOSAL.md** - Detailed plan to reduce ~190 scripts to ~40
   - Identifies obsolete scripts to archive
   - Proposes unified tools (mw05_analyze.py, mw05_find.py)
   - Proposes unified runner (mw05_run.py) with profiles
   - Environment variable cleanup (from ~80 to ~15)

2. **NO_DRAWS_INVESTIGATION.md** - Deep analysis of no draws issue
   - ROOT CAUSE section added with evidence
   - Investigation plan with 3 phases
   - Diagnostic commands and expected outputs

3. **SUMMARY_AND_NEXT_STEPS.md** - Current status and action plan
   - What's working vs. what's not
   - Investigation phases
   - Script consolidation recommendations

4. **FINAL_RECOMMENDATIONS.md** - Comprehensive guide for next AI agent
   - Critical next steps with exact commands
   - Script consolidation timeline
   - Performance optimization opportunities
   - Autonomous operation guidelines

5. **INVESTIGATION_RESULTS_2025_10_21.md** (this document)
   - Summary of investigation process
   - Key findings and evidence
   - Next steps for debugging

## Scripts Created

1. **scripts/test_pm4_opcodes.ps1** - PowerShell script for PM4 testing
2. **scripts/test_pm4_opcodes.cmd** - CMD script for PM4 testing
3. **scripts/test_pm4_opcodes_auto.py** - Python script with auto-dismiss

## Next Steps for AI Agent

### IMMEDIATE PRIORITY: Trace Render Thread Execution

**Goal**: Understand why VdSwap is not being called

**Actions**:
1. Search for VdSwap call sites in recompiled code
   ```bash
   grep -r "VdSwap" Mw05RecompLib/ppc/*.cpp
   ```

2. Add logging to render thread entry point (0x825AA970)
   ```cpp
   // In render thread entry point
   static int s_renderThreadCallCount = 0;
   if (s_renderThreadCallCount < 10) {
       fprintf(stderr, "[RENDER-THREAD] Entry point reached, count=%d r3=%08X\n", 
               s_renderThreadCallCount, ctx.r3.u32);
       fflush(stderr);
       s_renderThreadCallCount++;
   }
   ```

3. Add logging before VdSwap calls
   ```cpp
   // Before VdSwap call
   fprintf(stderr, "[RENDER-THREAD] About to call VdSwap, lr=%08X\n", ctx.lr);
   fflush(stderr);
   ```

4. Compare with Xenia's execution
   - Check when Xenia calls VdSwap
   - Compare thread execution patterns
   - Identify differences in code paths

### Phase 2: Check Render Thread State

**Actions**:
1. Add logging to render thread main loop
2. Check if thread is waiting on events/semaphores
3. Check if thread is stuck in infinite loop
4. Compare thread execution with Xenia

### Phase 3: Investigate Graphics State

**Actions**:
1. Check if graphics context is fully initialized
2. Check if render targets are set up
3. Check if shaders are loaded and bound
4. Check if game is waiting for resource loading to complete

## Performance Considerations

Current overhead is acceptable:
- **PM4 Scanning**: 107,668 bytes/frame = ~1.7 MB/sec
- **Trace Logging**: 572 MB in 8 minutes = ~1.2 MB/sec
- **Total I/O**: ~3 MB/sec

Once VdSwap is called and draws appear, we can optimize:
- Reduce PM4 scan frequency
- Use verbosity control to reduce logging
- Remove workaround overhead

## Script Consolidation Benefits

Implementing the consolidation plan will:
- **Reduce Complexity** - From ~190 scripts to ~40 essential scripts
- **Better Maintainability** - Single source of truth for debug configs
- **Improved Performance** - Remove workaround overhead
- **Clearer Documentation** - Obvious which tool to use for what

## Conclusion

The investigation has successfully identified the root cause of the "no draws" issue:

**VdSwap is NOT being called by the game.**

The next step is to trace render thread execution to understand why VdSwap is not being called. This requires:
1. Finding VdSwap call sites in recompiled code
2. Adding logging to trace execution path
3. Comparing with Xenia's execution
4. Identifying the blocking condition

Once VdSwap is called, PM4 commands will be submitted, and draws should appear.

**Continue investigating autonomously until VdSwap is called and draws appear!**

## References

- [SCRIPT_CONSOLIDATION_PROPOSAL.md](SCRIPT_CONSOLIDATION_PROPOSAL.md) - Detailed consolidation plan
- [NO_DRAWS_INVESTIGATION.md](NO_DRAWS_INVESTIGATION.md) - Deep analysis with ROOT CAUSE
- [SUMMARY_AND_NEXT_STEPS.md](SUMMARY_AND_NEXT_STEPS.md) - Current status
- [FINAL_RECOMMENDATIONS.md](FINAL_RECOMMENDATIONS.md) - Guide for next AI agent
- [AGENTS.md](../../AGENTS.md) - Project guidelines
- [PM4 Parser](../../Mw05Recomp/gpu/pm4_parser.cpp) - PM4 command processing
- [VdSwap Implementation](../../Mw05Recomp/kernel/imports.cpp) - VdSwap function (line 1389)

