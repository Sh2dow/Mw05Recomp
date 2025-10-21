# Debugging Guide

## Three-Level Debugging System

### Level 1: Built-in Debug Console
- Launch game (e.g., `scripts\debug.cmd`), press ` or F1
- Commands:
  - `status` - Show current settings
  - `heap.stats` - Show heap statistics
  - `thread.list` - List all threads
  - `trace.vdswap on|off` - Enable/disable VdSwap tracing
  - `vdswap.log` - Show VdSwap log
  - `pm4.stats` - Show PM4 statistics
  - `pm4.opcodes` - Show PM4 opcode histogram
  - `pm4.dump 100` - Dump first 100 PM4 packets
  - `profile verbose|minimal|normal|pm4|fileio` - Load debug profile
  - `clear` - Clear console output
- Use for runtime toggles and quick checks without restarts

### Level 2: Environment Variables
- **Graphics**: `MW05_DEBUG_GRAPHICS=0|1|2|3` (0=off, 1=minimal, 2=normal, 3=verbose)
- **PM4**: `MW05_DEBUG_PM4=0|1|2|3`
- **Kernel**: `MW05_DEBUG_KERNEL=0|1|2|3`
- **Threads**: `MW05_DEBUG_THREAD=0|1|2|3`
- **Heap**: `MW05_DEBUG_HEAP=0|1|2|3`
- **File I/O**: `MW05_DEBUG_FILEIO=0|1|2|3`
- **PM4 Control**:
  - `MW05_PM4_TRACE=1` - Enable PM4 tracing
  - `MW05_PM4_SCAN_ALL=1` - Scan all PM4 packets
  - `MW05_PM4_APPLY_STATE=1` - Apply PM4 state changes
  - `MW05_PM4_EMIT_DRAWS=1` - Emit draw commands
- Use for automated runs/CI; restart required to change

### Level 3: External Debuggers
- Use CDB/WinDbg for breakpoints, stepping, call stacks, memory inspection
- Launch helpers exist in `scripts/`
- Example: `scripts\debug.cmd` launches game with CDB attached

## "No Draws" Investigation Checklist
1. **VdSwap tracing ON** - Expect calls; if none, render path not reached
2. **pm4.stats/opcodes** - NOP + REG_WRITE only = init phase; draws=0
3. **thread.list** - Verify 12 threads alive; if not, fix thread creation
4. **heap.stats** - Ensure memory not exhausted
5. **If still no draws** - Attach debugger and trace render thread entry (0x825AA970) and VdSwap callsites

## Common Debugging Scenarios

### Crash Investigation
1. Check stderr output for crash location (offset +0x...)
2. Calculate PPC address from crash offset
3. Find function in IDA or generated PPC sources
4. Check if function is in TOML (if not, add it)
5. Look for NULL-CALL errors in trace log

### Thread Issues
1. Check thread creation with `thread.list`
2. Verify all 12 threads are created
3. Check thread context initialization (callback pointers at +84, +88)
4. Look for race conditions (params copy, dynamic_cast + Wait())

### File I/O Issues
1. Enable `MW05_DEBUG_FILEIO=3`
2. Check for StreamBridge operations in trace log
3. Verify game files exist in `./game/` directory
4. Check for file path resolution (game:\ maps to .\game\)

### Rendering Issues
1. Enable `MW05_DEBUG_GRAPHICS=3` and `MW05_DEBUG_PM4=3`
2. Check for VdSwap calls in trace log
3. Monitor PM4 opcode histogram for draw commands (0x22, 0x36)
4. Check function pointer gate at +0x3CEC (rendering function)


## Heap Analysis
1. Set `MW05_DEBUG_HEAP=3` and run a 60s session
2. In console: `heap.stats` (user vs physical heaps)
3. Verify physical bump allocator counters (allocated bytes)
4. Watch for large spikes or regressions after PM4 or file I/O bursts
5. If corrupted stats: check for over-aligned physical allocations and Free() path

## Recommended Debugging Workflow
1. Start with built-in console (Level 1) for toggles and quick signals
2. Enable only the subsystem you investigate (`debug.pm4 2`, `debug.graphics 2`)
3. If no clear signal in 1 minute, turn to Level 2 (env vars) and rerun for 5–10 minutes
4. If still unclear, attach CDB (Level 3) and set breakpoints on the suspected functions
5. Always capture: pm4.stats, thread.list, heap.stats, and stderr summary
