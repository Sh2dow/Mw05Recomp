# Self-Debuggable App Plan - Replace Scripts with Built-in Debug System

**Date**: 2025-10-21  
**Goal**: Make MW05Recomp self-debuggable, eliminate 80+ environment variables, delete obsolete scripts

## Problem Statement

**Current State**:
- 80+ environment variables for debug control
- 190+ scripts (many obsolete workarounds)
- External scripts for every debug scenario
- No runtime control - must restart app to change debug settings

**User's Vision**:
- App should be self-debuggable with built-in commands
- Use CDB/WinDbg for external debugging when needed
- Eliminate script sprawl
- Runtime control of debug settings

## Solution: Self-Debuggable App Architecture

### Phase 1: Built-in Debug Console (ImGui)

**Add Debug Console Window** (already have ImGui):
```cpp
// Mw05Recomp/ui/debug_console.h
class DebugConsole {
public:
    void Render();  // ImGui window
    void ExecuteCommand(const char* cmd);
    
    // Commands:
    // debug.graphics 0|1|2|3    - Set graphics verbosity
    // debug.pm4 0|1|2|3         - Set PM4 verbosity
    // debug.kernel 0|1|2|3      - Set kernel verbosity
    // trace.start [file]        - Start trace logging
    // trace.stop                - Stop trace logging
    // pm4.dump                  - Dump PM4 ring buffer
    // pm4.stats                 - Show PM4 statistics
    // heap.stats                - Show heap statistics
    // thread.list               - List all threads
    // vdswap.trace on|off       - Enable VdSwap tracing
};
```

**Benefits**:
- Change debug settings at runtime (no restart needed)
- See immediate effect of changes
- Built-in help system
- Command history

### Phase 2: Runtime Debug Control (Replace Environment Variables)

**Convert Environment Variables to Runtime Settings**:
```cpp
// Mw05Recomp/kernel/debug_settings.h
class DebugSettings {
public:
    // Verbosity levels (runtime changeable)
    std::atomic<int> graphics_verbosity{1};  // 0=off, 1=minimal, 2=normal, 3=verbose
    std::atomic<int> pm4_verbosity{1};
    std::atomic<int> kernel_verbosity{1};
    std::atomic<int> thread_verbosity{1};
    std::atomic<int> heap_verbosity{1};
    std::atomic<int> fileio_verbosity{1};
    
    // Trace control (runtime changeable)
    std::atomic<bool> trace_imports{false};
    std::atomic<bool> trace_hostops{false};
    std::atomic<bool> trace_vdswap{false};
    std::atomic<bool> trace_pm4{false};
    
    // PM4 control (runtime changeable)
    std::atomic<bool> pm4_scan_all{true};
    std::atomic<bool> pm4_apply_state{true};
    std::atomic<bool> pm4_emit_draws{true};
    
    // File I/O control (runtime changeable)
    std::atomic<bool> stream_bridge{true};
    
    // Initialize from environment (for backward compatibility)
    void InitFromEnvironment();
    
    // Save/load profiles
    void LoadProfile(const char* name);  // "minimal", "normal", "verbose", "pm4", "fileio"
    void SaveProfile(const char* name);
};

extern DebugSettings g_debugSettings;
```

**Migration Path**:
1. Keep environment variable support for backward compatibility
2. Add runtime control via debug console
3. Gradually remove environment variables as we verify runtime control works

### Phase 3: CDB/WinDbg Integration

**Create Single Debug Launcher** (`scripts/debug.cmd`):
```batch
@echo off
REM Single debug launcher - replaces all run_*.ps1 scripts

set EXE=out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe

if "%1"=="cdb" (
    REM Launch with CDB debugger
    cdb -g -G %EXE%
) else if "%1"=="windbg" (
    REM Launch with WinDbg
    windbg -g %EXE%
) else if "%1"=="profile" (
    REM Launch with profiler
    REM TODO: Add profiler integration
    %EXE%
) else (
    REM Normal launch
    %EXE%
)
```

**CDB/WinDbg Commands** (for external debugging):
```
# Break on VdSwap
bp Mw05Recomp!VdSwap

# Break on specific address
bp Mw05Recomp!sub_82598A20

# Trace function calls
wt -l 5

# Dump call stack
k

# Continue execution
g
```

### Phase 4: Delete Obsolete Scripts

**Scripts to DELETE** (workarounds no longer needed):
```
scripts/run_with_debug.ps1          - Replaced by debug console
scripts/run_deep_debug.ps1          - Replaced by debug console
scripts/run_pm4_trace.ps1           - Replaced by debug console
scripts/run_game.ps1                - Replaced by debug.cmd
scripts/run_pure_natural.ps1        - Replaced by debug.cmd
scripts/test_with_env.ps1           - Replaced by debug console
scripts/test_pm4_opcodes.ps1        - Replaced by debug console (NEW - just created!)
scripts/test_pm4_opcodes.cmd        - Replaced by debug console (NEW - just created!)
scripts/test_pm4_opcodes_auto.py    - Replaced by debug console (NEW - just created!)
scripts/auto_handle_messageboxes.py - Keep (useful for automated testing)
scripts/run_with_env.cmd            - Keep (used by other scripts)
... (30+ more workaround scripts)
```

**Scripts to KEEP** (essential tools):
```
scripts/run_with_env.cmd            - Environment setup helper
scripts/auto_handle_messageboxes.py - Automated testing
build_cmd.ps1                       - Build system
update_submodules.bat               - Git helper
```

**Tools to CONSOLIDATE** (merge into single tool):
```
tools/analyze_*.py → tools/mw05_analyze.py
tools/find_*.py    → tools/mw05_find.py
tools/trace_*.py   → tools/mw05_trace.py
```

### Phase 5: Environment Variable Cleanup

**Keep ONLY Essential Variables** (15 total):
```batch
REM Debug verbosity (6 vars) - DEPRECATED, use debug console instead
MW05_DEBUG_GRAPHICS=0|1|2|3
MW05_DEBUG_KERNEL=0|1|2|3
MW05_DEBUG_THREAD=0|1|2|3
MW05_DEBUG_HEAP=0|1|2|3
MW05_DEBUG_FILEIO=0|1|2|3
MW05_DEBUG_PM4=0|1|2|3

REM Trace control (2 vars) - DEPRECATED, use debug console instead
MW05_HOST_TRACE_FILE=path
MW05_HOST_TRACE_IMPORTS=0|1

REM PM4 control (3 vars) - DEPRECATED, use debug console instead
MW05_PM4_TRACE=0|1
MW05_PM4_APPLY_STATE=0|1
MW05_PM4_EMIT_DRAWS=0|1

REM File I/O (1 var) - DEPRECATED, use debug console instead
MW05_STREAM_BRIDGE=0|1

REM Game paths (3 vars) - KEEP
MW05_XEX=path/to/game.xex
MW05_GAME_ROOT=path/to/game
MW05_SAVE_ROOT=path/to/saves
```

**Delete ALL Workaround Variables** (60+ vars):
```
MW05_UNBLOCK_MAIN              - No longer needed (game runs naturally)
MW05_BREAK_82813514            - No longer needed (worker threads fixed)
MW05_FAKE_ALLOC_SYSBUF         - No longer needed (allocation works)
MW05_FORCE_VD_INIT             - No longer needed (VD init works)
MW05_FORCE_GFX_NOTIFY_CB       - No longer needed (callbacks work)
MW05_FORCE_RENDER_THREAD       - No longer needed (threads created naturally)
MW05_FORCE_PRESENT             - No longer needed (present works)
MW05_BREAK_SLEEP_LOOP          - No longer needed (sleep works)
MW05_BREAK_WAIT_LOOP           - No longer needed (wait works)
MW05_FAST_BOOT                 - No longer needed (boot works)
... (50+ more workaround variables)
```

## Implementation Plan

### Week 1: Add Debug Console
1. Create `Mw05Recomp/ui/debug_console.h` and `.cpp`
2. Add ImGui window with command input
3. Implement basic commands (debug.*, trace.*, pm4.*)
4. Test runtime control of verbosity levels

### Week 2: Runtime Settings System
1. Create `Mw05Recomp/kernel/debug_settings.h` and `.cpp`
2. Replace `std::getenv()` calls with `g_debugSettings.*`
3. Add profile support (minimal, normal, verbose, pm4, fileio)
4. Test backward compatibility with environment variables

### Week 3: CDB/WinDbg Integration
1. Create `scripts/debug.cmd` launcher
2. Document CDB/WinDbg commands for common scenarios
3. Test debugging workflows
4. Update AGENTS.md with new debug workflow

### Week 4: Script Cleanup
1. Delete obsolete workaround scripts (30+ files)
2. Archive old scripts to `scripts/archive/`
3. Consolidate analysis tools (tools/mw05_*.py)
4. Update documentation

## Benefits

**Before** (Current State):
- 80+ environment variables
- 190+ scripts
- Must restart app to change debug settings
- Hard to understand which variables are needed
- Many obsolete workarounds

**After** (Self-Debuggable App):
- 15 environment variables (backward compatibility only)
- 40 scripts (essential tools only)
- Runtime control via debug console
- Clear documentation
- No obsolete workarounds

**Performance Impact**:
- Minimal (atomic variables for settings)
- No overhead when debug features disabled
- Same performance as current implementation

## Next Steps

1. **IMMEDIATE**: Create debug console UI (ImGui window)
2. **NEXT**: Implement runtime settings system
3. **THEN**: Add CDB/WinDbg integration
4. **FINALLY**: Delete obsolete scripts and environment variables

This approach makes the app self-sufficient for debugging while keeping CDB/WinDbg available for deep debugging when needed.

