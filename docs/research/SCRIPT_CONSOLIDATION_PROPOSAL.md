# Script Consolidation and Debug System Unification Proposal

**Date**: 2025-10-21  
**Status**: Proposal for Review

## Executive Summary

The MW05Recomp project has accumulated ~190 scripts/tools across `scripts/` and `tools/` directories. Many have overlapping functionality, are one-off debugging aids, or are no longer needed after recent fixes. This document proposes:

1. **Consolidate redundant scripts** - Reduce from ~190 to ~30-40 essential scripts
2. **Unified debug control system** - Single Python/PowerShell wrapper for all debug scenarios
3. **Environment variable cleanup** - Reduce from ~80+ to ~20 essential variables
4. **Performance-focused approach** - Remove magic-number workarounds, focus on root causes

## Current State Analysis

### Scripts Directory (~90 files)

**Run Scripts** (30+ files - HIGH REDUNDANCY):
- `run_*.ps1` - Multiple variants (debug, trace, minimal, clean, etc.)
- `test_*.ps1` - Test scripts with similar purposes
- **Problem**: Each script sets slightly different env vars, hard to maintain

**Analysis Scripts** (20+ files):
- `analyze_*.py`, `analyze_*.ps1` - Trace analysis tools
- **Problem**: Split between scripts/ and tools/, unclear which to use

**Debug Scripts** (10+ files):
- `debug_*.ps1` - Various debugging scenarios
- **Problem**: Overlap with run scripts, unclear distinction

### Tools Directory (~100+ files)

**Analysis Tools** (40+ files):
- `analyze_*.py` - Duplicate functionality with scripts/
- `find_*.py` - Search/investigation tools
- **Problem**: Many are one-off tools for fixed bugs

**Trace Tools** (15+ files):
- `trace_*.py` - Trace file analysis
- **Problem**: Could be consolidated into single tool

### Environment Variables (~80+ variables)

**Categories**:
1. **Debug/Tracing** (20 vars): `MW05_TRACE_*`, `MW05_DEBUG_*`
2. **Workarounds** (30 vars): `MW05_FORCE_*`, `MW05_BREAK_*`, `MW05_FAKE_*`
3. **PM4/Graphics** (15 vars): `MW05_PM4_*`, `MW05_VD_*`
4. **File I/O** (5 vars): `MW05_STREAM_*`, `MW05_FILE_*`
5. **Thread Control** (10 vars): `MW05_RENDER_THREAD_*`, etc.

**Problem**: Many workarounds are no longer needed after recompiler fixes!

## Proposed Consolidation

### Phase 1: Remove Obsolete Scripts

**Scripts to Archive** (move to `scripts/archive/`):
```
# One-off debugging tools for fixed bugs
scripts/analyze_crash*.py          # Crash bugs are fixed
scripts/find_crash_function.ps1    # No longer crashing
scripts/test_heap_corruption.ps1   # Heap issues resolved
scripts/debug_crash.ps1            # Crashes fixed
scripts/investigate_black_screen.ps1  # Screen rendering works

# Redundant run scripts
scripts/run_5sec.ps1               # Use unified runner with --duration
scripts/run_10sec.ps1
scripts/run_60sec.ps1
scripts/run_longer.ps1
scripts/run_very_long.ps1
scripts/run_minimal.ps1            # Use unified runner with --profile minimal
scripts/run_clean_test.ps1
scripts/run_essential_only.ps1

# Obsolete workaround scripts
scripts/test_unblock_main*.ps1     # MW05_UNBLOCK_MAIN no longer needed
scripts/test_force_present.ps1     # Rendering works naturally now
scripts/test_force_gfx.ps1
```

**Total to Archive**: ~40 scripts

### Phase 2: Consolidate Analysis Tools

**Create Unified Tools**:

1. **`tools/mw05_analyze.py`** - Single analysis tool with subcommands:
   ```bash
   python tools/mw05_analyze.py trace <file>      # Analyze trace logs
   python tools/mw05_analyze.py pm4 <file>        # Analyze PM4 commands
   python tools/mw05_analyze.py threads <file>    # Analyze thread activity
   python tools/mw05_analyze.py imports <file>    # Analyze import calls
   ```

2. **`tools/mw05_find.py`** - Single search tool:
   ```bash
   python tools/mw05_find.py function <address>   # Find function info
   python tools/mw05_find.py caller <address>     # Find callers
   python tools/mw05_find.py pattern <regex>      # Search patterns
   ```

**Tools to Consolidate** (merge into above):
```
tools/analyze_trace.py
tools/analyze_pm4_commands.py
tools/analyze_thread_activity.py
tools/analyze_imports.py
tools/find_lr_function.py
tools/find_caller.py
tools/find_function_sizes.py
```

**Total to Consolidate**: ~30 tools

### Phase 3: Unified Debug Runner

**Create `scripts/mw05_run.py`** - Single runner for all scenarios:

```python
#!/usr/bin/env python3
"""
Unified MW05 debug runner with profile-based configuration.
Replaces 30+ run_*.ps1 scripts with single tool.
"""

import argparse
import subprocess
import os
from pathlib import Path

PROFILES = {
    "minimal": {
        "description": "Minimal logging, maximum performance",
        "env": {
            "MW05_DEBUG_GRAPHICS": "0",
            "MW05_DEBUG_KERNEL": "0",
            "MW05_DEBUG_PM4": "0",
        }
    },
    "normal": {
        "description": "Normal logging (default)",
        "env": {
            "MW05_DEBUG_GRAPHICS": "1",
            "MW05_DEBUG_KERNEL": "1",
            "MW05_DEBUG_PM4": "1",
        }
    },
    "verbose": {
        "description": "Verbose logging for debugging",
        "env": {
            "MW05_DEBUG_GRAPHICS": "3",
            "MW05_DEBUG_KERNEL": "3",
            "MW05_DEBUG_PM4": "3",
            "MW05_HOST_TRACE_IMPORTS": "1",
            "MW05_HOST_TRACE_HOSTOPS": "1",
        }
    },
    "pm4": {
        "description": "PM4 command analysis",
        "env": {
            "MW05_DEBUG_PM4": "3",
            "MW05_PM4_TRACE": "1",
            "MW05_PM4_SCAN_ALL": "1",
        }
    },
    "fileio": {
        "description": "File I/O debugging",
        "env": {
            "MW05_DEBUG_FILEIO": "3",
            "MW05_STREAM_BRIDGE": "1",
        }
    },
}

def main():
    parser = argparse.ArgumentParser(description="MW05 unified debug runner")
    parser.add_argument("--profile", choices=PROFILES.keys(), default="normal",
                        help="Debug profile to use")
    parser.add_argument("--duration", type=int, default=30,
                        help="Run duration in seconds")
    parser.add_argument("--auto-dismiss", action="store_true",
                        help="Auto-dismiss message boxes")
    parser.add_argument("--capture-stderr", action="store_true",
                        help="Capture stderr to file")
    args = parser.parse_args()
    
    # Set environment variables from profile
    profile = PROFILES[args.profile]
    for key, value in profile["env"].items():
        os.environ[key] = value
    
    print(f"Running with profile: {args.profile} - {profile['description']}")
    print(f"Duration: {args.duration} seconds")
    
    # Run game
    # ... implementation ...

if __name__ == "__main__":
    main()
```

**Usage Examples**:
```bash
# Run with minimal logging for 60 seconds
python scripts/mw05_run.py --profile minimal --duration 60

# Run with PM4 debugging
python scripts/mw05_run.py --profile pm4 --auto-dismiss

# Run with verbose logging and stderr capture
python scripts/mw05_run.py --profile verbose --capture-stderr
```

### Phase 4: Environment Variable Cleanup

**Essential Variables** (keep these):

**Debug/Tracing** (6 vars):
```
MW05_DEBUG_GRAPHICS=0|1|2|3    # Graphics subsystem verbosity
MW05_DEBUG_KERNEL=0|1|2|3      # Kernel subsystem verbosity
MW05_DEBUG_THREAD=0|1|2|3      # Thread subsystem verbosity
MW05_DEBUG_HEAP=0|1|2|3        # Heap subsystem verbosity
MW05_DEBUG_FILEIO=0|1|2|3      # File I/O subsystem verbosity
MW05_DEBUG_PM4=0|1|2|3         # PM4 subsystem verbosity
```

**PM4/Graphics** (5 vars):
```
MW05_PM4_TRACE=0|1             # Enable PM4 tracing
MW05_PM4_APPLY_STATE=0|1       # Apply PM4 state to host
MW05_PM4_EMIT_DRAWS=0|1        # Emit host draw calls
MW05_PM4_SCAN_ALL=0|1          # Scan entire ring buffer
MW05_PM4_SNOOP=0|1             # Snoop ring buffer writes
```

**File I/O** (2 vars):
```
MW05_STREAM_BRIDGE=0|1         # Enable streaming bridge
MW05_HOST_TRACE_FILE=path      # Trace log file path
```

**Workarounds to REMOVE** (no longer needed):
```
MW05_UNBLOCK_MAIN              # Game runs naturally now
MW05_FORCE_RENDER_THREADS      # Threads created naturally
MW05_BREAK_82813514            # Worker threads work correctly
MW05_FAKE_ALLOC_SYSBUF         # Allocation works correctly
MW05_FORCE_VD_INIT             # Graphics init works naturally
MW05_FORCE_GFX_NOTIFY_CB       # Callbacks registered naturally
MW05_BREAK_SLEEP_LOOP          # Sleep loops work correctly
MW05_FORCE_PRESENT             # Present works naturally
... (20+ more workaround vars)
```

**Total Reduction**: From ~80 to ~15 essential variables

## Implementation Plan

### Week 1: Archive Obsolete Scripts
1. Create `scripts/archive/` directory
2. Move obsolete scripts with README explaining why
3. Update documentation

### Week 2: Create Unified Tools
1. Implement `tools/mw05_analyze.py`
2. Implement `tools/mw05_find.py`
3. Test with existing trace files
4. Archive old tools

### Week 3: Create Unified Runner
1. Implement `scripts/mw05_run.py`
2. Define profiles for common scenarios
3. Test all profiles
4. Archive old run scripts

### Week 4: Environment Variable Cleanup
1. Remove workaround variables from code
2. Update documentation
3. Test game runs without workarounds
4. Verify performance improvement

## Expected Benefits

1. **Reduced Complexity**: From ~190 scripts to ~40
2. **Better Maintainability**: Single source of truth for debug configs
3. **Improved Performance**: Remove workaround overhead
4. **Clearer Documentation**: Obvious which tool to use for what
5. **Easier Onboarding**: New developers can understand system quickly

## Next Steps

1. Review this proposal
2. Test game runs without workaround variables
3. Implement unified runner
4. Archive obsolete scripts
5. Update AGENTS.md with new workflow

