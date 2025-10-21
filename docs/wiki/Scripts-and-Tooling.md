# Scripts & Tooling

## Consolidation Summary
- **Goal**: Reduce ~190 scripts/tools to ~30-40 essentials
- **Approach**: Unify analysis, search, and run scripts
- **Status**: Proposal stage, not yet implemented

## Proposed Unified Tools

### Single Analysis Tool
```bash
python tools/mw05_analyze.py trace <file>      # Analyze trace logs
python tools/mw05_analyze.py pm4 <file>        # Analyze PM4 commands
python tools/mw05_analyze.py threads <file>    # Analyze thread activity
python tools/mw05_analyze.py imports <file>    # Analyze import calls
```

### Single Search Tool
```bash
python tools/mw05_find.py function <address>   # Find function info
python tools/mw05_find.py caller <address>     # Find callers
python tools/mw05_find.py xref <address>       # Find cross-references
```

### Single Runner
```bash
python scripts/mw05_run.py --profile debug     # Debug profile
python scripts/mw05_run.py --profile verbose   # Verbose logging
python scripts/mw05_run.py --profile pm4       # PM4 debugging
python scripts/mw05_run.py --profile fileio    # File I/O debugging
python scripts/mw05_run.py --duration 60       # Run for 60 seconds
```

## Environment Variables

### Keep (Essential)
- `MW05_DEBUG_*` - Verbosity control (graphics, pm4, kernel, thread, heap, fileio)
- `MW05_PM4_*` - PM4 control (scan, apply, emit)
- `MW05_HOST_TRACE_*` - Trace logging control

### Remove/Phase-out (Obsolete Workarounds)
- `MW05_FORCE_*` - Force various behaviors (no longer needed after fixes)
- `MW05_BREAK_*` - Break loops (no longer needed after fixes)
- `MW05_UNBLOCK_MAIN` - Unblock main thread (caused heap corruption!)
- `MW05_FORCE_VD_INIT` - Force video init (caused crashes!)
- `MW05_STREAM_FALLBACK_BOOT` - Fallback boot mode (now default behavior)

## GitHub Wiki Publishing

### Manual Publishing
1. Clone the Wiki repo (once):
   ```
   git clone https://github.com/Sh2dow/Mw05Recomp.wiki.git
   ```
2. Copy wiki pages:
   ```
   xcopy /E /I docs\wiki Mw05Recomp.wiki
   ```
3. Commit & push:
   ```
   cd Mw05Recomp.wiki
   git add -A
   git commit -m "wiki: update consolidated docs"
   git push
   ```

### Automated Publishing
Use `scripts/publish_wiki.ps1` to automate cloning/pulling and pushing the Wiki (supports -DryRun).

## Self-Debuggable App Plan

### Built-in Debug Console (Implemented)
- ImGui-based console window (toggle with ` or F1)
- Runtime control of all debug settings (no restart needed!)
- Command history (up/down arrows)
- Profile system (minimal, normal, verbose, pm4, fileio)
- Backward compatible with environment variables

### Commands
```
debug.graphics 0|1|2|3  - Set graphics verbosity
debug.pm4 0|1|2|3       - Set PM4 verbosity
debug.kernel 0|1|2|3    - Set kernel verbosity
debug.thread 0|1|2|3    - Set thread verbosity
debug.heap 0|1|2|3      - Set heap verbosity
debug.fileio 0|1|2|3    - Set file I/O verbosity
profile minimal|normal|verbose|pm4|fileio - Load debug profile
trace.vdswap on|off     - Enable/disable VdSwap tracing
trace.pm4 on|off        - Enable/disable PM4 tracing
status                  - Show current settings
clear                   - Clear console output
help                    - Show all commands
```

## Current Scripts (Essential)
- `build_cmd.ps1` - Build helper (stages: configure, codegen, genlist, lib, app)
- `run_with_debug.ps1` - Run with debug logging
- `scripts/auto_handle_messageboxes.py` - Automated testing with message box handling
- `scripts/run_with_env.cmd` - Run with environment variables
- `scripts/debug.cmd` - Launch with CDB/WinDbg
- `tools/analyze_trace.py` - Analyze trace logs
- `tools/analyze_main_thread.py` - Analyze main thread activity
- `tools/find_spin_loop_address.py` - Find spin loop addresses

