# Repository Guidelines
**Project**: Mw05Recomp - Xbox 360 NFS: Most Wanted recompilation to x64 with D3D12/Vulkan backend
 
## Project Structure & Module Organization
- `Mw05Recomp/`: Application and platform code (e.g., `ui/`, `gpu/`, `apu/`, `kernel/`, `install/`).
- `Mw05RecompLib/`: Recompiled game library and generated PPC sources (`ppc/`).
- `Mw05RecompResources/`: Art/assets used by the app (no proprietary game data).
- `tools/`, `thirdparty/`: Helper tools and vendored deps (includes `thirdparty/vcpkg`).
- `out/`: CMake/Ninja build output (`out/build/<preset>`, `out/install/<preset>`).
- Top-level: `CMakeLists.txt`, `CMakePresets.json`, `build_cmd.ps1`, `.editorconfig`.
 
## Build, Test, and Development Commands
- Configure (Windows/Clang): `cmake --preset x64-Clang-Release`
- Build all targets: `cmake --build out/build/x64-Clang-Release -j`
- Staged helper (Windows): `./build_cmd.ps1 -Stage all` (stages: `configure`, `codegen`, `genlist`, `lib`, `app`). Example: `./build_cmd.ps1 -Stage app`
- Clean generated PPC: `./build_cmd.ps1 -Clean -Stage codegen`
- Linux/macOS: use `linux-*` / `macos-*` presets in `CMakePresets.json` (generator: Ninja)
- Notes: vcpkg is vendored; presets set `VCPKG_ROOT`. Provide `MW05_XEX` when configuring locally.
 
## Coding Style & Naming Conventions
- `.editorconfig`: UTF-8, LF newlines, 4-space indentation.
- C++: PascalCase for types/methods (`GameWindow::SetTitle()`), `s_` for statics, camelCase for fields.
- Prefer self-contained headers, minimal globals, clear module boundaries (`ui/`, `patches/`, `kernel/`).
 
## Testing Guidelines
- No formal unit tests. Validate by building `Mw05Recomp` and exercising installer and main menus.
- Keep changes testable (small entry points, assertions under debug defines).
- If adding tests, mirror folders under `tests/` and integrate via optional CMake targets.
 
## Commit & Pull Request Guidelines
- Commits: short, imperative summaries (e.g., `gpu: fix video init`, `build: pin SDL`).
- PRs: concise description, rationale, affected modules, platforms tested; link issues (e.g., `Fixes #123`). Add screenshots for UI/visual changes.
- Do not commit generated files, binaries, or any game assets.
 
## Security & Configuration Tips
- Never add proprietary game data to the repo or PRs.
- Never edit generated PPC
- Keep toolchain paths out of code; rely on presets and `build_cmd.ps1` params.
- Use `update_submodules.bat` and pinned vendor deps; avoid ad-hoc version bumps without justification.

## Critical Debugging Information

### Current Status: ROOT CAUSE FOUND - Context Structure Not Initialized!
**XENIA DEBUG COMPLETE**: Analyzed Thread #2 (0x82812ED0) with assembly disassembly and memory dumps.
**FUNCTION ANALYSIS**: `sub_82812ED0` is a TRAMPOLINE function that:
  1. Takes context structure pointer in r3
  2. Loads function pointer from *(r3 + 4)
  3. Loads context parameter from *(r3 + 8)
  4. Calls the function pointer with the context
  5. Returns
**CONTEXT STRUCTURE** (at offset r3):
  ```c
  struct ThreadContext {
      uint32_t state;        // +0x00 - set to 1 before calling
      uint32_t function_ptr; // +0x04 - function to call
      uint32_t context;      // +0x08 - parameter to pass
  };
  ```
**OUR PROBLEM**: Context at 0x00120E10 contains GARBAGE:
  - +0x00 (state): 0x00000000 (OK, will be set to 1)
  - +0x04 (func_ptr): 0xE0348182 (GARBAGE! Not a valid function pointer!)
  - +0x08 (context): 0x00000000 (OK)
**ROOT CAUSE**: Thread #1 (0x828508A8) is NOT initializing the context structure before creating Thread #2.
**XENIA BEHAVIOR**: Thread #2 created with ctx=0x701EFAF0, which is properly initialized before thread creation.
**KEY FINDING**: Context addresses are DIFFERENT!
  - Xenia: ctx=0x701EFAF0 (heap memory, 0x70000000 range)
  - Ours: ctx=0x00120E10 (XEX data section, 0x00100000 range)
**CRITICAL DISCOVERY**: Context is CORRUPTED between thread creation and execution!
  - At ExCreateThread: +0x04 = 0x828134E0 (VALID function pointer!)
  - At wrapper execution: +0x04 = 0xE0348182 (GARBAGE!)
  - Something overwrites memory at 0x00120E10 + 4 after thread creation
**ROOT CAUSE FOUND**: NOT corruption - BYTE-SWAPPING ERROR!
  - 0x828134E0 (big-endian) = 0xE0348182 (little-endian)
  - Context was always correct, just read wrong (missing __builtin_bswap32)
  - Fixed byte-swapping in wrapper - function pointer now reads correctly
**NEW PROBLEM**: Thread #2 still completes immediately instead of running worker loop
**INVESTIGATION**: Worker function sub_828134E0 checks qword_828F1F98 after wait
  - If qword_828F1F98 == 0, worker exits immediately (line 0x8281351C: beq cr6, loc_82813580)
  - This is likely a "should continue running" flag that needs to be initialized
**VM ARENA**: VmArena is initialized at [0x7FEA0000, 0xA0000000) = 513 MB (correct!)
  - Context at 0x00120E10 is in XEX data section (static variable, not heap-allocated)
  - This is correct - Xenia also uses static context, just at different address
**ROOT CAUSE FOUND**: sub_82813598 (worker init function) IS being called, but qword_828F1F98 remains 0!
  - BEFORE sub_82813598: qword_828F1F98 = 0x0000000000000000
  - AFTER sub_82813598: qword_828F1F98 = 0x0000000000000000
  - The initialization function is NOT setting the flag!
  - This causes Thread #2 to exit immediately when it checks the flag
**DEEPER INVESTIGATION**: Assembly shows `std r11, (qword_828F1F98)` at line 0x8281363C
  - r11 should contain: divw(0xFF676980, r3) sign-extended = 0xFFFFFFFFFFFE7960 (when r3=0x64)
  - But recompiled code stores 0 instead!
  - Workaround: Manually setting flag BEFORE function call works, but recompiled code overwrites it back to 0
**RECOMPILER BUG**: The PPC recompiler is not correctly executing the `std` instruction or the division/sign-extension
  - Either r11 is being calculated as 0 (division bug)
  - Or the `std` instruction is storing the wrong value
  - This is a bug in the PPC-to-x64 recompilation process
**WORKAROUND IMPLEMENTED**: Manually setting qword_828F1F98 after sub_82813598 returns (in mw05_trace_threads.cpp)
**RECOMPILER FIX NEEDED**: See RECOMPILER_BUG_INVESTIGATION.md for detailed instructions to fix XenonRecomp
**NEXT STEP**: Either fix the recompiler (long-term) or verify the workaround allows Thread #2 to run correctly (short-term).

### Key Findings
1. **VBlank pump working** - Fixed in previous iteration, VBlank ticks are happening
2. ✅ **Import table patching WORKING!** - 388/719 imports (54%) successfully patched and callable
3. ✅ **Auto-generated import lookup** - 232 __imp__ functions in lookup table
4. ✅ **Nt* kernel functions implemented** - Added 12 Nt* functions + 10 additional kernel functions
5. ✅ **VdInitializeEngines being called!** - Game is calling graphics initialization functions
6. ✅ **Graphics callbacks registered!** - Game naturally registered graphics callback at 0x825979A8
7. ✅ **Graphics callbacks invoked!** - 1,994 successful callback invocations in 30 seconds
8. ✅ **PM4 command buffer scanning!** - PM4_ScanLinear is being called, processing command buffers
9. ✅ **KeDelayExecutionThread implemented!** - Sleep function is working correctly
10. ⚠️ **No draws yet** - PM4 scans show draws=0, game hasn't issued draw commands yet
11. ⚠️ **Game stuck in sleep loop** - KeDelayExecutionThread called 9,285 times in 30 seconds
12. ⚠️ **NO file I/O** - Game has not called NtCreateFile/NtOpenFile/NtReadFile even once
13. ⚠️ **331 imports still missing** - 182 unique missing imports (mostly NetDll, Xam, XMA)
14. ⚠️ **Missing 6 threads** - Xenia creates 9 threads, we only create 3

### Execution Flow Comparison (Xenia vs Our Implementation)
**Xenia (Working)**:
- Line 375-380: Creates XMA Decoder and Audio Worker threads BEFORE loading game
- Line 725-944: **Processes import table** - patches 193 xboxkrnl imports with kernel function addresses
- Line 1122-1123: Game starts executing, loads title name "NFS Most Wanted"
- Line 1280+: Main thread sleeps at `lr=0x8262F300` (SAME AS US!)
- Line 1280-317729: **Game sleeps 149,148 times** (this is NORMAL!)
- Line 35788+: VD notify callback invoked, NEW THREAD created
- Line 317731: **First draw command issued!**

**Our Implementation (Current State)**:
- ✅ VBlank pump starts before guest thread (FIXED)
- ✅ Import table processed - 388/719 imports patched (WORKING)
- ✅ Multiple threads running, kernel calls happening (WORKING)
- ✅ Main thread sleeping at `lr=0x8262F300` (SAME AS XENIA!)
- ⚠️ Game sleeps infinitely - never progresses to draw commands
- ❌ Missing 6 threads - Only 3/9 threads created
- ❌ No file I/O - Game hasn't loaded any resources

### Memory Addresses of Interest
- `0x82A2CF40`: Main thread spin loop flag (unblock thread sets this to 1)
- `0x40007180`: Graphics context (16KB, allocated and initialized)
- `0x8262DD80`: String formatting function where main thread is stuck
- `0x8262DD88`: Link register value in infinite loop
- `0x82441CF0`: Main game loop function (never reached)
- `0x8262DE60`: Frame update function (never reached)

### Environment Variables (set in `run_with_debug.ps1`)
```powershell
$env:MW05_FAST_BOOT = "1"                          # Fast boot to skip delays
$env:MW05_UNBLOCK_MAIN = "1"                       # Unblock main thread at 0x82A2CF40 (WORKING)
$env:MW05_BREAK_82813514 = "1"                     # Break worker thread loop (WORKING)
$env:MW05_BREAK_WAIT_LOOP = "1"                    # Break wait loop at 0x825CEE18
$env:MW05_FORCE_PRESENT = "1"                      # Force host to present frames
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"                # Force graphics callback registration
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"   # Graphics callback context address
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"  # Delay before forcing callback
```

### Key Files
- `Mw05Recomp/kernel/imports.cpp`: Kernel function implementations, VBLANK handler, audio stubs
- `Mw05Recomp/cpu/mw05_boot_shims.cpp`: Boot shims, loop-breaking logic for worker threads
- `Mw05Recomp/cpu/mw05_trace_threads.cpp`: Thread wrappers, unblock thread implementation
- `Mw05RecompLib/ppc/ppc_recomp.80.cpp`: `sub_8262DD80` string formatting (line 1856+)
- `Mw05RecompLib/ppc/ppc_recomp.54.cpp`: `sub_82441CF0` main game loop (line 12143+)
- `run_with_debug.ps1`: Automated test script (runs 15 seconds, captures stderr)
- `tools/xenia.log`: Reference log from working Xenia emulator
- `out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log`: Runtime trace of all kernel calls

### Diagnostic Commands
```powershell
# Build and test
./build_cmd.ps1 -Stage app
./run_with_debug.ps1

# Analyze traces
python tools/analyze_trace.py
python tools/analyze_main_thread.py
python tools/find_spin_loop_address.py

# Check for specific patterns
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log | Select-String 'pattern'
Get-Content debug_stderr.txt | Select-String 'STUB|!!!'
```

### Next Steps to Get Draws Appearing
1. **Implement more imports** - Add the missing 697 imports (prioritize Ke*, Nt*, Rtl*, Ex* kernel functions)
2. **Investigate game state** - Check why the game is stuck and not progressing to draw commands
3. **Monitor thread activity** - Ensure all game threads are running and not blocked
4. **Check for missing resources** - Verify that all required game resources are accessible
5. **Add more Vd* functions** - Implement any additional graphics functions the game might need

### Reference: Working Thread Patterns (from Xenia)
- XMA Decoder thread created at startup (before game module load)
- Audio Worker thread created at startup (before game module load)
- Import table setup happens automatically after module load
- Game code starts executing after import table is ready
- VD notify callback triggers NEW THREAD creation for rendering
- That new thread issues draw commands via PM4 packets
