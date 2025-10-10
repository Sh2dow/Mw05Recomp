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

### Current Status: BLACK SCREEN - Game Stuck in Early Init
**ROOT CAUSE**: Game stuck in infinite loop in `sub_8262DD80` (string formatting) at `lr=0x8262DD88` BEFORE calling any kernel functions or setting up import table.

### Key Findings
1. **Main loop IS running** - unblock thread at `0x82A2CF40` working correctly (138M+ iterations)
2. **Game stuck in CRT initialization** - never reaches import table setup (ObReferenceObjectByHandle, etc.)
3. **Main thread spinning** - 81,501 calls doing memory stores in string formatting code
4. **NO kernel function calls** - game hasn't called TLS, file I/O, audio, input, or any other kernel functions
5. **PM4 buffers have register writes** - 24,576 type-0 packets (GPU config) but 0 draw commands
6. **Graphics callback registered and invoked** - 923+ times, but does no work (context values = 0)

### Execution Flow Comparison (Xenia vs Our Implementation)
**Xenia (Working)**:
- Line 375-380: Creates XMA Decoder and Audio Worker threads BEFORE loading game
- Line 910-950: Sets up import table (ObReferenceObjectByHandle, RtlUnicodeToMultiByteN, etc.)
- Line 1122-1123: Game starts executing, loads title name "NFS Most Wanted"
- Line 35788+: VD notify callback invoked, NEW THREAD created, draw commands issued

**Our Implementation (Broken)**:
- Creates 28 threads including worker threads at `0x82812ED0` → `0x828134E0` (complete successfully)
- Main thread `tid=a9c4` (entry `0x8262E9A8`) stuck in infinite loop
- Executing at `lr=0x8262DD88` in `sub_8262DD80` (string formatting)
- NEVER reaches import table setup
- NEVER calls any kernel functions
- NEVER progresses to main game loop

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

### Next Steps to Fix
1. **Identify infinite loop in `sub_8262DD80`** - why string formatting never completes
2. **Add aggressive loop breaking** - similar to `MW05_BREAK_82813514` but for CRT init
3. **Skip CRT initialization** - jump directly to import table setup
4. **Implement missing CRT dependencies** - whatever `sub_8262DD80` is waiting for
5. **Compare with Xenia startup** - find what we're missing in early init sequence

### Reference: Working Thread Patterns (from Xenia)
- XMA Decoder thread created at startup (before game module load)
- Audio Worker thread created at startup (before game module load)
- Import table setup happens automatically after module load
- Game code starts executing after import table is ready
- VD notify callback triggers NEW THREAD creation for rendering
- That new thread issues draw commands via PM4 packets
