# Repository Guidelines
 
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
- Keep toolchain paths out of code; rely on presets and `build_cmd.ps1` params.
- Use `update_submodules.bat` and pinned vendor deps; avoid ad-hoc version bumps without justification.
