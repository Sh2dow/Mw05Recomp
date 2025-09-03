# Repository Guidelines

## Project Structure & Module Organization
- Mw05Recomp: Game application and platform code (e.g., `ui/`, `gpu/`, `apu/`, `kernel/`, `install/`).
- Mw05RecompLib: Recompiled game library and generated PPC sources (`ppc/`).
- Mw05RecompResources: Art/assets used by the app (no proprietary game data).
- tools/ and thirdparty/: Helper tools and dependencies (includes `vcpkg`).
- out/: CMake/Ninja build output (`out/build/<preset>`, `out/install/<preset>`).
- Top-level: `CMakeLists.txt`, `CMakePresets.json`, `build_cmd.ps1`, `.editorconfig`.

## Build, Test, and Development Commands
- Configure (Windows/Clang preset): `cmake --preset x64-Clang-Release`
- Build all: `cmake --build out/build/x64-Clang-Release -j`
- One-shot staged helper (recommended on Windows): `./build_cmd.ps1 -Stage all`  
  Stages: `configure`, `codegen` (PPC), `genlist`, `lib`, `app`. Example: `./build_cmd.ps1 -Stage app`.
- Clean generated PPC sources: `./build_cmd.ps1 -Clean -Stage codegen`
- Linux/macOS: use `linux-*` or `macos-*` presets from `CMakePresets.json` (generator: Ninja).

Notes
- vcpkg is vendored under `thirdparty/vcpkg` (presets set `VCPKG_ROOT`).
- Provide a valid `MW05_XEX` when configuring locally; no game assets are tracked.

## Coding Style & Naming Conventions
- Follow `.editorconfig`: UTF-8, LF newlines, 4-space indentation.
- C++ style: PascalCase for types and methods (`GameWindow::SetTitle()`), `s_` prefix for statics, camelCase for fields.
- Prefer self-contained headers, minimal global state, and clear module boundaries (e.g., `ui/`, `patches/`, `kernel/`).

## Testing Guidelines
- No formal unit tests are present. Validate by building `Mw05Recomp` and running through installer and main menus.
- Keep changes testable: add small entry points or assertions behind debug defines when needed.
- If adding tests, mirror folder layout under a `tests/` tree and integrate via CMake optional targets.

## Commit & Pull Request Guidelines
- Commit messages: short, imperative summaries (e.g., "gpu: fix video init", "build: pin SDL").
- PRs must include: concise description, rationale, affected modules, and platform(s) tested. Add screenshots for UI/visual changes.
- Reference issues (e.g., `Fixes #123`). Avoid committing generated files, binaries, or game assets.

## Security & Configuration Tips
- Do not add proprietary game data to the repo or PRs.
- Keep toolchain paths out of code; prefer presets and `build_cmd.ps1` parameters.
- Run `update_submodules.bat` and vendor deps as pinned; avoid ad-hoc version bumps without justification.

