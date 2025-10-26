# MW05 Recompilation Project - AI Agent Guidelines

**Project**: Mw05Recomp - Xbox 360 NFS: Most Wanted recompilation to x64 with D3D12/Vulkan backend

## 🎯 CRITICAL RULES FOR AI AGENTS

### 1. **PPC Function Override Pattern** (MEMORY LEAK FIX - 2025-10-26)
**⚠️ CRITICAL**: Always use the correct `PPC_FUNC_IMPL` + `PPC_FUNC` pattern for overriding recompiled functions!

**✅ CORRECT Pattern**:
```cpp
PPC_FUNC_IMPL(__imp__sub_XXXXXXXX);
PPC_FUNC(sub_XXXXXXXX)
{
    // function body
}
```

**❌ WRONG Patterns** (cause 15-20 GB memory leaks!):
```cpp
// WRONG #1: Regular function definition
void sub_XXXXXXXX(PPCContext& ctx, uint8_t* base) { ... }

// WRONG #2: Missing PPC_FUNC_IMPL
PPC_FUNC(sub_XXXXXXXX) { ... }

// WRONG #3: Forward declaration instead of PPC_FUNC_IMPL
extern "C" void __imp__sub_XXXXXXXX(PPCContext& ctx, uint8_t* base);
```

**Why This Matters**:
- Using regular function definitions instead of `PPC_FUNC` causes the linker to create duplicate symbols
- This leads to catastrophic memory leaks (15-20 GB working set instead of 1.7 GB)
- **Files to check**: `Mw05Recomp/cpu/*_shims.cpp`, `Mw05Recomp/kernel/imports.cpp`

### 2. **Build System**
- **Build command**: `.\build_cmd.ps1 -Stage app` (NOT direct CMake commands)
- **Test command**: `python scripts/auto_handle_messageboxes.py --duration 30`
- **Kill processes**: Always kill `Mw05Recomp.exe` before building: `taskkill /F /IM Mw05Recomp.exe`
- **TOML file**: `Mw05RecompLib/config/MW05.toml` (NOT `tools/XenonRecomp/resources/mw05_recomp.toml`)

### 3. **Never Edit Generated Code**
- **NEVER** edit files in `Mw05RecompLib/ppc/` - these are auto-generated
- Use shims/wrappers in `Mw05Recomp/cpu/*_shims.cpp` instead
- Fix recompiler bugs in `tools/XenonRecomp/` if needed

### 4. **Memory Management**
- User heap: 0x00100000-0x7FEA0000 (1 MB start to avoid NULL pointer corruption)
- Physical heap: 0xA0000000-0x100000000 (2.5 GB-4 GB)
- **NEVER** allocate below 0x100000 (causes o1heap corruption)

### 5. **Debugging Tools**
- **IDA Pro API**: `http://127.0.0.1:5050/decompile?ea=<address>`
- **Trace logs**: `traces/auto_test_stderr.txt`, `traces/auto_test_stdout.txt`
- **Memory stats**: Search logs for `Physical heap usage` and `User heap`

### 6. **File Organization**
- **Traces/logs**: `traces/` directory
- **Research docs**: `docs/research/` directory (move old AGENTS.md content here)
- **IDA dumps**: `IDA_dumps/` directory
- **Build output**: `out/build/x64-Clang-Debug/`

## 📁 Project Structure
- `Mw05Recomp/`: Application code (ui/, gpu/, apu/, kernel/, cpu/)
- `Mw05RecompLib/`: Recompiled game library + generated PPC sources
- `tools/XenonRecomp/`: PPC-to-x64 recompiler
- `thirdparty/`: Dependencies (vcpkg, SDL, etc.)
- `scripts/`: Helper scripts for testing/debugging

## 🔧 Common Tasks

### Build and Test
```powershell
# Kill existing processes
taskkill /F /IM Mw05Recomp.exe

# Build
.\build_cmd.ps1 -Stage app

# Test (30 second run)
python scripts/auto_handle_messageboxes.py --duration 30
```

### Check Memory Usage
```powershell
# Check heap stats in logs
Get-Content traces/auto_test_stderr.txt | Select-String -Pattern "Physical heap usage|User heap"

# Expected: ~1.7 GB working set, ~360 MB physical heap
```

### Find Function Calls
```powershell
# Search for function calls in logs
Get-Content traces/auto_test_stderr.txt | Select-String -Pattern "sub_XXXXXXXX"
```

## 🚨 Known Issues & Fixes

### ✅ Memory Leak FIXED (2025-10-26)
- **Problem**: 15-20 GB working set, 18+ GB peak
- **Cause**: Improper PPC function override patterns
- **Fix**: Use `PPC_FUNC_IMPL` + `PPC_FUNC` pattern (see Rule #1)
- **Result**: 1.76 GB working set, 90% reduction

### ✅ Heap Corruption FIXED (2025-10-22)
- **Problem**: o1heap corruption after 5-60 seconds
- **Cause**: NULL pointer writes to low memory addresses
- **Fix**: Moved heap start from 0x20000 to 0x100000
- **Result**: Game runs 120+ seconds without crashes

### ❌ No Rendering Yet (draws=0)
- Game initializes correctly but doesn't issue draw commands
- All systems operational (threads, PM4, VBLANK, file I/O)
- Investigation ongoing - see `docs/research/` for details

## 📚 Additional Documentation
- **Full debugging history**: `docs/research/AGENTS_ARCHIVE.md` (moved from AGENTS.md)
- **Research notes**: `docs/research/*.md`
- **Build system**: `CMakePresets.json`, `build_cmd.ps1`

