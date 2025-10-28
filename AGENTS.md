# MW05 Recompilation Project - AI Agent Guidelines

**Project**: Mw05Recomp - Xbox 360 NFS: Most Wanted recompilation to x64 with D3D12/Vulkan backend

**MCP servers** available: Context 7, Sequebtial thinking, Redis

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
- **⚠️ GAME ASSETS**: Located at `out/build/x64-Clang-Debug/Mw05Recomp/game/` (NOT in repo root `game/`)
  - Contains GLOBAL/, CARS/, TRACKS/, Movies/, SOUND/, etc.
  - Game executable runs from `out/build/x64-Clang-Debug/Mw05Recomp/` directory
  - All file paths are relative to the build output directory

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

### IDA Pro API Usage (Port 5050)

**Available Endpoints**:
- `/decompile?ea=<address>` - Decompile function at address
- `/disasm?ea=<address>&count=<count>` - Disassemble instructions
- `/functions?mode=<fast|full>&filter=<regex>&limit=<n>` - List functions

**Examples**:

```powershell
# Decompile a function
$response = Invoke-WebRequest -Uri "http://127.0.0.1:5050/decompile?ea=0x82598A20" -UseBasicParsing
$response.Content | Out-File "traces/ida_sub_82598A20_decomp.txt" -Encoding utf8

# Disassemble 20 instructions
$response = Invoke-WebRequest -Uri "http://127.0.0.1:5050/disasm?ea=0x828AA03C&count=20" -UseBasicParsing
$response.Content

# List functions (fast mode - no xrefs)
$response = Invoke-WebRequest -Uri "http://127.0.0.1:5050/functions?limit=100" -UseBasicParsing
$data = $response.Content | ConvertFrom-Json
$data.functions | Format-Table name, start_ea -AutoSize

# Filter functions by keyword
$response = Invoke-WebRequest -Uri "http://127.0.0.1:5050/functions?filter=render|draw|swap&limit=50" -UseBasicParsing
$data = $response.Content | ConvertFrom-Json
$data.functions | Format-Table name, start_ea -AutoSize

# Full mode with xref counts (slower)
$response = Invoke-WebRequest -Uri "http://127.0.0.1:5050/functions?mode=full&filter=vdswap&limit=10" -UseBasicParsing
$data = $response.Content | ConvertFrom-Json
$data.functions | Format-Table name, xrefs_to, start_ea -AutoSize
```

### Redis MCP Usage

**IMPORTANT**: Redis MCP is available for storing research findings, debugging state, and cross-session data.

```powershell
# Store research findings
hset_Redis -name "mw05:issue_name" -key "root_cause" -value "Description of root cause"
hset_Redis -name "mw05:issue_name" -key "solution" -value "Description of solution"

# Retrieve findings
hget_Redis -name "mw05:issue_name" -key "root_cause"

# Get all data for an issue
hgetall_Redis -name "mw05:issue_name"

# Store vectors/embeddings
set_vector_in_hash_Redis -name "mw05:function_analysis" -vector @(0.1, 0.2, 0.3, ...)

# Store JSON data
json_set_Redis -name "mw05:config" -path "$.render_settings" -value @{draws=0; pm4_active=$true}
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

### ✅ VdSwap Fixed - Signature Mismatch (2025-10-28)
- **Problem**: VdSwap was never called, causing zero draw commands
- **Root Cause**: VdSwap signature mismatch - function was defined with 3 parameters but game calls it with 8 parameters (r3-r10)
- **IDA Decompilation**: Game calls VdSwap with 8 parameters:
  - r3: command buffer write cursor
  - r4: swap params pointer
  - r5: GPU ring buffer base
  - r6: system command buffer address
  - r7: system command buffer size
  - r8-r10: surface/format/flags pointers
- **Fix Applied**:
  1. Updated VdSwap signature to accept 8 parameters
  2. Manually extracted parameters from PPC registers (r3-r10) instead of using `HostToGuestFunction` template
  3. VdSwap now being called successfully
- **Current Status**: VdSwap is working, but game is NOT issuing draw commands yet (still in initialization phase)

### ✅ PM4 Buffer System FIXED (2025-10-28)
- **Problem**: Game was not writing PM4 commands to buffers (all zeros)
- **Root Cause Analysis**:
  - `sub_82595FC8` is a game-side PM4 buffer space allocator (NOT VdGetSystemCommandBuffer!)
  - `VdGetSystemCommandBuffer` is a separate kernel function that takes two output pointers
  - The game manages its own PM4 command buffers independently from the system command buffer
  - Attempting to override these functions caused conflicts with game's buffer management
- **Fix Applied**:
  1. Removed custom overrides of `sub_82595FC8` and `sub_825972B0`
  2. Let the original recompiled functions handle PM4 buffer management
  3. Game initializes its own GPU context structures correctly
- **Result**:
  - Buffer system working correctly with no memory leaks
  - Game writing **1.2 million TYPE3 PM4 packets**
  - VdSwap called successfully
  - PM4 scanner processing commands correctly
  - Memory usage stable (no growth)
- **Current Status**: Buffer system FIXED! Game writing PM4 commands. Still `draws=0` - game is in initialization phase writing context updates (opcode 0x3E). Need to investigate why game hasn't progressed to rendering stage yet.

### ✅ Memory Leak in Buffer Initialization FIXED (2025-10-28)
- **Problem**: Physical heap growing 2-5 MB/second, 145 MB leaked in 30 seconds
- **Root Cause**: GPU context initialization check was flawed
  - After game writes PM4 commands, it updates `write_ptr` (gpu_ctx[0])
  - Code checked if `write_ptr == base_ptr` to determine if initialized
  - Since game updates write_ptr after writing, this check always failed
  - Result: Re-initialized GPU context on EVERY call (580 times instead of once)
  - Each initialization allocated 256KB → 580 × 256KB = **145 MB leaked**
- **Fix Applied**:
  - Use `static std::unordered_set<uint32_t>` to track initialized GPU context addresses
  - Only initialize each unique GPU context address once
  - Check if game already initialized the context (valid base_ptr and end_ptr)
- **Result**:
  - **580 initializations → 4 initializations** (one per unique GPU context)
  - **145 MB leak → 1 MB total** (4 contexts × 256KB each)
  - Memory usage stable, no more growth

## 📚 Additional Documentation
- **Full debugging history**: `docs/research/AGENTS_ARCHIVE.md` (moved from AGENTS.md)
- **Research notes**: `docs/research/*.md`
- **Build system**: `CMakePresets.json`, `build_cmd.ps1`

