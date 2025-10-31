# MW05 Recompilation Project - AI Agent Guidelines

**Project**: Mw05Recomp - Xbox 360 NFS: Most Wanted recompilation to x64 with D3D12/Vulkan backend

**MCP servers** available: Desktop Commander, Context 7, Sequential thinking, Redis

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
- Uses Xenia's BaseHeap allocator (page-based with metadata in host memory)
- **NEVER** allocate below 0x100000 (causes heap corruption)

### 5. **Debugging Tools**
- **IDA Pro API**: `http://127.0.0.1:5050/decompile?ea=<address>`
- **Trace logs**: `traces/auto_test_stderr.txt`, `traces/auto_test_stdout.txt`
- **Memory stats**: Search logs for `Physical heap usage` and `User heap`
- **Environment Variables**: See section below for complete list of debugging flags

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

### ✅ Heap Corruption FIXED (2025-10-31)
- **Problem**: Heap corruption after 5-60 seconds, growing from 8 MB to 2030+ MB
- **Cause**: Game writing to guest addresses that corrupted heap metadata stored in guest memory
- **Fix**: Migrated from o1heap to Xenia's BaseHeap with page table in HOST memory
- **Result**: 99.85% reduction in heap usage (2030 MB → 3 MB stable), game runs 120+ seconds without crashes

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

## 🐛 Environment Variables for Debugging

**Note**: Most debugging features are **disabled by default** for performance. Enable them by setting environment variables to `"1"`.

### Core Debug Logging (Default: MINIMAL)
```powershell
$env:MW05_DEBUG_GRAPHICS = "1"   # Graphics subsystem logging
$env:MW05_DEBUG_KERNEL = "1"     # Kernel operations logging
$env:MW05_DEBUG_THREAD = "1"     # Thread operation logging
$env:MW05_DEBUG_HEAP = "1"       # Memory allocation logging
$env:MW05_DEBUG_FILEIO = "1"     # File I/O operations logging
$env:MW05_DEBUG_PM4 = "1"        # PM4 command buffer logging
$env:MW05_DEBUG_ISR = "1"        # Interrupt Service Routine logging
$env:MW05_DEBUG_VBLANK = "1"     # VBlank pump logging (PERFORMANCE: disabled by default)
$env:MW05_DEBUG_WAIT = "1"       # Wait function logging
$env:MW05_DEBUG_PROFILE = "0"    # Disable debug profile (enabled by default)
```

### Boot & Initialization
```powershell
$env:MW05_FAST_BOOT = "1"                    # Skip slow initialization steps
$env:MW05_BREAK_82813514 = "1"               # Breakpoint at specific address
$env:MW05_BREAK_CRT_INIT = "1"               # Breakpoint at CRT initialization
$env:MW05_BREAK_8262DD80 = "1"               # Breakpoint at specific function
$env:MW05_BREAK_8262DD80_MAX_ITER = "100"    # Max iterations before break
$env:MW05_FAST_RET = "1"                     # Fast return from certain functions
$env:MW05_SKIP_825A8698_BUG = "1"            # Skip buggy CreateDevice function
$env:MW05_SKIP_828508A8_BUG = "1"            # Skip buggy function
```

### Thread & Synchronization
```powershell
$env:MW05_SET_FLAG_FROM_SLEEP = "1"          # Set flag from sleep function
$env:MW05_KICK_VIDEO = "1"                   # Kick video thread
$env:MW05_FORCE_VD_INIT = "1"                # Force video device initialization
$env:MW05_UNBLOCK_MAIN = "1"                 # Unblock main thread (AVOID: overrides game behavior)
$env:MW05_FORCE_INIT_CALLBACK_PARAM = "1"    # Force initialization callback parameter
$env:MW05_FORCE_RENDER_THREADS = "1"         # Force render thread creation
$env:MW05_DEEP_DEBUG = "1"                   # Enable deep debugging
$env:MW05_FORCE_SLEEP_CALL = "1"             # Force sleep call
$env:MW05_FORCE_SLEEP_FLAG = "1"             # Force sleep flag
$env:MW05_BREAK_WAIT_LOOP = "1"              # Break wait loop
$env:MW05_RENDER_THREAD_ENTRY = "0x12345678" # Render thread entry point address
$env:MW05_RENDER_THREAD_CTX = "0x12345678"   # Render thread context address
```

### Graphics & Rendering
```powershell
$env:MW05_DRAW_DIAGNOSTIC = "1"              # Draw diagnostic overlay
$env:MW05_PM4_SCAN_FULL = "1"                # Full PM4 command buffer scan
$env:MW05_PM4_APPLY_STATE = "1"              # Apply PM4 state changes
$env:MW05_MICRO_TREE = "1"                   # Micro instruction tree
$env:MW05_DUMP_SYSBUF = "1"                  # Dump system buffer
$env:MW05_TITLE_STATE_TRACE = "1"            # Title state tracing
$env:MW05_TRACE_GFX_CALLBACK = "1"           # Graphics callback tracing
$env:MW05_VD_ISR_SWAP_AT_ENTRY = "1"         # VD ISR swap at entry
$env:MW05_VD_ISR_FORCE_R3 = "1"              # Force R3 register value
$env:MW05_SCHED_R3_EA = "0x12345678"         # Scheduler R3 effective address
$env:MW05_SET_PRESENT_CB = "1"               # Set present callback (default: enabled)
$env:MW05_PM4_DUMP_AFTER_BUILDER = "1"       # Dump PM4 after builder
$env:MW05_PM4_SCAN_AFTER_BUILDER = "1"       # Scan PM4 after builder
$env:MW05_FORCE_MICROIB = "1"                # Force micro instruction buffer
$env:MW05_TRY_BUILDER_WITH_SEH = "1"         # Try builder with SEH
$env:MW05_PRESENT_STUB = "1"                 # Present stub
```

### PM4 Command Buffer Analysis
```powershell
$env:MW05_PM4_TRACE_INTERESTING = "1"        # Trace interesting PM4 commands
$env:MW05_PM4_LOG_NONZERO = "1"              # Log non-zero PM4 values
$env:MW05_PM4_EMIT_DRAWS = "1"               # Emit draw commands
$env:MW05_PM4_TRACE = "1"                    # PM4 command tracing
$env:MW05_TRACE_KERNEL = "1"                 # Kernel tracing
$env:MW05_PM4_SNOOP = "1"                    # PM4 command snooping
$env:MW05_PM4_ARM_RING_SCRATCH = "1"         # Arm ring scratch buffer
$env:MW05_PM4_SCAN_WIDER = "1"               # Wider PM4 scan
$env:MW05_FORCE_ACK_WAIT = "1"               # Force acknowledgment wait
$env:MW05_PM4_LOG_TYPE0 = "1"                # Log TYPE0 PM4 packets
$env:MW05_PM4_TRACE_REGS = "1"               # Trace PM4 register writes
$env:MW05_PM4_TRACE_REG_BUDGET = "1000"      # Register trace budget
$env:MW05_PM4_EAGER_SCAN = "1"               # Eager PM4 scanning
$env:MW05_PM4_SCAN_ALL = "1"                 # Scan all PM4 commands
$env:MW05_PM4_SCAN_RING = "1"                # Scan PM4 ring buffer
$env:MW05_PM4_SYSBUF_TO_RING = "1"           # Copy system buffer to ring
$env:MW05_PM4_BYPASS_WAITS = "1"             # Bypass PM4 wait commands
$env:MW05_PM4_PROBE_ON_PRESENT = "1"         # Probe PM4 on present
$env:MW05_PM4_SYSBUF_SCAN = "1"              # Scan system buffer
$env:MW05_PM4_FORCE_SYSBUF_SCAN = "1"        # Force system buffer scan
$env:MW05_PM4_SCAN_BLK13 = "1"               # Scan block 13
$env:MW05_PM4_MICRO_SCAN = "1"               # Micro PM4 scan
$env:MW05_PM4_DUMP_MICRO = "1"               # Dump micro PM4 commands
```

### Video Device (VD) Control
```powershell
$env:MW05_FAKE_VDSWAP = "1"                  # Fake VdSwap calls
$env:MW05_TV_STATIC = "1"                    # TV static effect
$env:MW05_ALWAYS_ON_OVERLAY = "1"            # Always-on overlay
$env:MW05_FORCE_PM4_BUILDER_ONCE = "1"       # Force PM4 builder once
$env:MW05_VBLANK_CB = "1"                    # VBlank callback
$env:MW05_FORCE_PRESENT = "1"                # Force present calls
$env:MW05_FORCE_PRESENT_BG = "1"             # Force present in background
$env:MW05_BRINGUP_NONBLACK_CLEAR = "1"       # Non-black clear color
$env:MW05_VD_ISR_CTX_SCHED = "1"             # VD ISR context scheduling
$env:MW05_VD_ISR_CTX_SCHED_DELAY_TICKS = "10" # VD ISR scheduling delay
$env:MW05_VD_ISR_CTX_SEEN_MIN = "5"          # Minimum VD ISR context seen count
$env:MW05_ISR_AUTO_PRESENT = "1"             # Auto present in ISR
$env:MW05_HOST_ISR_RB_STEP = "1"             # Host ISR ring buffer step
$env:MW05_ISR_TRY_BUILDER = "1"              # Try PM4 builder in ISR
$env:MW05_HOST_ISR_ACK_EVENT = "1"           # Host ISR acknowledge event
$env:MW05_HOST_ISR_SCHED_CLEAR = "1"         # Host ISR scheduler clear
$env:MW05_HOST_ISR_SIGNAL_VD_EVENT = "1"     # Host ISR signal VD event
$env:MW05_PULSE_E0DD0 = "1"                  # Pulse event at 0xE0DD0
$env:MW05_HOST_ISR_FORCE_SIGNAL_LAST_WAIT = "1" # Force signal last wait
$env:MW05_HOST_ISR_TRACE_LAST_WAIT = "1"     # Trace last wait
$env:MW05_HOST_ISR_NUDGE_ONCE = "1"          # Nudge ISR once
$env:MW05_HOST_ISR_NUDGE_AFTER = "100"       # Nudge ISR after N ticks
$env:MW05_HOST_ISR_TICK_SYSID = "1"          # Tick system ID in ISR
$env:MW05_HOST_ISR_NOTIFY_SRC_SEQ = "1"      # Notify source sequence
```

### VBlank & Present Control
```powershell
$env:MW05_VBLANK_PUMP = "1"                  # VBlank pump
$env:MW05_PUMP_EVENTS = "1"                  # Pump events
$env:MW05_SIGNAL_WAKE_EVENT = "1"            # Signal wake event
$env:MW05_GFX_CALLBACK_FREQUENCY = "60"      # Graphics callback frequency (Hz)
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "1000" # Max callback invocations
$env:MW05_FORCE_VIDEO_THREAD = "1"           # Force video thread
$env:MW05_FORCE_VIDEO_THREAD_TICK = "1"      # Force video thread tick
$env:MW05_TRY_CALL_82548F18 = "1"            # Try calling specific function
$env:MW05_FORCE_VIDEO_WORK_FLAG = "1"        # Force video work flag
$env:MW05_ISR_GRACE_TICKS = "10"             # ISR grace period ticks
$env:MW05_PM4_SYSBUF_WATCH = "1"             # Watch system buffer
$env:MW05_PM4_SYSBUF_WATCH_VERBOSE = "1"     # Verbose system buffer watch
$env:MW05_VBLANK_CB_FORCE = "1"              # Force VBlank callback
$env:MW05_DEFAULT_VD_ISR = "1"               # Default VD ISR
$env:MW05_GUEST_ISR_DELAY_TICKS = "10"       # Guest ISR delay ticks
$env:MW05_PRESENT_HEARTBEAT_MS = "16"        # Present heartbeat (ms)
$env:MW05_VBLANK_VDSWAP = "1"                # VBlank VdSwap
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "1"   # Force present wrapper once
$env:MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS = "10" # Present wrapper delay
$env:MW05_DUMP_SCHED_CTX = "1"               # Dump scheduler context
$env:MW05_FORCE_PRESENT_INNER = "1"          # Force present inner
$env:MW05_FPW_KICK_PM4 = "1"                 # Force present wrapper kick PM4
$env:MW05_FPW_POST_SYSBUF = "1"              # Force present wrapper post sysbuf
$env:MW05_PM4_SCAN_ON_FPW_POST = "1"         # Scan PM4 on FPW post
$env:MW05_FPW_RETRIES = "3"                  # Force present wrapper retries
$env:MW05_FPW_RETRY_TICKS = "10"             # Force present wrapper retry ticks
```

### VD Register Control
```powershell
$env:MW05_VD_POLL_DIAG = "1"                 # VD poll diagnostic
$env:MW05_VD_POKE_E58 = "0x12345678"         # Poke VD register E58
$env:MW05_VD_POKE_E68 = "0x12345678"         # Poke VD register E68
$env:MW05_VD_POKE_E70 = "0x12345678"         # Poke VD register E70
$env:MW05_VD_TICK_E70 = "1"                  # Tick VD register E70
$env:MW05_VD_TOGGLE_E68 = "1"                # Toggle VD register E68
$env:MW05_VD_TOGGLE_E58 = "1"                # Toggle VD register E58
$env:MW05_VD_TOGGLE_E58_MASK = "0xFFFF"      # VD E58 toggle mask
$env:MW05_VD_E68_HANDSHAKE = "1"             # VD E68 handshake
$env:MW05_VD_E68_ACK_PULSE = "1"             # VD E68 acknowledge pulse
$env:MW05_VD_E48_LOW16_FORCE = "0x1234"      # Force VD E48 low 16 bits
$env:MW05_VD_E58_MIRROR_E60_HI = "1"         # Mirror VD E60 high to E58
$env:MW05_VD_E58_LOW16_FORCE = "0x1234"      # Force VD E58 low 16 bits
$env:MW05_VD_READ_TRACE = "1"                # Trace VD reads
```

### PM4 Swap Detection
```powershell
$env:MW05_PM4_FAKE_SWAP = "1"                # Fake PM4 swap
$env:MW05_PM4_FAKE_SWAP_ADDR = "0x12345678"  # Fake swap address
$env:MW05_PM4_FAKE_SWAP_OR = "0x1234"        # Fake swap OR mask
$env:MW05_PM4_FAKE_SWAP2_ADDR = "0x12345678" # Fake swap 2 address
$env:MW05_PM4_FAKE_SWAP2_OR = "0x1234"       # Fake swap 2 OR mask
$env:MW05_PM4_FAKE_SWAP_TOKEN_ADDR = "0x12345678" # Fake swap token address
$env:MW05_PM4_FAKE_SWAP_TOKEN_BASE = "0x1000" # Fake swap token base
$env:MW05_PM4_FAKE_SWAP_TOKEN_INC = "1"      # Fake swap token increment
$env:MW05_VD_TOKEN_ON_FLIP = "1"             # VD token on flip
$env:MW05_SYNTH_VDSWAP_ON_FLIP = "1"         # Synthesize VdSwap on flip
$env:MW05_PM4_SWAP_DETECT = "1"              # PM4 swap detection
$env:MW05_PM4_SWAP_DETECT_MASK = "0xFFFF"    # PM4 swap detection mask
$env:MW05_PM4_SWAP_PRESENT = "1"             # PM4 swap present
$env:MW05_AUTO_VDSWAP_HEUR = "1"             # Auto VdSwap heuristic
$env:MW05_AUTO_VDSWAP_HEUR_ONCE = "1"        # Auto VdSwap heuristic once
$env:MW05_AUTO_VDSWAP_HEUR_DELAY = "10"      # Auto VdSwap heuristic delay
$env:MW05_AUTO_VDSWAP_HEUR_E58_MASK = "0xFFFF" # Auto VdSwap E58 mask
$env:MW05_AUTO_VDSWAP_HEUR_E68_MASK = "0xFFFF" # Auto VdSwap E68 mask
$env:MW05_PM4_FAKE_SWAP_TAIL = "1"           # Fake swap tail
$env:MW05_FORCE_VDSWAP_ONCE = "1"            # Force VdSwap once
```

### Event & Synchronization Control
```powershell
$env:MW05_PULSE_VD_EVENT_ON_SLEEP = "1"      # Pulse VD event on sleep
$env:MW05_ZERO_EVENT_PTR_AFTER_ACK = "1"     # Zero event pointer after ack
$env:MW05_ZERO_EVENT_STATUS_AFTER_ACK = "1"  # Zero event status after ack
$env:MW05_FORCE_VD_EVENT_EA = "0x12345678"   # Force VD event effective address
$env:MW05_AUTO_VIDEO = "1"                   # Auto video
$env:MW05_DUMP_SCHED_BLOCK = "1"             # Dump scheduler block
$env:MW05_ACK_FROM_EVENT_FIELD = "1"         # Acknowledge from event field
$env:MW05_CLEAR_SCHED_BLOCK = "1"            # Clear scheduler block
$env:MW05_FORCE_VD_ISR = "1"                 # Force VD ISR
$env:MW05_ALLOW_FIRMWARE_RETURN = "1"        # Allow firmware return
$env:MW05_ALLOW_BUGCHECK = "1"               # Allow bugcheck
```

### Graphics Callbacks & Notifications
```powershell
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"          # Force graphics notify callback
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "10" # Graphics notify delay
$env:MW05_FORCE_GFX_NOTIFY_CB_EA = "0x12345678" # Graphics notify callback address
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x12345678" # Graphics notify context
$env:MW05_FORCE_GFX_NOTIFY_CB_IMMEDIATE = "1" # Immediate graphics notify
$env:MW05_FORCE_CALL_CREATEDEVICE = "1"      # Force CreateDevice call
$env:MW05_FORCE_CREATEDEVICE_DELAY_TICKS = "10" # CreateDevice delay
$env:MW05_FORCE_CALL_CREATE_RENDER_THREAD = "1" # Force create render thread
$env:MW05_FORCE_CREATE_RENDER_THREAD_DELAY_TICKS = "10" # Render thread delay
$env:MW05_FORCE_PRESENT_FLAG = "1"           # Force present flag
$env:MW05_NOTIFY_IMMEDIATE = "1"             # Immediate notification
$env:MW05_INJECT_VD_CALLBACK = "1"           # Inject VD callback
$env:MW05_MONITOR_GFX_CONTEXT = "1"          # Monitor graphics context
$env:MW05_FORCE_PRESENT_ON_ZERO = "1"        # Force present on zero
$env:MW05_FORCE_PRESENT_EVERY_ZERO = "1"     # Force present every zero
$env:MW05_FORCE_PRESENT_ON_FIRST_ZERO = "1"  # Force present on first zero
$env:MW05_SET_RENDER_FLAG = "1"              # Set render flag
$env:MW05_RENDER_FLAG_ADDR = "0x12345678"    # Render flag address
$env:MW05_ISR_CALL_PRESENT = "1"             # ISR call present
$env:MW05_ISR_PRESENT_INTERVAL = "60"        # ISR present interval
```

### Tracing & Logging
```powershell
$env:MW05_TRACE_LOADER_ARGS = "1"            # Trace loader arguments
$env:MW05_LIST_SHIMS = "1"                   # List shim functions
$env:MW05_LOG_DBG_BREAK = "1"                # Log debug breaks
$env:MW05_FILE_LOG = "1"                     # File I/O logging
$env:MW05_HOST_TRACE_FILE = "path/to/file"   # Host trace file path
$env:MW05_TRACE_RB_WRITES = "1"              # Trace ring buffer writes
$env:MW05_TRACE_MMIO = "1"                   # Trace MMIO operations
$env:MW05_LOG_FILE = "path/to/file"          # Log file path
$env:MW05_LOG_CONSOLE = "1"                  # Log to console
```

### Advanced/Experimental
```powershell
$env:MW05_DISABLE_OVERRIDES = "1"            # Disable manual overrides
$env:MW05_RUNTIME_PATCHES = "1"              # Enable runtime patches
$env:MW05_GAME_PATH = "path/to/game"         # Game assets path
$env:MW05_MODULE_PATH = "path/to/module"     # Module path
$env:MW05_FAKE_NOTIFY = "1"                  # Fake XAM notifications
$env:MW05_ALLOW_FLAG_CLEAR_AFTER_MS = "1000" # Allow flag clear after ms
$env:MW05_INNER_TRY_PM4 = "1"                # Inner try PM4
$env:MW05_INNER_TRY_PM4_DEEP = "1"           # Inner try PM4 deep
$env:MW05_LOOP_TRY_PM4_PRE = "1"             # Loop try PM4 pre
$env:MW05_LOOP_TRY_PM4 = "1"                 # Loop try PM4
$env:MW05_LOOP_TRY_PM4_DEEP = "1"            # Loop try PM4 deep
```

### Usage Examples

**Basic debugging session**:
```powershell
# Enable core logging
$env:MW05_DEBUG_HEAP = "1"
$env:MW05_DEBUG_THREAD = "1"
$env:MW05_DEBUG_ISR = "1"
$env:MW05_DEBUG_VBLANK = "1"

# Run game
.\build_cmd.ps1 -Stage app
python scripts/auto_handle_messageboxes.py --duration 30
```

**PM4 command buffer analysis**:
```powershell
# Enable PM4 tracing
$env:MW05_PM4_TRACE = "1"
$env:MW05_PM4_SCAN_FULL = "1"
$env:MW05_PM4_EMIT_DRAWS = "1"
$env:MW05_PM4_SYSBUF_SCAN = "1"

# Run game
.\build_cmd.ps1 -Stage app
python scripts/auto_handle_messageboxes.py --duration 30
```

**Graphics rendering debug**:
```powershell
# Enable graphics debugging
$env:MW05_DRAW_DIAGNOSTIC = "1"
$env:MW05_TRACE_GFX_CALLBACK = "1"
$env:MW05_MONITOR_GFX_CONTEXT = "1"
$env:MW05_FORCE_PRESENT = "1"

# Run game
.\build_cmd.ps1 -Stage app
python scripts/auto_handle_messageboxes.py --duration 30
```

## 📚 Additional Documentation
- **Full debugging history**: `docs/research/AGENTS_ARCHIVE.md` (moved from AGENTS.md)
- **Research notes**: `docs/research/*.md`
- **Build system**: `CMakePresets.json`, `build_cmd.ps1`

