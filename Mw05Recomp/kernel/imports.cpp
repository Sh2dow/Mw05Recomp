#include <stdafx.h>
#include <cpu/ppc_context.h>
#include <cpu/guest_thread.h>
#include <ppc/ppc_context.h>

#include <apu/audio.h>
#include "function.h"
#include "xex.h"
#include "xbox.h"
#include "heap.h"
#include "memory.h"
#include "debug_verbosity.h"
// REMOVED: #include "vm_arena.h" - not using VmArena anymore (like UnleashedRecomp)
#include <memory>
#include <map>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include "xam.h"
#include "xdm.h"
#include <user/config.h>
#include <ui/game_window.h>
#include <os/logger.h>
#include <gpu/video.h>
#include <gpu/pm4_parser.h>

// Forward decl: original guest MW05 present-wrapper body
extern "C" void __imp__sub_82598A20(PPCContext& ctx, uint8_t* base);

// Forward decl: MW05 graphics initialization function (calls VdInitializeEngines + VdSetGraphicsInterruptCallback)
extern "C" void __imp__sub_825A85E0(PPCContext& ctx, uint8_t* base);

// Forward decl: MW05 graphics initialization chain
extern "C" void __imp__sub_82216088(PPCContext& ctx, uint8_t* base);  // Entry point for graphics init

// Trace shim export: last-seen scheduler r3 (captured in mw05_trace_shims.cpp)
extern "C"
{
    uint32_t Mw05Trace_LastSchedR3();
    uint32_t Mw05Trace_SchedR3SeenCount();

    // Graphics context helper: get the heap-allocated graphics context address
    uint32_t Mw05GetGraphicsContextAddress();

    // Diagnostic forward decl for MW05 micro-interpreter
    void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size);

    // Memory helper: get the guest base pointer
    uint8_t* MmGetGuestBase();
}

#include "kernel/event.h"
#include "kernel/semaphore.h"
#include "kernel/handles.h"   // HandleTable, g_HandleTable, Handle type/Lookup
#include "kernel/apc.h"       // ApcPendingForCurrentThread()
#include "kernel/time.h"      // KeQuerySystemTime()

// ---- cross-SDK type shims (safe with/without Windows headers) ----
#include <cstdint>
#include <chrono>
#include <thread>
#include <algorithm>
#include <vector>
#include <cstring>  // for memset in VdQueryVideoMode
#include <cstdlib>   // std::getenv
#include <atomic>
#include <cctype>
#include <limits>
#include <string_view>
#include <kernel/xdm.h>

// Ensure the current OS thread has a valid guest PPCContext before calling into guest code.
static inline void EnsureGuestContextForThisThread(const char* tag = nullptr) {
    if (!GetPPCContext()) {
        static thread_local GuestThreadContext s_threadGuestCtx(0);
        KernelTraceHostOpF("HOST.GuestCtx.install tag=%s", tag ? tag : "");
    }
}

// APC queue per thread (moved here for use in NtReadFile)
struct ApcEntry {
    uint32_t routine;
    uint32_t context;
    uint32_t arg1;
    uint32_t arg2;
};

static std::mutex g_apcMutex;
static std::map<uint32_t, std::queue<ApcEntry>> g_apcQueues;  // threadId -> queue of APCs

static std::atomic<uint32_t> g_keSetEventGeneration;
static std::atomic<uint32_t> g_vdInterruptEventEA{0};
static std::atomic<bool> g_vdInterruptPending{false};
static std::atomic<uint32_t> g_lastWaitEventEA{0};
static std::atomic<uint32_t> g_lastWaitEventType{0};

static std::atomic<uint32_t> g_lastWaitKernelHandle{0};

static std::atomic<bool> g_vblankPumpRun{false};
static std::atomic<bool> g_sawRealVdSwap{false};

static std::atomic<bool> g_guestHasSwapped{false};
static std::atomic<uint32_t> g_vblankTicks{0};

static std::atomic<uint64_t> g_lastPresentMs{0};

extern "C"
{
    void Mw05NoteHostPresent(uint64_t ms)
    {
        g_lastPresentMs.store(ms, std::memory_order_release);
    }


    bool Mw05SawRealVdSwap() { return g_sawRealVdSwap.load(std::memory_order_acquire); }

    bool Mw05HasGuestSwapped() { return g_guestHasSwapped.load(std::memory_order_acquire); }

    uint32_t Mw05ConsumeSchedulerBlockEA();
    uint32_t Mw05GetSchedulerHandleEA();
    uint32_t Mw05GetSchedulerTimeoutEA();
    void Mw05ForceVdInitOnce();
    void Mw05LogIsrIfRegisteredOnce();
    void VdInitializeEngines(uint32_t callback_ea = 0, uint32_t arg1 = 0, uint32_t arg2 = 0, uint32_t arg3 = 0, uint32_t arg4 = 0);

    // Global variables for VdInitializeEngines callback workaround
    uint32_t g_vd_init_callback_ea = 0;
    uint32_t g_vd_init_callback_arg1 = 0;
    uint32_t g_vd_init_callback_arg2 = 0;
    uint32_t g_vd_init_callback_arg3 = 0;

    bool Mw05FastBootEnabled() {
        static const bool enabled = []() -> bool {
            if (const char* v = std::getenv("MW05_FAST_BOOT"))
                return !(v[0] == '0' && v[1] == '\0');

            return false;
        }();
        return enabled;
    }

    bool Mw05ListShimsEnabled() {
        static const bool enabled = []() -> bool {
            if (const char* v = std::getenv("MW05_LIST_SHIMS"))
                return !(v[0] == '0' && v[1] == '\0');
            return false;
        }();
        return enabled;
    }

    // put this near your other forward declarations, before first use
    void Mw05RegisterVdInterruptEvent(uint32_t eventEA, bool manualReset);

    // fwd-decls for helpers defined later in this file
    uint32_t VdGetSystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue);
    void VdInitializeRingBuffer(uint32_t base, uint32_t len_log2);
    void VdEnableRingBufferRPtrWriteBack(uint32_t base);
    void VdSetSystemCommandBufferGpuIdentifierAddress(uint32_t addr);
    void VdCallGraphicsNotificationRoutines(uint32_t source);
    void Mw05MarkGuestSwappedOnce();
    bool Mw05AnyPresentSeen();
}
// Forward decl: MW05 PM4 builder shim entry (defined in mw05_trace_shims.cpp) - removed


// Forward declarations for VD bridge helpers used across this file
void VdSetGraphicsInterruptCallback(uint32_t callback, uint32_t context);
void VdRegisterGraphicsNotificationRoutine(uint32_t callback, uint32_t context);
void VdInitializeEDRAM();
void VdInitializeEngines(uint32_t callback_ea, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);

// Forward declaration for PM4 system command buffer scanner (defined in gpu/pm4_parser.cpp)
void PM4_ScanSystemCommandBuffer();


#ifdef _WIN32
  #include <windows.h>
#endif

// NtDuplicateObject.cpp (fixed)
#include <cpu/guest_stack_var.h>   // CURRENT_THREAD_HANDLE
#include "ntstatus.h"           // STATUS_* codes

// Xbox 360-style signature you appear to use; adjust types/names if yours differ.
// Example signature — match yours.
// constants (adjust to your project's headers if they already exist)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER 0xC000000D
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE 0xC0000008
#endif

#ifndef DUPLICATE_CLOSE_SOURCE
#define DUPLICATE_CLOSE_SOURCE 0x00000001
#endif
#ifndef DUPLICATE_SAME_ACCESS
#define DUPLICATE_SAME_ACCESS  0x00000002
#endif

#ifndef NTSTATUS
  using NTSTATUS = long;
#endif
#ifndef STATUS_SUCCESS
  #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef BOOLEAN
  using BOOLEAN = unsigned char;
#endif
#ifndef _KPROCESSOR_MODE_DEFINED
  using KPROCESSOR_MODE = unsigned char;
  #define _KPROCESSOR_MODE_DEFINED
#endif

// Prefer SDK's LARGE_INTEGER if present
#ifndef PLARGE_INTEGER
  using PLARGE_INTEGER = LARGE_INTEGER*;
#endif

// ---- host fallbacks if your emulator helpers are missing ----
#ifndef HAVE_READ_GUEST_HELPERS
  // Define this macro in your build if you already have read_guest_i64/host_sleep.
  static inline int64_t read_guest_i64(const void* p) {
    if (!p) return 0;
    uint64_t raw = *reinterpret_cast<const uint64_t*>(p);
  #if defined(_MSC_VER)
    raw = _byteswap_uint64(raw);
  #else
    raw = __builtin_bswap64(raw);
  #endif
    return static_cast<int64_t>(raw);
  }
  static inline void host_sleep(int ms) {
    if (ms <= 0) std::this_thread::yield();
    else std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  }
#endif

// helpers
inline void HostSleepTiny() {
      // use whichever you prefer in your project
      host_sleep(0);
      // or: std::this_thread::yield();
  }

// helper (place near the top of the file with other helpers)
inline bool GuestOffsetInRange(uint32_t off, size_t bytes = 1) {
      if (off == 0) return false;
      if (off < 4096) return false; // guard page
      return (size_t)off + bytes <= PPC_MEMORY_SIZE;
  }

// Forward declaration for early calls in this file
uint32_t KeWaitForSingleObject(XDISPATCHER_HEADER* Object, uint32_t WaitReason, uint32_t WaitMode, bool Alertable, be<int64_t>* Timeout);

static std::atomic<uint32_t> g_RbWriteBackPtr{0};
static std::atomic<uint32_t> g_RbBase{0}, g_RbLen{0};

#ifndef FILE_SUPERSEDED
#define FILE_SUPERSEDED        0
// ---- Force-ack helpers for waits (opt-in via MW05_FORCE_ACK_WAIT) ----
static inline bool Mw05ForceAckWaitEnabled() {
    if (const char* v = std::getenv("MW05_FORCE_ACK_WAIT"))
        return !(v[0]=='0' && v[1]=='\0');
    return false;
}

static inline bool Mw05PulseVdOnSleepEnabled() {
    if (const char* v = std::getenv("MW05_PULSE_VD_EVENT_ON_SLEEP"))
        return !(v[0]=='0' && v[1]=='\0');
    // Auto-on when force-ack is enabled
    return Mw05ForceAckWaitEnabled();
}

static void Mw05ForceAckFromEventEA(uint32_t eventEA) {
    if (!eventEA || !GuestOffsetInRange(eventEA, sizeof(XDISPATCHER_HEADER))) return;
    if (!Mw05ForceAckWaitEnabled()) return;

    KernelTraceHostOpF("HOST.Wait.force_ack.begin ea=%08X", eventEA);

    uint32_t cleared_blockEA = 0;
    if (uint32_t blockEA = Mw05ConsumeSchedulerBlockEA()) {
        if (GuestOffsetInRange(blockEA + 8, sizeof(uint64_t))) {
            if (auto* block = reinterpret_cast<uint32_t*>(g_memory.Translate(blockEA))) {
                auto* fence64 = reinterpret_cast<uint64_t*>(block + 2);
                uint64_t before = fence64 ? *fence64 : 0;
                if (fence64) *fence64 = 0;
                KernelTraceHostOpF("HOST.Wait.force_ack.block ea=%08X before=%016llX",
                                   blockEA, static_cast<unsigned long long>(before));
                cleared_blockEA = blockEA;
            } else {
                KernelTraceHostOpF("HOST.Wait.force_ack.block ea=%08X (unmapped)", blockEA);
            }
        }
    }

    if (!cleared_blockEA) {
        const int32_t kProbeOffsets[] = { -8, -16, -24, -32 };
        for (int32_t off : kProbeOffsets) {
            const uint32_t probeEA = eventEA + off;
            if (!GuestOffsetInRange(probeEA, sizeof(uint64_t))) continue;
            const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(probeEA));
            if (!p) continue;
            uint64_t be_ptr64 = *reinterpret_cast<const uint64_t*>(p);
            #if defined(_MSC_VER)
            be_ptr64 = _byteswap_uint64(be_ptr64);
            #else
            be_ptr64 = __builtin_bswap64(be_ptr64);
            #endif
            const uint32_t blkEA = static_cast<uint32_t>(be_ptr64);
            if (!blkEA || !GuestOffsetInRange(blkEA + 8, sizeof(uint64_t))) continue;
            if (auto* blk = reinterpret_cast<uint32_t*>(g_memory.Translate(blkEA))) {
                auto* fence64 = reinterpret_cast<uint64_t*>(blk + 2);
                uint64_t before = fence64 ? *fence64 : 0;
                if (fence64) *fence64 = 0;
                KernelTraceHostOpF("HOST.Wait.force_ack.fallback block=%08X before=%016llX (off=%d)",
                                   blkEA, static_cast<unsigned long long>(before), (int)off);
                cleared_blockEA = blkEA;
                break;
            }
        }
    }

    if (cleared_blockEA) {
        if (const char* z = std::getenv("MW05_ZERO_EVENT_PTR_AFTER_ACK")) {
            if (!(z[0]=='0' && z[1]=='\0')) {
                if (GuestOffsetInRange(eventEA - 8, sizeof(uint64_t))) {
                    if (auto* p2 = static_cast<uint8_t*>(g_memory.Translate(eventEA - 8))) {
                        *reinterpret_cast<uint64_t*>(p2) = 0ull;
                        KernelTraceHostOpF("HOST.Wait.force_ack.ptr.zero ea=%08X", eventEA - 8);
                    }
                }
            }
        }
        if (const char* zs = std::getenv("MW05_ZERO_EVENT_STATUS_AFTER_ACK")) {
            if (!(zs[0]=='0' && zs[1]=='\0')) {
                if (GuestOffsetInRange(eventEA, sizeof(uint64_t))) {
                    if (auto* ps = static_cast<uint8_t*>(g_memory.Translate(eventEA))) {
                        *reinterpret_cast<uint64_t*>(ps) = 0ull;
                        KernelTraceHostOpF("HOST.Wait.force_ack.status.zero ea=%08X", eventEA);
                    }
                }
            }
        }
    }
}

#endif
#ifndef FILE_OPENED
#define FILE_OPENED            1
#endif
#ifndef FILE_CREATED
#define FILE_CREATED           2
#endif
#ifndef FILE_OVERWRITTEN
#define FILE_OVERWRITTEN       3
#endif
#ifndef FILE_EXISTS
#define FILE_EXISTS            4
#endif
#ifndef FILE_DOES_NOT_EXIST
#define FILE_DOES_NOT_EXIST    5
#endif

inline uint32_t GetKernelHandle(void* obj) {
    return GetKernelHandle(reinterpret_cast<KernelObject*>(obj));
}
#include <kernel/io/file_system.h>

uint32_t XSetFilePointer(FileHandle* hFile,
                         int32_t lDistanceToMove,
                         be<int32_t>* lpDistanceToMoveHigh,
                         uint32_t dwMoveMethod);
uint32_t XSetFilePointerEx(FileHandle* hFile,
                           int32_t lDistanceToMove,
                           LARGE_INTEGER* lpNewFilePointer,
                           uint32_t dwMoveMethod);

#ifndef STATUS_OBJECT_NAME_INVALID
#define STATUS_OBJECT_NAME_INVALID 0xC0000033
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#endif
#ifndef STATUS_OBJECT_PATH_NOT_FOUND
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif
#ifndef STATUS_END_OF_FILE
#define STATUS_END_OF_FILE 0xC0000011
#endif
#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE 0x00000000
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_CREATE
#define FILE_CREATE 0x00000002
#endif
#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF 0x00000003
#endif
#ifndef FILE_OVERWRITE
#define FILE_OVERWRITE 0x00000004
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 0x00000005
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#endif
#ifndef FILE_ATTRIBUTE_DIRECTORY
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#endif
#ifndef FILE_FLAG_BACKUP_SEMANTICS
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000
#endif
#ifndef CREATE_NEW
#define CREATE_NEW 1
#endif
#ifndef CREATE_ALWAYS
#define CREATE_ALWAYS 2
#endif
#ifndef OPEN_EXISTING
#define OPEN_EXISTING 3
#endif
#ifndef OPEN_ALWAYS
#define OPEN_ALWAYS 4
#endif
#ifndef TRUNCATE_EXISTING
#define TRUNCATE_EXISTING 5
#endif
#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER 0xFFFFFFFF
#endif
#ifndef FILE_BEGIN
#define FILE_BEGIN 0
#endif
#ifndef FILE_CURRENT
#define FILE_CURRENT 1
#endif
#ifndef FILE_END
#define FILE_END 2
#endif

namespace {

std::string ExtractGuestPath(const XOBJECT_ATTRIBUTES* attributes)
{
    if (!attributes) {
        return {};
    }
    const auto* name = attributes->Name.get();
    if (!name) {
        return {};
    }
    const char* buffer = name->Buffer.get();
    if (!buffer) {
        return {};
    }
    const uint16_t length = name->Length;
    std::string path(buffer, buffer + length);
    while (!path.empty() && path.back() == '\0') {
        path.pop_back();
    }
    return path;
}

static std::string NormalizeGuestPath(std::string path)
{
    if (path.empty()) return path;

    std::replace(path.begin(), path.end(), '/', '\\');

    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

    auto strip_prefix = [&](std::string_view prefix) {
        if (lower.size() >= prefix.size() &&
            lower.compare(0, prefix.size(), prefix) == 0) {
            path.erase(0, prefix.size());
            lower.erase(0, prefix.size());
            return true;
            }
        return false;
    };

    strip_prefix(R"(\??\)");

    if (strip_prefix(R"(\device\cdrom0\)")) {
        path.insert(0, R"(game:\)");
    } else if (strip_prefix(R"(\device\cdrom1\)")) {
        path.insert(0, R"(update:\)");
    } else if (strip_prefix(R"(\device\harddisk0\partition1\)")) {
        path.insert(0, R"(game:\)");
    } else if (strip_prefix(R"(\device\harddisk0\partition0\)")) {
        path.insert(0, R"(hdd:\)");
    } else if (strip_prefix(R"(\device\harddisk0\partition2\)")) {
        path.insert(0, R"(cache:\)");
    }

    if (!path.empty() && path.front() == '\\') {
        path.erase(path.begin());
        path.insert(0, R"(game:\)");
    }

    if (path.size() >= 5 && path[4] == ':' && (path.size() == 5 || path[5] != '\\')) {
        path.insert(5, R"(\)");
    }

    return path;
}

bool MapCreateDisposition(uint32_t createDisposition, uint32_t& out)
{
    switch (createDisposition) {
    case FILE_SUPERSEDE:
    case FILE_OVERWRITE_IF:
        out = CREATE_ALWAYS;
        return true;
    case FILE_OPEN:
        out = OPEN_EXISTING;
        return true;
    case FILE_CREATE:
        out = CREATE_NEW;
        return true;
    case FILE_OPEN_IF:
        out = OPEN_ALWAYS;
        return true;
    case FILE_OVERWRITE:
        out = TRUNCATE_EXISTING;
        return true;
    default:
        return false;
    }
}

uint32_t MapCreateOptions(uint32_t createOptions, uint32_t fileAttributes)
{
    uint32_t flags = fileAttributes ? fileAttributes : FILE_ATTRIBUTE_NORMAL;
    if (createOptions & FILE_DIRECTORY_FILE) {
        flags &= ~FILE_ATTRIBUTE_NORMAL;
        flags |= FILE_ATTRIBUTE_DIRECTORY | FILE_FLAG_BACKUP_SEMANTICS;
    }
    return flags;
}

bool ApplyAbsoluteOffset(FileHandle* file, int64_t offset, LARGE_INTEGER& originalPos, bool& hasOriginal)
{
    hasOriginal = false;
    if (offset < 0) {
        return true;
    }

    if (XSetFilePointerEx(file, 0, &originalPos, FILE_CURRENT) != FALSE) {
        hasOriginal = true;
    }

    const int32_t low = static_cast<int32_t>(offset & 0xFFFFFFFF);
    const int32_t high = static_cast<int32_t>(offset >> 32);

    if (high != 0) {
        be<int32_t> hi(high);
        return XSetFilePointer(file, low, &hi, FILE_BEGIN) != INVALID_SET_FILE_POINTER;
    }

    return XSetFilePointerEx(file, low, nullptr, FILE_BEGIN) != FALSE;
}

void RestoreFileOffset(FileHandle* file, const LARGE_INTEGER& originalPos, bool hasOriginal)
{
    if (!hasOriginal) {
        return;
    }

    const int64_t offset = originalPos.QuadPart;
    const int32_t low = static_cast<int32_t>(offset & 0xFFFFFFFF);
    const int32_t high = static_cast<int32_t>(offset >> 32);

    if (high != 0) {
        be<int32_t> hi(high);
        XSetFilePointer(file, low, &hi, FILE_BEGIN);
    } else {
        XSetFilePointerEx(file, low, nullptr, FILE_BEGIN);
    }
}

} // namespace

// Optional: allow forcing the VD interrupt event EA via environment for bring-up
static std::atomic<bool> g_forceVdEventChecked{false};
static void Mw05MaybeForceRegisterVdEventFromEnv() {
    bool expected = false;
    if (!g_forceVdEventChecked.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const char* v = std::getenv("MW05_FORCE_VD_EVENT_EA");
    if (!v || !*v) return;
    // Accept hex with or without 0x prefix
    uint32_t ea = (uint32_t)strtoul(v, nullptr, 0);
    if (GuestOffsetInRange(ea, sizeof(XDISPATCHER_HEADER))) {
        // Assume auto-reset (manualReset=false) for safety; guests typically pulse this.
        Mw05RegisterVdInterruptEvent(ea, /*manualReset*/false);
    }
}

// ---- optional auto video bring-up (small ring + write-back) ----
static std::atomic<bool> g_autoVideoDone{false};
static inline bool Mw05AutoVideoEnabled() {
    // Default ON; disable with MW05_AUTO_VIDEO=0 if needed
    if (const char* v = std::getenv("MW05_AUTO_VIDEO"))
        return !(v[0]=='0' && v[1]=='\0');
    return true;
}

void Mw05AutoVideoInitIfNeeded() {
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Mw05AutoVideoInitIfNeeded ENTER\n");

    if (!Mw05AutoVideoEnabled()) {
        DEBUG_LOG_GRAPHICS(NORMAL, "[AUTO-VIDEO] AutoVideo disabled, returning\n");
        return;
    }

    bool expected = false;
    if (!g_autoVideoDone.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Already done, returning\n");
        return;
    }
    DEBUG_LOG_GRAPHICS(NORMAL, "[AUTO-VIDEO] First time, initializing video system\n");

    // CRITICAL FIX: Move env var check AFTER g_autoVideoDone check to prevent infinite recursion
    // Mw05MaybeForceRegisterVdEventFromEnv() -> Mw05RegisterVdInterruptEvent() -> Mw05AutoVideoInitIfNeeded()
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Checking for forced VD event registration\n");
    Mw05MaybeForceRegisterVdEventFromEnv();
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Forced VD event check complete\n");

    // If a ring and write-back already exist, skip.
    if (g_RbLen.load(std::memory_order_relaxed) != 0 &&
        g_RbWriteBackPtr.load(std::memory_order_relaxed) != 0) {
        DEBUG_LOG_GRAPHICS(NORMAL, "[AUTO-VIDEO] Ring buffer already exists, skipping\n");
        return;
    }
    DEBUG_LOG_GRAPHICS(NORMAL, "[AUTO-VIDEO] Creating ring buffer and write-back\n");

    // Ensure a system command buffer exists for callers that query it later.
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Getting system command buffer\n");
    VdGetSystemCommandBuffer(nullptr, nullptr);

    const uint32_t len_log2 = 16; // 64 KiB ring (closer to MW05 expectations)
    const uint32_t size_bytes = 1u << len_log2;
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Allocating ring buffer (%u bytes)\n", size_bytes);
    void* ring_host = g_userHeap.Alloc(size_bytes);
    if (!ring_host) {
        DEBUG_LOG_GRAPHICS(MINIMAL, "[AUTO-VIDEO] ERROR: Failed to allocate ring buffer!\n");
        // CRITICAL FIX: Reset g_autoVideoDone so we can retry later
        g_autoVideoDone.store(false, std::memory_order_release);
        return;
    }
    const uint32_t ring_guest = g_memory.MapVirtual(ring_host);
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Ring buffer allocated at guest=0x%08X host=%p\n", ring_guest, ring_host);

    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Allocating write-back buffer (64 bytes)\n");
    void* wb_host = g_userHeap.Alloc(64);
    if (!wb_host) {
        DEBUG_LOG_GRAPHICS(MINIMAL, "[AUTO-VIDEO] ERROR: Failed to allocate write-back buffer!\n");
        // CRITICAL FIX: Reset g_autoVideoDone so we can retry later
        g_autoVideoDone.store(false, std::memory_order_release);
        return;
    }
    const uint32_t wb_guest = g_memory.MapVirtual(wb_host);
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Write-back buffer allocated at guest=0x%08X host=%p\n", wb_guest, wb_host);

    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Initializing ring buffer\n");
    KernelTraceHostOpF("HOST.AutoVideo.Init ring=%08X len_log2=%u wb=%08X", ring_guest, len_log2, wb_guest);
    VdInitializeRingBuffer(ring_guest, len_log2);

    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Enabling ring buffer write-back\n");
    VdEnableRingBufferRPtrWriteBack(wb_guest);

    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Setting GPU identifier address\n");
    VdSetSystemCommandBufferGpuIdentifierAddress(wb_guest + 8);

    DEBUG_LOG_GRAPHICS(NORMAL, "[AUTO-VIDEO] Video system initialization complete\n");
}

inline static void DumpRawHeader16(uint32_t ea) {
    if (!GuestOffsetInRange(ea, sizeof(XDISPATCHER_HEADER))) return;
    const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(ea));
    // print 16 bytes (header is 16)
    KernelTraceHostOpF("DISP RAW %08X: %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X",
        ea, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

inline static void DumpRawHeader(uint32_t ea) {
    uint8_t buf[32]{};
    std::memcpy(buf, g_memory.Translate(ea), sizeof(buf));
    KernelTraceHostOpF("DISP RAW %08X: "
                       "%02X %02X %02X %02X  %02X %02X %02X %02X  "
                       "%02X %02X %02X %02X  %02X %02X %02X %02X",
                       ea,
                       buf[0],buf[1],buf[2],buf[3], buf[4],buf[5],buf[6],buf[7],
                       buf[8],buf[9],buf[10],buf[11], buf[12],buf[13],buf[14],buf[15]);
}



// --- Minimal stateful Vd* bridge (enough to unblock guest expectations) ---
static std::atomic<uint32_t> g_VdSystemCommandBuffer{0};
static std::atomic<uint32_t> g_VdSystemCommandBufferGpuIdAddr{0};

// CRITICAL FIX: Support multiple GPU contexts with separate callbacks
// The game creates TWO GPU contexts (0x40007180 and 0x01568400) and registers
// a callback for each one. Using global variables caused the second registration
// to overwrite the first one's callback, breaking rendering.
// Solution: Use a map to store callback/context pairs for each GPU context address.
static std::mutex g_VdCallbackMapMutex;
static std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> g_VdCallbackMap;  // context_addr -> (callback, context)
static std::atomic<uint32_t> g_VdGraphicsCallback{0};  // Deprecated - kept for compatibility
static std::atomic<uint32_t> g_VdGraphicsCallbackCtx{0};  // Deprecated - kept for compatibility

static constexpr uint32_t kHostDefaultVdIsrMagic = 0xDEFAD15A; // magic tag for host default ISR

// Accessor functions for GPU writeback pointers (used by mw05_trace_shims.cpp)
extern "C" uint32_t GetRbWriteBackPtr() {
    return g_RbWriteBackPtr.load(std::memory_order_relaxed);
}

extern "C" uint32_t GetVdSystemCommandBufferGpuIdAddr() {
    return g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_relaxed);
}

extern "C" uint32_t GetRbLen() {
    return g_RbLen.load(std::memory_order_relaxed);
}

// Accessor functions for VD graphics callback (used by system_threads.cpp)
extern "C" uint32_t GetVdGraphicsCallback() {
    return g_VdGraphicsCallback.load(std::memory_order_relaxed);
}

extern "C" uint32_t GetVdGraphicsCallbackCtx() {
    return g_VdGraphicsCallbackCtx.load(std::memory_order_relaxed);
}
static std::mutex g_VdNotifMutex;
static std::vector<std::pair<uint32_t,uint32_t>> g_VdNotifList;

static inline bool Mw05EnvEnabled(const char* name) {
    if (const char* v = std::getenv(name)) return !(v[0]=='0' && v[1]=='\0');
    return false;
}
static void Mw05MaybeInstallDefaultVdIsr() {
    static bool s_logged_once = false;
    if (!s_logged_once) {
        bool env_enabled = Mw05EnvEnabled("MW05_REGISTER_DEFAULT_VD_ISR");
        uint32_t cur_cb = g_VdGraphicsCallback.load(std::memory_order_acquire);
        fprintf(stderr, "[VBLANK-ISR-INSTALL] env_enabled=%d cur_cb=%08X\n", (int)env_enabled, cur_cb);
        fflush(stderr);
        s_logged_once = true;
    }
    if (!Mw05EnvEnabled("MW05_REGISTER_DEFAULT_VD_ISR")) return;
    if (g_VdGraphicsCallback.load(std::memory_order_acquire) != 0) return;
    g_VdGraphicsCallback.store(kHostDefaultVdIsrMagic, std::memory_order_release);
    g_VdGraphicsCallbackCtx.store(0, std::memory_order_release);
    KernelTraceHostOp("HOST.VdISR.default.registered");
}

static inline void NudgeEventWaiters() {
    g_keSetEventGeneration.fetch_add(1, std::memory_order_acq_rel);
    g_keSetEventGeneration.notify_all();
}
static void Mw05HostIsrSignalLastWaitHandleIfAny();

// Thread-local flag to prevent infinite recursion when VdSwap is called from the interrupt handler
static thread_local bool s_inVdInterruptDispatch = false;

static bool Mw05SignalVdInterruptEvent();
static void Mw05DispatchVdInterruptIfPending();

extern "C" {
    uint32_t VdGetGraphicsInterruptCallback() {
        // CRITICAL FIX: Look up callback for the CURRENT GPU context
        // The VBlank ISR needs to use the correct callback for whichever context is active
        // Read the current scheduler context address from the global scheduler pointer
        uint32_t current_ctx = LoadBE32_Watched(g_memory.base, 0x82909650);
        if(current_ctx != 0) {
            // Look up the callback for this context
            std::lock_guard<std::mutex> lock(g_VdCallbackMapMutex);
            auto it = g_VdCallbackMap.find(current_ctx);
            if(it != g_VdCallbackMap.end()) {
                return it->second.first;  // Return callback
            }
        }

        // Fallback to deprecated global variable
        return g_VdGraphicsCallback.load();
    }

    uint32_t VdGetGraphicsInterruptContext() {
        uint32_t ctx = g_VdGraphicsCallbackCtx.load();
        // Optional: override ISR context globally with the discovered scheduler pointer.
        // This centralizes the override instead of patching every callsite.
        static const bool s_force_ctx_sched = []() {
            if(const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED")) return !(v[0] == '0' && v[1] == '\0');
            return false;
        }
        ();
        if(!s_force_ctx_sched) return ctx;

        // Gating to avoid early-boot crashes: wait some vblank ticks and a few stable sightings
        static const uint32_t s_ctx_delay_ticks = []() {
            if(const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED_DELAY_TICKS"))
                return (uint32_t)std::strtoul(v, nullptr, 0);
            return (uint32_t)120; // default ~2s at 60 Hz
        }
        ();
        static const uint32_t s_seen_min = []() {
            if(const char* v = std::getenv("MW05_VD_ISR_CTX_SEEN_MIN"))
                return (uint32_t)std::strtoul(v, nullptr, 0);
            return (uint32_t)2; // need at least 2 stable sightings
        }
        ();

        const uint32_t ticks = g_vblankTicks.load(std::memory_order_acquire);
        if(ticks < s_ctx_delay_ticks) return ctx;

        uint32_t sched = Mw05Trace_LastSchedR3();
        bool seeded_env = false;
        // Allow explicit seeding from env if trace hasn't seen a good pointer yet
        if(!GuestOffsetInRange(sched, 4)) {
            if(const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
                uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
                if(GuestOffsetInRange(env_r3, 4)) {
                    sched = env_r3;
                    seeded_env = true;
                }
            }
        }

        if(GuestOffsetInRange(sched, 4)) {
            const uint32_t seen = Mw05Trace_SchedR3SeenCount();
            // If seeded from env, allow immediate override; otherwise require stable sightings
            if(seeded_env || (seen >= s_seen_min)) {
                static bool s_logged = false;
                if(!s_logged) {
                    KernelTraceHostOpF("HOST.VdGetGraphicsInterruptContext.override ctx=%08X->%08X ticks=%u seen=%u%s", ctx, sched, (unsigned)ticks, (unsigned)seen, seeded_env ? " (env)" : "");
                    s_logged = true;
                }
                return sched;
            }
        }
        return ctx;
    }
    uint32_t Mw05GetHostDefaultVdIsrMagic() {
        return kHostDefaultVdIsrMagic;
    }

    bool KeSetEvent(XKEVENT* pEvent, uint32_t Increment, bool Wait);
    bool KeResetEvent(XKEVENT* pEvent);

    void Mw05RunHostDefaultVdIsrNudge(const char* tag) {
        // PERFORMANCE: ISR debug logging (disabled by default - causes FPS drop)
        static const bool s_debug_isr = [](){
            if (const char* v = std::getenv("MW05_DEBUG_ISR"))
                return !(v[0]=='0' && v[1]=='\0');
            return false; // DISABLED by default for performance
        }();

        // Controls whether the host default VD ISR requests a Present at the end of each nudge.
        // Default: enabled (preserves current behavior). Set MW05_ISR_AUTO_PRESENT=0 to disable for diagnostics.
        static const bool s_isr_auto_present = []() {
            if(const char* v = std::getenv("MW05_ISR_AUTO_PRESENT"))
                return !(v[0] == '0' && v[1] == '\0');
            return true;
        }
        ();

        static thread_local bool s_inHostIsrNudge = false;
        if(s_inHostIsrNudge) {
            if (s_debug_isr) KernelTraceHostOp("HOST.HostDefaultVdIsr.nudge.reentrant");
            return;
        }
        s_inHostIsrNudge = true;

        if (s_debug_isr) {
            if(tag) KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge.%s", tag);
            else     KernelTraceHostOp("HOST.HostDefaultVdIsr.nudge");
        }

        // Adjustable ring write-back step
        uint32_t step = 0x40u;
        if(const char* s = std::getenv("MW05_HOST_ISR_RB_STEP")) {
            // Accept hex (0x...) or decimal

            // Controls whether the host default VD ISR requests a Present at the end of each nudge.
            // Default: enabled (preserves current behavior). Set MW05_ISR_AUTO_PRESENT=0 to disable for diagnostics.
            static const bool s_isr_auto_present = []() {
                if(const char* v = std::getenv("MW05_ISR_AUTO_PRESENT"))
                    return !(v[0] == '0' && v[1] == '\0');
                return true;
            }
            ();

            char* endp = nullptr;
            unsigned long v = std::strtoul(s, &endp, (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10);
            if(v > 0 && v < 0x100000) step = static_cast<uint32_t>(v);
        }

        // Bump ring write-back pointer
        if(uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed)) {
            if(auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb))) {
                uint32_t cur = *rptr;
                uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
                uint32_t mask = len_log2 ? ((1u << len_log2) - 1u) : 0xFFFFu;
                uint32_t next = (cur + step) & mask;
                uint32_t write = next ? next : 0x20u;
                *rptr = write;
                if (s_debug_isr) {
                    KernelTraceHostOpF("HOST.RB.rptr.bump ea=%08X cur=%08X next=%08X step=%u mask=%08X", wb, cur, write, step, mask);
                }
            }
        }

        // Optional: scan the ring buffer periodically early-on to surface TYPE3 packets (env: MW05_PM4_SCAN_RING=1)
        {
            static uint32_t s_ring_scan_count = 0;
            static const bool s_scan_ring = []() {
                if(const char* v = std::getenv("MW05_PM4_SCAN_RING")) return !(v[0] == '0' && v[1] == '\0');
                return false;
            }
            ();
            if(s_scan_ring && s_ring_scan_count < 8) {
                const uint32_t base = g_RbBase.load(std::memory_order_relaxed);
                const uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
                if(base && len_log2) {
                    const uint32_t bytes = 1u << len_log2;
                    if (s_debug_isr) {
                        KernelTraceHostOpF("HOST.PM4.ScanLinear.RingTick base=%08X bytes=%u tick_scan=%u", base, bytes, s_ring_scan_count);
                    }
                    PM4_ScanLinear(base, bytes);
                    ++s_ring_scan_count;
                }
                // Optional: try calling the MW05 PM4 builder shim from ISR a few times early (env: MW05_ISR_TRY_BUILDER=1)
                {
                    static uint32_t s_builder_calls = 0;
                    static const bool s_try_builder = []() {
                        if(const char* v = std::getenv("MW05_ISR_TRY_BUILDER")) return !(v[0] == '0' && v[1] == '\0');
                        return false;
                    }
                    ();
                    if(s_try_builder && s_builder_calls < 3) {
                        uint32_t seed = Mw05Trace_LastSchedR3();
                        if(!(seed >= 0x1000u)) seed = 0x00060E30u;
                        if(seed >= 0x1000u) {
                            // Ensure guest context on this thread to preserve TOC/r13 etc.
                            EnsureGuestContextForThisThread("HostDefaultVdIsr");
                            PPCContext ctx{};
                            if(auto* cur = GetPPCContext()) ctx = *cur;
                            ctx.r3.u32 = seed;
                            if(ctx.r4.u32 == 0) ctx.r4.u32 = 0x40;
                            uint8_t* base = g_memory.base;
                            if (s_debug_isr) {
                                KernelTraceHostOpF("HOST.ISR.pm4_forward r3=%08X r4=%08X call=%u", ctx.r3.u32, ctx.r4.u32, s_builder_calls);
                            }
                            ++s_builder_calls;
                        }
                    }
                }

            }
        }

        // Optionally ACK the VD event directly in ISR path
        if(const char* a = std::getenv("MW05_HOST_ISR_ACK_EVENT")) {
            if(!(a[0] == '0' && a[1] == '\0')) {
                const uint32_t eventEA = g_vdInterruptEventEA.load(std::memory_order_acquire);
                if(eventEA) {
                    if(GuestOffsetInRange(eventEA, sizeof(uint64_t))) {
                        if(auto* ps = static_cast<uint8_t*>(g_memory.Translate(eventEA))) {
                            *reinterpret_cast<uint64_t*>(ps) = 0ull;
                            if (s_debug_isr) {
                                KernelTraceHostOpF("HOST.HostDefaultVdIsr.ack.status.zero ea=%08X", eventEA);
                            }
                        }
                    }
                    if(GuestOffsetInRange(eventEA - 8, sizeof(uint64_t))) {
                        if(auto* p2 = static_cast<uint8_t*>(g_memory.Translate(eventEA - 8))) {
                            *reinterpret_cast<uint64_t*>(p2) = 0ull;
                            if (s_debug_isr) {
                                KernelTraceHostOpF("HOST.HostDefaultVdIsr.ack.ptr.zero ea=%08X", eventEA - 8);
                            }
                        }
                    }

                    // Optionally clear scheduler block header that the waiter fences on
                    bool do_sched_clear = false;
                    if(const char* sc = std::getenv("MW05_HOST_ISR_SCHED_CLEAR")) {
                        do_sched_clear = !(sc[0] == '0' && sc[1] == '\0');
                    } else {
                        // Auto-on when force-ack is enabled
                        do_sched_clear = Mw05ForceAckWaitEnabled();
                    }
                    if(do_sched_clear) {
                        // Try to read a big-endian pointer to the block from eventEA-8
                        if(GuestOffsetInRange(eventEA - 8, sizeof(uint64_t))) {
                            const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(eventEA - 8));
                            if(p) {
                                uint64_t be_ptr64 = *reinterpret_cast<const uint64_t*>(p);
#if defined(_MSC_VER)
                                be_ptr64 = _byteswap_uint64(be_ptr64);
#else
                                be_ptr64 = __builtin_bswap64(be_ptr64);
#endif
                                const uint32_t blkEA = static_cast<uint32_t>(be_ptr64);
                                if(blkEA && GuestOffsetInRange(blkEA, 0x20)) {
                                    if(auto* blk = static_cast<uint8_t*>(g_memory.Translate(blkEA))) {
                                        memset(blk, 0, 0x20);
                                        if (s_debug_isr) {
                                            KernelTraceHostOpF("HOST.HostDefaultVdIsr.sched.clear ea=%08X", blkEA);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Optionally signal the VD event from ISR
                    if(const char* se = std::getenv("MW05_HOST_ISR_SIGNAL_VD_EVENT")) {
                        if(!(se[0] == '0' && se[1] == '\0')) {
                            if(auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(eventEA))) {
                                KeSetEvent(evt, 0, false);
                                if (s_debug_isr) {
                                    KernelTraceHostOpF("HOST.HostDefaultVdIsr.signal ea=%08X", eventEA);
                                }
                            }
                        }
                    }
                }
            }
        }


        // Optional: aggressively pulse the suspected scheduler event at EA=0x000E0DD0 (diagnostic)
        // Guarded by MW05_PULSE_E0DD0=1. This is a temporary nudge to test whether that wait gate blocks progress.
        if(const char* pe = std::getenv("MW05_PULSE_E0DD0")) {
            if(!(pe[0] == '0' && pe[1] == '\0')) {
                constexpr uint32_t kPulseEA = 0x000E0DD0u;
                if(GuestOffsetInRange(kPulseEA, sizeof(XDISPATCHER_HEADER))) {
                    if(auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(kPulseEA))) {
                        KeSetEvent(evt, 0, false);
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.pulse.e0dd0 ea=%08X", kPulseEA);
                    }
                }
            }
        }

        // Optionally signal the last waited-on event (if different from the VD event)
        if(const char* slw = std::getenv("MW05_HOST_ISR_FORCE_SIGNAL_LAST_WAIT")) {
            if(!(slw[0] == '0' && slw[1] == '\0')) {
                const uint32_t lastEA = g_lastWaitEventEA.load(std::memory_order_acquire);
                const uint32_t vdEA   = g_vdInterruptEventEA.load(std::memory_order_acquire);
                if(const char* tl2 = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
                    if(!(tl2[0] == '0' && tl2[1] == '\0')) {
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.last_wait.state last=%08X vd=%08X", lastEA, vdEA);
                    }
                }

                if(lastEA && lastEA != vdEA && GuestOffsetInRange(lastEA, sizeof(XDISPATCHER_HEADER))) {
                    if(auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(lastEA))) {
                        KeSetEvent(evt, 0, false);
                        // Trace last-wait state for diagnostics
                        if(const char* tl = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
                            if(!(tl[0] == '0' && tl[1] == '\0')) {
                                KernelTraceHostOpF("HOST.HostDefaultVdIsr.last_wait.state last=%08X vd=%08X", lastEA, vdEA);
                            }
                        }

                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.signal.last_wait ea=%08X", lastEA);

                    }
                }

                // If we didn't have a valid last-wait EA, try the last kernel handle waited on (implemented later)
                if(!(lastEA && GuestOffsetInRange(lastEA, sizeof(XDISPATCHER_HEADER)))) {
                    Mw05HostIsrSignalLastWaitHandleIfAny();
                }

            }
        }


        // Optional: one-time nudge after N ISR ticks if still stuck (env-guarded)
        {
            static bool  s_nudgeOnceEnabled = []() {
                if(const char* v = std::getenv("MW05_HOST_ISR_NUDGE_ONCE"))
                    return !(v[0] == '0' && v[1] == '\0');
                return false;
            }
            ();
            static uint32_t s_afterTicks = []() {
                if(const char* v = std::getenv("MW05_HOST_ISR_NUDGE_AFTER"))
                    return (uint32_t)std::strtoul(v, nullptr, 10);
                return 240u; // ~4 seconds at 60Hz
            }
            ();
            static uint32_t s_ticks = 0;
            static bool     s_done  = false;
            static bool     s_loggedCfg = false;

            if(!s_loggedCfg) {
                KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge_once.config enabled=%u after=%u", (unsigned)s_nudgeOnceEnabled, s_afterTicks);
                s_loggedCfg = true;
            }

            if(!s_done) ++s_ticks;
            if(s_nudgeOnceEnabled && !s_done && s_ticks >= s_afterTicks) {
                const uint32_t lastEA = g_lastWaitEventEA.load(std::memory_order_acquire);
                const uint32_t vdEA   = g_vdInterruptEventEA.load(std::memory_order_acquire);
                bool did = false;
                if(lastEA && lastEA != vdEA && GuestOffsetInRange(lastEA, sizeof(XDISPATCHER_HEADER))) {
                    if(auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(lastEA))) {
                        KeSetEvent(evt, 0, false);
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge_once.last_wait ea=%08X ticks=%u", lastEA, s_ticks);
                        did = true;
                    }
                }
                if(!did) {
                    Mw05HostIsrSignalLastWaitHandleIfAny();
                    KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge_once.handle_or_none handle=%08X ticks=%u",
                                       (unsigned)g_lastWaitKernelHandle.load(std::memory_order_relaxed), s_ticks);
                }
                s_done = true;
            }
        }

        // Optionally tick the system command buffer GPU-identifier value
        if(const char* t = std::getenv("MW05_HOST_ISR_TICK_SYSID")) {
            if(!(t[0] == '0' && t[1] == '\0')) {
                const uint32_t sysIdEA = g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_acquire);
                if(sysIdEA && GuestOffsetInRange(sysIdEA, sizeof(uint32_t))) {
                    if(auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(sysIdEA))) {
                        uint32_t val = *p + 1u;
                        *p = val;
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.sys_id.tick val=%08X", val);
                    }
                }
                if(!tag || strcmp(tag, "vd_call") != 0) {

                    // Optionally drive notifications again within the same tick (safe: reentrancy-guarded)
                    static thread_local bool s_inIsrNudge = false;
                    if(!s_inIsrNudge) {
                        s_inIsrNudge = true;
                        VdCallGraphicsNotificationRoutines(0u);


                        s_inIsrNudge = false;
                    }

                    // Optionally synthesize additional notify sources (e.g., 1,2) some titles expect
                    if(const char* seq = std::getenv("MW05_HOST_ISR_NOTIFY_SRC_SEQ")) {
                        // Format: comma-separated uints, e.g., "0,1,2"
                        const char* p = seq;
                        while(*p) {
                            unsigned v = 0;
                            bool any = false;
                            while(*p && *p == ' ') ++p;
                            while(*p && *p >= '0' && *p <= '9') {
                                v = v * 10 + unsigned(*p - '0');
                                ++p;
                                any = true;
                            }
                            if(any) VdCallGraphicsNotificationRoutines(static_cast<uint32_t>(v));
                            while(*p && *p != ',') ++p;
                            if(*p == ',') ++p;
                        }
                    } else {
                        // Default: also emit a '1' source in addition to the vblank (0)
                        VdCallGraphicsNotificationRoutines(0u);
                    }
                    // If a real ISR is registered (not the host magic), also call it with extra sources
                    if(uint32_t cb = VdGetGraphicsInterruptCallback()) {
                        if(cb != kHostDefaultVdIsrMagic) {
                            const uint32_t ctx = VdGetGraphicsInterruptContext();
                            // same sequence logic as above: use env or default to 1
                            if(const char* seq2 = std::getenv("MW05_HOST_ISR_NOTIFY_SRC_SEQ")) {
                                const char* p2 = seq2;
                                while(*p2) {
                                    unsigned v = 0;
                                    bool any = false;
                                    while(*p2 && *p2 == ' ') ++p2;
                                    while(*p2 && *p2 >= '0' && *p2 <= '9') {
                                        v = v * 10 + unsigned(*p2 - '0');
                                        ++p2;
                                        any = true;
                                    }
                                    if(any) GuestToHostFunction<void>(cb, static_cast<uint32_t>(v), ctx);
                                    while(*p2 && *p2 != ',') ++p2;
                                    if(*p2 == ',') ++p2;
                                }
                            } else {
                                GuestToHostFunction<void>(cb, 0u, ctx);
                            }
                        }
                    }

                }
            }
        }

        // Optional diagnostics to understand what the title is polling before calling VdGetSystemCommandBuffer/VdSwap
        if(const char* d = std::getenv("MW05_VD_POLL_DIAG")) {
            if(!(d[0] == '0' && d[1] == '\0')) {
                static int s_diagTick = 0;
                // Log every 8th tick to avoid spamming
                if(((++s_diagTick) & 7) == 0) {
                    auto read_be64 = [](uint32_t ea)->uint64_t {
                        if(!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                        const void* p = g_memory.Translate(ea);
                        if(!p) return 0;
                        uint64_t v = *reinterpret_cast<const uint64_t*>(p);
#if defined(_MSC_VER)
                        v = _byteswap_uint64(v);
#else
                        v = __builtin_bswap64(v);
#endif
                        return v;
                    };

                    auto read_u32 = [](uint32_t ea)->uint32_t {
                        if(!GuestOffsetInRange(ea, sizeof(uint32_t))) return 0;
                        const void* p = g_memory.Translate(ea);
                        if(!p) return 0;
                        uint32_t v = *reinterpret_cast<const uint32_t*>(p);
                        return v; // Many R/WB pointers are stored in native endian
                    };

                    const uint32_t rb_ea   = g_RbWriteBackPtr.load(std::memory_order_acquire);
                    const uint32_t rb_val  = rb_ea ? read_u32(rb_ea) : 0;
                    const uint32_t sys_ea  = g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_acquire);
                    const uint32_t sys_val = sys_ea ? read_u32(sys_ea) : 0;
                    const uint32_t vd_ea   = g_vdInterruptEventEA.load(std::memory_order_acquire);

                    const uint64_t e50 = read_be64(0x00060E50);
                    const uint64_t e58 = read_be64(0x00060E58);
                    const uint64_t e60 = read_be64(0x00060E60);
                    const uint64_t e68 = read_be64(0x00060E68);
                    const uint64_t e70 = read_be64(0x00060E70);
                    const uint64_t e78 = read_be64(0x00060E78);
                    const uint64_t e80 = read_be64(0x00060E80);

                    KernelTraceHostOpF(
                        "HOST.VD.diag rb=(%08X,%08X) sysid=(%08X,%08X) vd=%08X e50=%016llX e58=%016llX e60=%016llX e68=%016llX e70=%016llX e78=%016llX e80=%016llX",
                        rb_ea, rb_val, sys_ea, sys_val, vd_ea,
                        (unsigned long long)e50, (unsigned long long)e58, (unsigned long long)e60,
                        (unsigned long long)e68, (unsigned long long)e70, (unsigned long long)e78, (unsigned long long)e80);
                }
            }
        }

        // Optional pokes to satisfy early-boot polls (guarded by env)
        if(const char* poke58 = std::getenv("MW05_VD_POKE_E58")) {
            // Accept hex or decimal; examples: "0x600" or "1536". If the string starts with '+', OR the value.
            if(poke58 && poke58[0]) {
                const bool or_mode = (poke58[0] == '+');
                const char* val_str = or_mode ? poke58 + 1 : poke58;
                unsigned long v = std::strtoul(val_str, nullptr, 0);
                auto write_be64 = [](uint32_t ea, uint64_t v64) {
                    if(!GuestOffsetInRange(ea, sizeof(uint64_t))) return false;
                    auto* p = static_cast<uint8_t*>(g_memory.Translate(ea));
                    if(!p) return false;
                    p[0] = uint8_t(v64 >> 56);
                    p[1] = uint8_t(v64 >> 48);
                    p[2] = uint8_t(v64 >> 40);
                    p[3] = uint8_t(v64 >> 32);
                    p[4] = uint8_t(v64 >> 24);
                    p[5] = uint8_t(v64 >> 16);
                    p[6] = uint8_t(v64 >>  8);
                    p[7] = uint8_t(v64 >>  0);
                    return true;
                };
                const uint32_t ea = 0x00060E58u;
                // Only write if different to minimize churn
                auto read_be64 = [](uint32_t ea)->uint64_t{
                    if(!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                    const void* p = g_memory.Translate(ea);
                    if(!p) return 0;
                    uint64_t r = *reinterpret_cast<const uint64_t*>(p);
#if defined(_MSC_VER)
                    r = _byteswap_uint64(r);
#else
                    r = __builtin_bswap64(r);
#endif
                    return r;
                };
                const uint64_t ov = read_be64(ea);
                const uint64_t nv = or_mode ? (ov | uint64_t(v)) : uint64_t(v);
                if(ov != nv) {
                    if(write_be64(ea, nv)) {
                        KernelTraceHostOpF("HOST.VD.poke%s e58=%016llX (was %016llX)", or_mode ? "|" : "", (unsigned long long)nv, (unsigned long long)ov);
                    }
                }
            }
        }

        // Optional poke for e68 (OR mode supported with leading '+')
        if(const char* poke68 = std::getenv("MW05_VD_POKE_E68")) {
            if(poke68 && poke68[0]) {
                const bool or_mode = (poke68[0] == '+');
                const char* val_str = or_mode ? poke68 + 1 : poke68;
                unsigned long v = std::strtoul(val_str, nullptr, 0);
                auto write_be64 = [](uint32_t ea, uint64_t v64) {
                    if(!GuestOffsetInRange(ea, sizeof(uint64_t))) return false;
                    auto* p = static_cast<uint8_t*>(g_memory.Translate(ea));
                    if(!p) return false;
                    p[0] = uint8_t(v64 >> 56);
                    p[1] = uint8_t(v64 >> 48);
                    p[2] = uint8_t(v64 >> 40);
                    p[3] = uint8_t(v64 >> 32);
                    p[4] = uint8_t(v64 >> 24);
                    p[5] = uint8_t(v64 >> 16);
                    p[6] = uint8_t(v64 >>  8);
                    p[7] = uint8_t(v64 >>  0);
                    return true;
                };
                auto read_be64 = [](uint32_t ea)->uint64_t{
                    if(!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                    const void* p = g_memory.Translate(ea);
                    if(!p) return 0;
                    uint64_t r = *reinterpret_cast<const uint64_t*>(p);
#if defined(_MSC_VER)
                    r = _byteswap_uint64(r);
#else
                    r = __builtin_bswap64(r);
#endif
                    return r;
                };
                const uint32_t ea = 0x00060E68u;
                const uint64_t ov = read_be64(ea);
                const uint64_t nv = or_mode ? (ov | uint64_t(v)) : uint64_t(v);
                if(ov != nv && write_be64(ea, nv)) {
                    KernelTraceHostOpF("HOST.VD.poke%s e68=%016llX (was %016llX)", or_mode ? "|" : "", (unsigned long long)nv, (unsigned long long)ov);
                }
            }
        }

        // Optional poke for e70 (OR mode supported with leading '+')
        if(const char* poke70 = std::getenv("MW05_VD_POKE_E70")) {
            if(poke70 && poke70[0]) {
                const bool or_mode = (poke70[0] == '+');
                const char* val_str = or_mode ? poke70 + 1 : poke70;
                unsigned long v = std::strtoul(val_str, nullptr, 0);
                auto write_be64 = [](uint32_t ea, uint64_t v64) {
                    if(!GuestOffsetInRange(ea, sizeof(uint64_t))) return false;
                    auto* p = static_cast<uint8_t*>(g_memory.Translate(ea));
                    if(!p) return false;
                    p[0] = uint8_t(v64 >> 56);
                    p[1] = uint8_t(v64 >> 48);
                    p[2] = uint8_t(v64 >> 40);
                    p[3] = uint8_t(v64 >> 32);
                    p[4] = uint8_t(v64 >> 24);
                    p[5] = uint8_t(v64 >> 16);
                    p[6] = uint8_t(v64 >>  8);
                    p[7] = uint8_t(v64 >>  0);
                    return true;
                };
                auto read_be64 = [](uint32_t ea)->uint64_t{
                    if(!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                    const void* p = g_memory.Translate(ea);
                    if(!p) return 0;
                    uint64_t r = *reinterpret_cast<const uint64_t*>(p);
#if defined(_MSC_VER)
                    r = _byteswap_uint64(r);
#else
                    r = __builtin_bswap64(r);
#endif
                    return r;
                };
                const uint32_t ea = 0x00060E70u;
                const uint64_t ov = read_be64(ea);
                const uint64_t nv = or_mode ? (ov | uint64_t(v)) : uint64_t(v);
                if(ov != nv && write_be64(ea, nv)) {
                    KernelTraceHostOpF("HOST.VD.poke%s e70=%016llX (was %016llX)", or_mode ? "|" : "", (unsigned long long)nv, (unsigned long long)ov);
                }
            }
        }

        s_inHostIsrNudge = false;

        if(s_isr_auto_present) {
            Video::RequestPresentFromBackground();
        }
    }
}

struct Event final : KernelObject, HostObject<XKEVENT>
{
    bool manualReset;
    std::atomic<bool> signaled;
    uint32_t guestHeaderEA{0};

    Event(XKEVENT* header)
        : manualReset(!header->Type), signaled(!!header->SignalState)
    {
        guestHeaderEA = g_memory.MapVirtual(header);
    }

    Event(bool manualReset, bool initialState)
        : manualReset(manualReset), signaled(initialState)
    {
        guestHeaderEA = 0;
    }

    uint32_t Wait(uint32_t timeout) override
    {
        if (timeout == 0)
        {
            if (manualReset)
            {
                if (!signaled)
                    return STATUS_TIMEOUT;
            }
            else
            {
                bool expected = true;
                if (!signaled.compare_exchange_strong(expected, false))
                    return STATUS_TIMEOUT;
            }
        }
        else if (timeout == INFINITE)
        {
            if (manualReset)
            {
                signaled.wait(false);
            }
            else
            {
                while (true)
                {
                    bool expected = true;
                    if (signaled.compare_exchange_weak(expected, false))
                        break;

                    signaled.wait(expected);
                }
            }
        }
        else
        {
            // Timed wait implementation
            auto start = std::chrono::steady_clock::now();
            auto deadline = start + std::chrono::milliseconds(timeout);

            if (manualReset)
            {
                // Manual-reset event: wait until signaled or timeout
                while (!signaled.load())
                {
                    if (std::chrono::steady_clock::now() >= deadline)
                        return STATUS_TIMEOUT;
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
            else
            {
                // Auto-reset event: wait until we can consume the signal or timeout
                while (true)
                {
                    bool expected = true;
                    if (signaled.compare_exchange_weak(expected, false))
                        break;

                    if (std::chrono::steady_clock::now() >= deadline)
                        return STATUS_TIMEOUT;
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        }

        return STATUS_SUCCESS;
    }

    bool Set()
    {
        signaled = true;

        if (manualReset)
            signaled.notify_all();
        else
            signaled.notify_one();

        return TRUE;
    }

    bool Reset()
    {
        signaled = false;
        return TRUE;
    }
};

static inline bool Mw05VblankPumpEnabled() {
    // Default ON to improve bring-up, allow disabling with MW05_VBLANK_PUMP=0
    static const bool on = [](){
        if (const char* v = std::getenv("MW05_VBLANK_PUMP"))
            return !(v[0]=='0' && v[1]=='\0');
        return true;
    }();
    return on;
}

// VdSwap is called with 8 parameters based on IDA decompilation:
// r3: command buffer ptr, r4: swap params ptr, r5: GPU queue ptr
// r6: system command buffer, r7: ???, r8-r10: pointers to surface/format/flags
void VdSwap(uint32_t pWriteCur, uint32_t pParams, uint32_t pRingBase,
            uint32_t pSysCmdBuf, uint32_t param5, uint32_t pSurfaceAddr,
            uint32_t pFormat, uint32_t param8)
{
    // PERFORMANCE FIX: Use simple stub like UnleashedRecomp to avoid hangs
    // The complex implementation with 1400+ lines was causing performance issues and hangs
    static std::atomic<uint32_t> s_vdswap_count{0};
    uint32_t count = s_vdswap_count.fetch_add(1, std::memory_order_relaxed);

    // CRITICAL FIX (2025-11-01): Log VdSwap parameters to find where game writes PM4 commands
    // The game is NOT writing to system buffer (0x00F00000) or ring buffer
    // It must be writing to a different buffer - r3 (pWriteCur) is the command buffer write cursor!
    static const bool s_log_params = [](){
        if (const char* v = std::getenv("MW05_VDSWAP_LOG_PARAMS"))
            return !(v[0]=='0' && v[1]=='\0');
        return true; // DEFAULT: ON - we need to find the PM4 buffer!
    }();

    if (s_log_params && count < 10) {
        fprintf(stderr, "[VDSWAP-PARAMS] Call #%u: r3(WriteCur)=%08X r4(Params)=%08X r5(RingBase)=%08X r6(SysCmdBuf)=%08X r7=%08X r8(Surface)=%08X r9(Format)=%08X r10=%08X\n",
                count + 1, pWriteCur, pParams, pRingBase, pSysCmdBuf, param5, pSurfaceAddr, pFormat, param8);
        fflush(stderr);

        // Try to scan the buffer pointed to by r3 (pWriteCur)
        // This is likely where the game writes PM4 commands!
        if (GuestOffsetInRange(pWriteCur, 4)) {
            // Read the write cursor value
            if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(pWriteCur))) {
                uint32_t write_ptr = *p; // May be native or big-endian
                fprintf(stderr, "[VDSWAP-PARAMS] WriteCur points to: %08X (raw value at %08X)\n", write_ptr, pWriteCur);
                fflush(stderr);
            }
        }
    }

    // Mark that the guest performed a swap
    g_guestHasSwapped.store(true, std::memory_order_release);
    g_sawRealVdSwap.store(true, std::memory_order_release);

    // CRITICAL FIX: Scan system command buffer for PM4 commands
    // Game writes PM4 commands to system command buffer (0x00F00000), not ring buffer!
    // This is the natural place to scan for draw commands when the game presents a frame.
    PM4_ScanSystemCommandBuffer();

    // Request present from background (minimal overhead)
    Video::RequestPresentFromBackground();

    // That's it! Simple stub like UnleashedRecomp.
    // All the complex PM4 scanning, ring buffer management, etc. was causing hangs.
}

// Forward declarations for use in VBLANK handler
static void Mw05ForceRegisterGfxNotifyIfRequested();
static void Mw05ForceCreateRenderThreadIfRequested();

void Mw05StartVblankPumpOnce() {
    if (!Mw05VblankPumpEnabled()) return;
    bool expected = false;
    if (!g_vblankPumpRun.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    KernelTraceHostOp("HOST.VblankPump.start");
    std::thread([]{
        using namespace std::chrono;

        // Enable high-resolution timers on Windows to ensure accurate 16ms sleep
        #ifdef _WIN32
        timeBeginPeriod(1);
        // Increase thread priority to ensure vblank pump runs at 60 Hz
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        #endif

        const auto period = milliseconds(16);
        // Env toggles (latched once)
        // Only force presents from the vblank pump when explicitly requested.
        // Using MW05_FORCE_PRESENT here caused crashes because Video::Present()
        // manipulates ImGui/SDL state and must run on the main thread. The main
        // thread already presents when MW05_FORCE_PRESENT=1 (see main.cpp). To
        // avoid double-present and cross-thread UI calls, the background pump
        // now listens to MW05_FORCE_PRESENT_BG instead.
        static const bool s_force_present = [](){
            if (const char* v = std::getenv("MW05_FORCE_PRESENT_BG"))
                return !(v[0]=='0' && v[1]=='\0');
            return false;
        }();
        static const bool s_pump_events = [](){
            if (const char* v = std::getenv("MW05_PUMP_EVENTS"))
                return !(v[0]=='0' && v[1]=='\0');
            return false; // default OFF: only pump events on main thread
        }();
        static auto pump_start_time = std::chrono::steady_clock::now();
        static auto last_iteration_end = std::chrono::steady_clock::now();

        // PERFORMANCE: VBlank debug logging (disabled by default - causes massive FPS drop)
        static const bool s_debug_vblank = [](){
            if (const char* v = std::getenv("MW05_DEBUG_VBLANK"))
                return !(v[0]=='0' && v[1]=='\0');
            return false; // DISABLED by default for performance
        }();

        // CRITICAL DEBUG: Wrap entire loop in SEH to detect silent crashes
        #if defined(_WIN32)
        __try {
        #endif
        while (true) {
            // Check g_vblankPumpRun at start of each iteration
            const bool pumpRun = g_vblankPumpRun.load(std::memory_order_acquire);
            const uint32_t preTickValue = g_vblankTicks.load(std::memory_order_acquire);

            if (s_debug_vblank && preTickValue < 20) {
                fprintf(stderr, "[VBLANK-LOOP-START] About to increment tick (current=%u) pumpRun=%d\n", preTickValue, pumpRun ? 1 : 0);
                fflush(stderr);
            }
            if (!pumpRun) {
                if (s_debug_vblank) {
                    fprintf(stderr, "[VBLANK-LOOP-EXIT] g_vblankPumpRun is false at tick %u, exiting loop\n", preTickValue);
                    fflush(stderr);
                }
                break;
            }

            auto loop_start = std::chrono::steady_clock::now();
            auto inter_iteration_gap = std::chrono::duration_cast<std::chrono::milliseconds>(loop_start - last_iteration_end);
            auto elapsed_since_start = std::chrono::duration_cast<std::chrono::milliseconds>(loop_start - pump_start_time);

            // Global vblank tick counter for gating guest ISR dispatches
            const uint32_t currentTick = g_vblankTicks.fetch_add(1u, std::memory_order_acq_rel);

            // PERFORMANCE: Disabled by default - enable with MW05_DEBUG_VBLANK=1
            if (s_debug_vblank) {
                if (currentTick < 20) {
                    fprintf(stderr, "[VBLANK-TICK-INCREMENTED] currentTick=%u (after fetch_add)\n", currentTick);
                    fflush(stderr);
                }

                if (currentTick % 100 == 0) {
                    KernelTraceHostOpF("HOST.VblankPump.loop_executing tick=%u", currentTick);
                }

                if (currentTick == 3800) {
                    KernelTraceHostOpF("HOST.VblankPump.TICK_3800_REACHED tick=%u", currentTick);
                }

                static bool s_detailed_logging = false;
                if (currentTick >= 350 && currentTick <= 450) {
                    if (!s_detailed_logging) {
                        fprintf(stderr, "[VBLANK-DETAILED] Enabling detailed logging from tick 350-450\n");
                        fflush(stderr);
                        s_detailed_logging = true;
                    }
                    fprintf(stderr, "[VBLANK-TICK] count=%u (detailed mode) g_vblankPumpRun=%d\n", currentTick, g_vblankPumpRun.load(std::memory_order_acquire) ? 1 : 0);
                    fflush(stderr);
                } else if (currentTick == 0 || currentTick % 10 == 0 || currentTick < 20) {
                    fprintf(stderr, "[VBLANK-TICK] count=%u g_vblankPumpRun=%d\n", currentTick, g_vblankPumpRun.load(std::memory_order_acquire) ? 1 : 0);
                    fflush(stderr);
                }

                if (currentTick % 100 == 0) {
                    const uint32_t cb = VdGetGraphicsInterruptCallback();
                    const uint32_t ctx = VdGetGraphicsInterruptContext();
                    fprintf(stderr, "[VBLANK-ISR-STATUS] tick=%u cb=%08X ctx=%08X\n", currentTick, cb, ctx);
                    fflush(stderr);
                }
            }

            // DISABLED: Event signaling workaround - g_memory.Translate doesn't exist
            // The real issue is that threads are stuck in sleep loops instead of waiting on events
            // Need to find what sets r31 to 0 in the sleep function to allow threads to exit

            // PERFORMANCE FIX: Mw05ForceCreateMissingWorkerThreads() is DISABLED (just returns immediately)
            // Removed call to avoid wasted function calls on every tick

            // CRITICAL FIX: Signal event 0x400007E0 to wake up sleeping threads
            // According to CRITICAL_FINDINGS_VdInit.md, threads with entry 0x828508A8 are stuck
            // in sleep loops waiting for this event to be signaled. This event wakes them up
            // so they can call sub_823AF590 -> VdInitializeEngines with correct parameters.
            static const bool s_signal_wake_event = [](){
                if (const char* v = std::getenv("MW05_SIGNAL_WAKE_EVENT"))
                    return !(v[0]=='0' && v[1]=='\0');
                return true; // ENABLED BY DEFAULT - this is critical for game progression
            }();
            if (s_signal_wake_event && currentTick >= 10) {  // Wait a few ticks for event to be created
                constexpr uint32_t WAKE_EVENT_EA = 0x400007E0;
                if (auto* event = reinterpret_cast<XKEVENT*>(g_memory.Translate(WAKE_EVENT_EA))) {
                    static uint32_t s_signal_count = 0;
                    if (KeSetEvent(event, 0, false)) {
                        s_signal_count++;
                        if (s_debug_vblank && (s_signal_count <= 5 || s_signal_count % 100 == 0)) {
                            fprintf(stderr, "[VBLANK-WAKE] Signaled event 0x%08X (count=%u tick=%u)\n",
                                    WAKE_EVENT_EA, s_signal_count, currentTick);
                            fflush(stderr);
                            KernelTraceHostOpF("HOST.VblankPump.signal_wake_event ea=%08X count=%u tick=%u",
                                             WAKE_EVENT_EA, s_signal_count, currentTick);
                        }
                    }
                }
            }

            // MW05 FIX: Call VdCallGraphicsNotificationRoutines periodically to invoke registered callbacks
            // Only do this if a real callback is registered (not the host magic value)
            const uint32_t cb_check = VdGetGraphicsInterruptCallback();
            if (cb_check && cb_check != kHostDefaultVdIsrMagic && currentTick >= 350) {
                // Configurable frequency for callback invocation
                static const uint32_t s_callback_frequency = [](){
                    if (const char* v = std::getenv("MW05_GFX_CALLBACK_FREQUENCY"))
                        return (uint32_t)std::strtoul(v, nullptr, 10);
                    return 1u; // default: every tick (60Hz)
                }();

                // Configurable max invocations (0 = unlimited)
                static const uint32_t s_max_invocations = [](){
                    if (const char* v = std::getenv("MW05_GFX_CALLBACK_MAX_INVOCATIONS"))
                        return (uint32_t)std::strtoul(v, nullptr, 10);
                    return 0u; // default: unlimited
                }();

                static uint32_t s_vdcall_count = 0;

                // Check if we've reached the max invocations limit
                if (s_max_invocations > 0 && s_vdcall_count >= s_max_invocations) {
                    static bool s_logged_limit = false;
                    if (!s_logged_limit && s_debug_vblank) {
                        fprintf(stderr, "[MW05_FIX] Reached max invocations limit (%u), stopping callback invocations\n", s_max_invocations);
                        fflush(stderr);
                        s_logged_limit = true;
                    }
                    return; // Stop invoking the callback
                }

                if (currentTick % s_callback_frequency == 0) {
                    s_vdcall_count++;
                    if (s_debug_vblank && s_vdcall_count % 10 == 1) {  // Log every 10 calls
                        fprintf(stderr, "[MW05_FIX] Calling VdCallGraphicsNotificationRoutines tick=%u count=%u cb=%08X freq=%u max=%u\n",
                                currentTick, s_vdcall_count, cb_check, s_callback_frequency, s_max_invocations);
                        fflush(stderr);
                    }
                    // EXPERIMENT: Disable callback invocation to test if registration alone causes the crash
                    static bool s_disable_invocation = Mw05EnvEnabled("MW05_DISABLE_CALLBACK_INVOCATION");
                    if (!s_disable_invocation) {
                        // CRITICAL FIX: Call graphics callback directly - NO NEW THREAD!
                        // Creating a new thread for every VBlank tick (60 Hz) causes massive memory leak!
                        // The callback is already called from the VBlank pump thread, which is async.

                        // CRITICAL: Ensure guest context for this thread so function table is initialized!
                        // This is safe because the VBlank pump thread already has a guest context
                        EnsureGuestContextForThisThread("VBlankPump.AsyncCallback");

                        // Common pattern from Xenia: emit both source=0 (vblank-like) and source=1 (auxiliary)
                        VdCallGraphicsNotificationRoutines(0u);
                        VdCallGraphicsNotificationRoutines(1u);
                    } else if (s_debug_vblank) {
                        fprintf(stderr, "[MW05_FIX] Callback invocation DISABLED (registration only)\n");
                        fflush(stderr);
                    }
                }
            }

            if (s_debug_vblank && currentTick < 20) {
                fprintf(stderr, "[VBLANK-AFTER-GFX-CB] tick=%u after graphics callback section\n", currentTick);
                fflush(stderr);
            }

            // CRITICAL DEBUG: Log before video thread section
            if (s_debug_vblank && currentTick < 20) {
                fprintf(stderr, "[VBLANK-BEFORE-VIDEO-THREAD] tick=%u about to check video thread section\n", currentTick);
                fflush(stderr);
            }

            // EXPERIMENTAL: Force-trigger video thread initialization after boot completes
            // In Xenia, MW05 creates the video thread (F800000C) after ~227 vblank ticks.
            // MW05 appears to be waiting for a condition that's not being met in our version.
            // Force-call the initialization function to trigger the proper thread creation chain.
            static const bool s_force_video_thread = [](){
                if (const char* v = std::getenv("MW05_FORCE_VIDEO_THREAD"))
                    return !(v[0]=='0' && v[1]=='\0');
                return true; // default: ENABLED (game doesn't create video thread naturally)
            }();
            static const uint32_t s_force_video_thread_tick = [](){
                if (const char* v = std::getenv("MW05_FORCE_VIDEO_THREAD_TICK"))
                    return (uint32_t)std::strtoul(v, nullptr, 10);
                return 300u; // wait longer for natural initialization
            }();
            static std::atomic<bool> s_video_thread_created{false};
            static bool s_logged_config = false;

            // Log configuration once at tick 0
            if (s_debug_vblank && currentTick == 0 && !s_logged_config) {
                fprintf(stderr, "[VBLANK-CONFIG] s_force_video_thread=%d s_force_video_thread_tick=%u\n",
                    s_force_video_thread, s_force_video_thread_tick);
                fflush(stderr);
                s_logged_config = true;
            }

            if (s_force_video_thread && !s_video_thread_created.load(std::memory_order_acquire)) {
                // Periodically check if singleton was created naturally
                if ((currentTick % 50) == 0) {
                    // Check if the singleton pointer address is valid before accessing it
                    constexpr uint32_t SINGLETON_ADDR = 0x82911B78;  // Absolute guest address
                    if (void* ptr = g_memory.Translate(SINGLETON_ADDR)) {
                        uint32_t singleton_ptr = *reinterpret_cast<uint32_t*>(ptr);
                        if (singleton_ptr != 0) {
                            if (s_debug_vblank) {
                                fprintf(stderr, "[VBLANK-NATURAL] Singleton created naturally at tick=%u ptr=%08X\n", currentTick, singleton_ptr);
                                fflush(stderr);
                            }
                            s_video_thread_created.store(true, std::memory_order_release);
                        }
                    } else {
                        // Address not mapped - skip check
                        static bool logged_once = false;
                        if (s_debug_vblank && !logged_once) {
                            fprintf(stderr, "[VBLANK-NATURAL] Singleton address 0x%08X not mapped, skipping checks\n", SINGLETON_ADDR);
                            fflush(stderr);
                            logged_once = true;
                        }
                    }
                }

                // Debug: log when we're checking the condition
                if (s_debug_vblank && (currentTick == s_force_video_thread_tick || currentTick == s_force_video_thread_tick - 1)) {
                    fprintf(stderr, "[VBLANK-CHECK] currentTick=%u threshold=%u will_trigger=%d\n",
                        currentTick, s_force_video_thread_tick, currentTick >= s_force_video_thread_tick);
                    fflush(stderr);
                }
                if (currentTick >= s_force_video_thread_tick) {
                    bool expected = false;
                    if (s_video_thread_created.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                        fprintf(stderr, "[VBLANK-FORCE] Triggering ForceVideoThread at tick=%u\n", currentTick);
                        fflush(stderr);
                        KernelTraceHostOpF("HOST.ForceVideoThread.trigger tick=%u", currentTick);

                        // Call sub_82849DE8 which is the proper initialization function
                        // This will set up the correct parameters and call the thread creation chain:
                        // sub_82849DE8 -> sub_82881020 -> sub_82880FA0 -> sub_82885A70 -> sub_8284F548 -> ExCreateThread

                        // Set up a minimal context for the call
                        EnsureGuestContextForThisThread("ForceVideoThread");
                        PPCContext ctx{};
                        if (auto* cur = GetPPCContext()) ctx = *cur;

                        // Based on IDA analysis of sub_82548F18 which calls sub_82849DE8:
                        // At 0x82548F44: li r3, 3  (before calling sub_82849DE8)
                        // The function expects r3 to be a count/size parameter
                        // This is used by sub_8284A698 to calculate allocation size: r5 * 9 * 16 = 3 * 144 = 432 bytes
                        ctx.r3.u32 = 3;
                        ctx.r1.u64 = 0x00010000;  // stack pointer (safe default)
                        ctx.lr = 0;  // return address

                        // Read the singleton pointer at dword_82911B78
                        uint32_t singleton_ptr = *reinterpret_cast<uint32_t*>(g_memory.base + 0x02911B78);
                        fprintf(stderr, "[VBLANK-FORCE] dword_82911B78 = %08X\n", singleton_ptr);
                        fflush(stderr);

                        if (singleton_ptr == 0) {
                            // Optionally try a more natural init first: call sub_82548F18 (which calls sub_82849DE8 internally)
                            bool try_natural = false;
                            if (const char* v = std::getenv("MW05_TRY_CALL_82548F18")) try_natural = !(v[0]=='0' && v[1]=='\0');
                            if (try_natural) {
                                fprintf(stderr, "[VBLANK-FORCE] MW05_TRY_CALL_82548F18=1, calling sub_82548F18 first\n");
                                fflush(stderr);
                                extern void sub_82548F18(PPCContext& ctx, uint8_t* base);
                                // Per IDA, r3=3 before calling sub_82849DE8 inside sub_82548F18
                                ctx.r3.u32 = 3;
                                sub_82548F18(ctx, g_memory.base);
                                fprintf(stderr, "[VBLANK-FORCE] sub_82548F18 returned r3=%08X\n", ctx.r3.u32);
                                fflush(stderr);
                                // Re-read the singleton pointer after natural path
                                singleton_ptr = __builtin_bswap32(*reinterpret_cast<uint32_t*>(g_memory.base + 0x02911B78));
                                fprintf(stderr, "[VBLANK-FORCE] After 82548F18, dword_82911B78 = %08X\n", singleton_ptr);
                                fflush(stderr);
                                // If natural path produced an object pointer but didn't store the singleton, set it now
                                if (singleton_ptr == 0 && ctx.r3.u32 != 0) {
                                    fprintf(stderr, "[VBLANK-FORCE] Using 82548F18 result to set singleton r3=%08X\n", ctx.r3.u32);
                                    *reinterpret_cast<uint32_t*>(g_memory.base + 0x02911B78) = __builtin_bswap32(ctx.r3.u32);
                                    singleton_ptr = ctx.r3.u32;
                                    fprintf(stderr, "[VBLANK-FORCE] Singleton now set to %08X (from 82548F18)\n", singleton_ptr);
                                    fflush(stderr);
                                }
                            }

                            if (singleton_ptr == 0) {
                                // Singleton not created yet, fall back to direct call
                                fprintf(stderr, "[VBLANK-FORCE] Singleton not created, calling sub_82849DE8\n");
                                fflush(stderr);
                                KernelTraceHostOp("HOST.ForceVideoThread.call_sub_82849DE8");
                                extern void sub_82849DE8(PPCContext& ctx, uint8_t* base);
                                sub_82849DE8(ctx, g_memory.base);
                                fprintf(stderr, "[VBLANK-FORCE] sub_82849DE8 returned r3=%08X\n", ctx.r3.u32);
                                fflush(stderr);
                                KernelTraceHostOpF("HOST.ForceVideoThread.complete r3=%08X", ctx.r3.u32);

                                // Re-read the singleton pointer using byte-swapped read for correct byte order
                                singleton_ptr = __builtin_bswap32(*reinterpret_cast<uint32_t*>(g_memory.base + 0x02911B78));
                                fprintf(stderr, "[VBLANK-FORCE] After creation, dword_82911B78 = %08X\n", singleton_ptr);
                                fflush(stderr);
                            }

                            // CRITICAL FIX: sub_82849DE8 is not setting the singleton pointer for some reason
                            // Manually set it to the returned object pointer
                            if (singleton_ptr == 0 && ctx.r3.u32 != 0) {
                                fprintf(stderr, "[VBLANK-FORCE] MANUALLY setting singleton to r3=%08X\n", ctx.r3.u32);
                                fflush(stderr);
                                *reinterpret_cast<uint32_t*>(g_memory.base + 0x02911B78) = __builtin_bswap32(ctx.r3.u32);  // Write in big-endian format
                                singleton_ptr = ctx.r3.u32;
                                fprintf(stderr, "[VBLANK-FORCE] Singleton now set to %08X\n", singleton_ptr);
                                fflush(stderr);

                                // CRITICAL FIX #2: The singleton is a wrapper that contains a pointer to the actual video object
                                // We need to allocate the video object and store its pointer in the singleton
                                extern uint32_t GetVideoVtableGuestAddr();  // Defined in heap.cpp
                                extern Heap g_userHeap;  // Defined in heap.cpp
                                uint32_t vtable_addr = GetVideoVtableGuestAddr();
                                if (vtable_addr != 0) {
                                    // Read the pointer to the actual video object from singleton+0
                                    uint32_t video_obj_ptr = LoadBE32_Watched(g_memory.base, singleton_ptr + 0x00);
                                    fprintf(stderr, "[VBLANK-FORCE] Singleton wrapper at %08X, actual video object at %08X\n",
                                            singleton_ptr, video_obj_ptr);
                                    fflush(stderr);

                                    if (video_obj_ptr == 0) {
                                        // Allocate the video object (256 bytes should be enough)
                                        void* video_obj_host = g_userHeap.Alloc(256);
                                        if (video_obj_host) {
                                            video_obj_ptr = g_memory.MapVirtual(video_obj_host);
                                            fprintf(stderr, "[VBLANK-FORCE] Allocated video object at %08X (host=%p)\n",
                                                    video_obj_ptr, video_obj_host);
                                            fflush(stderr);

                                            // Store the video object pointer in the singleton
                                            StoreBE32_Watched(g_memory.base, singleton_ptr + 0x00, video_obj_ptr);
                                        } else {
                                            fprintf(stderr, "[VBLANK-FORCE] ERROR: Failed to allocate video object!\n");
                                            fflush(stderr);
                                        }
                                    }

                                    if (video_obj_ptr != 0) {
                                        fprintf(stderr, "[VBLANK-FORCE] Initializing video object at %08X with vtable %08X\n",
                                                video_obj_ptr, vtable_addr);
                                        fflush(stderr);

                                        // Write vtable pointer at video_obj+0
                                        StoreBE32_Watched(g_memory.base, video_obj_ptr + 0x00, vtable_addr);

                                        // Write fake thread handle at video_obj+0x64
                                        StoreBE32_Watched(g_memory.base, video_obj_ptr + 0x64, 0x00000001);

                                        // Write ready flag at video_obj+0x60
                                        StoreBE32_Watched(g_memory.base, video_obj_ptr + 0x60, 0x00000002);

                                        // Verify
                                        uint32_t vptr = LoadBE32_Watched(g_memory.base, video_obj_ptr + 0x00);
                                        uint32_t thr = LoadBE32_Watched(g_memory.base, video_obj_ptr + 0x64);
                                        fprintf(stderr, "[VBLANK-FORCE] Video object initialized: vptr=%08X thr=%08X\n", vptr, thr);
                                        fflush(stderr);

                                        // MW05 DEBUG: Disabled forced initialization - let the game call it naturally
                                        // The game will call VdSetGraphicsInterruptCallback when it's ready
                                        // We were forcing it too early before the context was set up
                                    }
                                } else {
                                    fprintf(stderr, "[VBLANK-FORCE] ERROR: Vtable not allocated yet!\n");
                                    fflush(stderr);
                                }
                            }
                        } else {
                            fprintf(stderr, "[VBLANK-FORCE] Singleton already exists at %08X\n", singleton_ptr);
                            fflush(stderr);
                        }

                        // Check if thread handle exists at offset 0x64
                        if (singleton_ptr != 0) {
                            uint32_t thread_handle = LoadBE32_Watched(g_memory.base, singleton_ptr + 0x64);
                            fprintf(stderr, "[VBLANK-FORCE] Thread handle at +0x64 = %08X\n", thread_handle);
                            fflush(stderr);

                            if (thread_handle != 0) {
                                fprintf(stderr, "[VBLANK-FORCE] Video thread exists, handle=%08X\n", thread_handle);
                                fflush(stderr);
                                // TODO: Check thread state and potentially resume it
                            } else {
                                fprintf(stderr, "[VBLANK-FORCE] WARNING: Singleton exists but no thread handle!\n");
                                fflush(stderr);
                            }
                        }
                    }
                }

                // CRITICAL FIX #3: Initialize dword_82A2AC40 (wait loop global)
                // This global is used by the wait loop at 0x825CEE18/0x825CEE28
                // It needs to point to a valid object for the wait functions to work
                static bool s_wait_loop_global_initialized = false;
                if (!s_wait_loop_global_initialized) {
                    const uint32_t wait_global_addr = 0x82A2AC40;
                    uint32_t wait_obj_ptr = LoadBE32_Watched(g_memory.base, wait_global_addr);

                    if (wait_obj_ptr == 0) {
                        // Check if loop breaker is enabled
                        static const bool s_break_wait_loop = [](){
                            if (const char* v = std::getenv("MW05_BREAK_WAIT_LOOP")) {
                                return !(v[0] == '0' && v[1] == '\0');
                            }
                            return false;
                        }();

                        // NOTE: dword_82A2D1AC initialization moved to KiSystemStartup() in main.cpp
                        // to ensure it's initialized BEFORE guest code starts executing

                        if (s_break_wait_loop) {
                            // Allocate a fake wait object (64 bytes should be enough)
                            extern Heap g_userHeap;
                            void* wait_obj_host = g_userHeap.Alloc(64);
                            if (wait_obj_host) {
                                wait_obj_ptr = g_memory.MapVirtual(wait_obj_host);
                                fprintf(stderr, "[VBLANK-FORCE] Allocated wait object at %08X (host=%p)\n",
                                        wait_obj_ptr, wait_obj_host);
                                fflush(stderr);

                                // Store the wait object pointer in the global
                                StoreBE32_Watched(g_memory.base, wait_global_addr, wait_obj_ptr);

                                // Initialize the wait object with some reasonable values
                                // (We don't know the exact structure, so just zero it)
                                memset(wait_obj_host, 0, 64);

                                fprintf(stderr, "[VBLANK-FORCE] Initialized dword_82A2AC40 = %08X\n", wait_obj_ptr);
                                fflush(stderr);

                                s_wait_loop_global_initialized = true;
                            } else {
                                fprintf(stderr, "[VBLANK-FORCE] ERROR: Failed to allocate wait object!\n");
                                fflush(stderr);
                            }
                        }
                    } else {
                        fprintf(stderr, "[VBLANK-FORCE] Wait object already exists at %08X\n", wait_obj_ptr);
                        fflush(stderr);
                        s_wait_loop_global_initialized = true;
                    }
                }
            }

            // Try to register graphics callback if requested (will check delay internally)
            Mw05ForceRegisterGfxNotifyIfRequested();

            // Try to create render thread if requested (will check delay internally)
            Mw05ForceCreateRenderThreadIfRequested();

            // CRITICAL FIX: Set video thread work flag to trigger file loading
            // The video thread at entry 0x82849D40 waits for flag at context+96 to become non-zero
            // Once set, it enters a work processing loop that loads files
            static const bool s_force_video_work_flag = [](){
                if (const char* v = std::getenv("MW05_FORCE_VIDEO_WORK_FLAG"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            static bool s_logged_work_flag_config = false;
            if (!s_logged_work_flag_config) {
                fprintf(stderr, "[VBLANK-VIDEO-WORK-CONFIG] MW05_FORCE_VIDEO_WORK_FLAG=%d\n", s_force_video_work_flag ? 1 : 0);
                fflush(stderr);
                s_logged_work_flag_config = true;
            }
            static bool s_video_work_flag_set = false;
            if (s_force_video_work_flag && !s_video_work_flag_set && currentTick >= 310) {
                // Video thread context is at 0x500120 (from ExCreateThread call)
                const uint32_t video_ctx_ea = 0x500120;
                const uint32_t work_flag_ea = video_ctx_ea + 96;  // offset +96
                if (auto* flag_ptr = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(work_flag_ea))) {
                    uint32_t current = flag_ptr->get();
                    if (current == 0) {
                        *flag_ptr = be<uint32_t>(1);  // Set flag to 1 to trigger work processing
                        s_video_work_flag_set = true;
                        fprintf(stderr, "[VBLANK-VIDEO-WORK] Set video thread work flag at 0x%08X (was=0x%08X now=0x00000001) tick=%u\n",
                                work_flag_ea, current, currentTick);
                        fflush(stderr);
                        KernelTraceHostOpF("HOST.VideoThread.work_flag.set ea=%08X tick=%u", work_flag_ea, currentTick);
                    } else {
                        // Flag already set by game - log once
                        static bool s_logged_already_set = false;
                        if (!s_logged_already_set) {
                            fprintf(stderr, "[VBLANK-VIDEO-WORK] Video thread work flag already set to 0x%08X at tick=%u\n", current, currentTick);
                            fflush(stderr);
                            s_logged_already_set = true;
                        }
                        s_video_work_flag_set = true;
                    }
                } else {
                    static bool s_logged_translate_fail = false;
                    if (!s_logged_translate_fail) {
                        fprintf(stderr, "[VBLANK-VIDEO-WORK] Failed to translate address 0x%08X at tick=%u\n", work_flag_ea, currentTick);
                        fflush(stderr);
                        s_logged_translate_fail = true;
                    }
                }
            }

            if (currentTick >= 340 && currentTick <= 360) {
                fprintf(stderr, "[VBLANK-POST-REG] After Mw05ForceRegisterGfxNotifyIfRequested tick=%u\n", currentTick);
                fflush(stderr);
            }

            // Keep a pending interrupt flowing; if event not yet registered,
            // Mw05SignalVdInterruptEvent() will fail and we keep the pending flag.
            if (!Mw05SignalVdInterruptEvent()) {
                g_vdInterruptPending.store(true, std::memory_order_release);
            }

            // CRITICAL DEBUG: Log before sleep-skip flag code
            if (currentTick % 100 == 0) {
                KernelTraceHostOpF("HOST.VblankPump.before_sleep_skip tick=%u", currentTick);
            }

            // CRITICAL: Set sleep-skip flag to allow main loop to progress
            // The main loop at sub_82441E80 checks the sleep-skip flag at 0x82A1FF40
            // When this flag is ZERO, the main loop calls sub_8262D9D0 (sleep function)
            // When this flag is non-zero, the main loop calls sub_8262DE60 (frame update function)
            // We need to set this flag to non-zero to allow the main loop to progress
            {
                // CRITICAL DEBUG: Log every 100 ticks to verify this block is executing
                if (currentTick % 100 == 0) {
                    KernelTraceHostOpF("HOST.VblankPump.sleep_skip_block_entered tick=%u", currentTick);
                }

                const uint32_t sleep_skip_flag_ea = 0x82A1FF40;
                volatile uint32_t* sleep_skip_flag_ptr = static_cast<volatile uint32_t*>(g_memory.Translate(sleep_skip_flag_ea));

                // CRITICAL DEBUG: Log translate result
                if (currentTick % 100 == 0) {
                    KernelTraceHostOpF("HOST.VblankPump.sleep_skip_translate ea=%08X ptr=%p tick=%u",
                                      sleep_skip_flag_ea, sleep_skip_flag_ptr, currentTick);
                }

                if (sleep_skip_flag_ptr) {
                    // CRITICAL DEBUG: Log that we entered the if block
                    if (currentTick % 100 == 0) {
                        KernelTraceHostOpF("HOST.VblankPump.sleep_skip_if_entered tick=%u", currentTick);
                    }

                    // Read current value with SEH protection
                    uint32_t current_value = 0;
                    bool read_success = false;
                    #if defined(_MSC_VER)
                        __try {
                            current_value = _byteswap_ulong(*sleep_skip_flag_ptr);
                            read_success = true;
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            if (currentTick % 100 == 0) {
                                KernelTraceHostOpF("HOST.VblankPump.sleep_skip_read_exception code=%08X tick=%u",
                                                  (unsigned)GetExceptionCode(), currentTick);
                            }
                        }
                    #else
                        current_value = __builtin_bswap32(*sleep_skip_flag_ptr);
                        read_success = true;
                    #endif

                    if (!read_success) {
                        continue; // Skip this iteration if read failed
                    }

                    // CRITICAL DEBUG: Log the value we read
                    if (currentTick % 100 == 0) {
                        KernelTraceHostOpF("HOST.VblankPump.sleep_skip_value value=%08X tick=%u", current_value, currentTick);
                    }

                    // Set flag to 1 if it's currently 0
                    if (current_value == 0) {
                        #if defined(_MSC_VER)
                            *sleep_skip_flag_ptr = _byteswap_ulong(1);
                        #else
                            *sleep_skip_flag_ptr = __builtin_bswap32(1);
                        #endif

                        std::atomic_thread_fence(std::memory_order_release);

                        static uint32_t s_sleep_skip_set_count = 0;
                        s_sleep_skip_set_count++;
                        if (s_sleep_skip_set_count <= 10 || (s_sleep_skip_set_count % 60 == 0)) {
                            KernelTraceHostOpF("HOST.VblankPump.sleep_skip_set was=%08X now=00000001 tick=%u count=%u",
                                              current_value, currentTick, s_sleep_skip_set_count);
                        }
                    }
                }
            }

            // CRITICAL DEBUG: Log after sleep-skip flag block
            if (currentTick % 100 == 0) {
                KernelTraceHostOpF("HOST.VblankPump.after_sleep_skip_block tick=%u", currentTick);
            }

            // REMOVED: Manual VBlank flag-setting workaround
            // Let the game's VBlank callback handle this naturally

            // CRITICAL FIX: Force-call CreateDevice to bypass blocked state machine
            // The game is stuck in TitleState loop and never calls CreateDevice naturally
            // This unblocks render thread creation and allows the game to progress
            {
                extern void Mw05ForceCallCreateDeviceIfRequested();
                Mw05ForceCallCreateDeviceIfRequested();
            }

            // CRITICAL FIX: Force-call sub_825AAE58 to create the main render thread
            // After CreateDevice succeeds, we need to call sub_825AAE58 which creates thread 0x825AA970
            {
                extern void Mw05ForceCallCreateRenderThreadIfRequested();
                Mw05ForceCallCreateRenderThreadIfRequested();
            }

            // Advance the ring-buffer write-back pointer a bit so guest
            // polling sees steady GPU progress even before the first present.
            uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);
            if (wb) {
                if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb))) {
                    uint32_t cur = *rptr;
                    uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
                    uint32_t mask = len_log2 ? ((1u << len_log2) - 1u) : 0xFFFFu;
                    uint32_t next = (cur + 0x40u) & mask; // smaller step than present
                    *rptr = next ? next : 0x20u;
                }
            }

            // Grace check: if no graphics ISR registered after a while, log once
            static int s_vblankTicks = 0;
            static const int s_isr_grace_ticks = [](){
                if (const char* v = std::getenv("MW05_ISR_GRACE_TICKS"))
                    return (int)std::strtoul(v, nullptr, 10);
                return 300; // ~5 seconds @60Hz
            }();
            static bool s_isr_missing_logged = false;
            if (!s_isr_missing_logged && ++s_vblankTicks >= s_isr_grace_ticks) {
                if (VdGetGraphicsInterruptCallback() == 0) {
                    KernelTraceHostOp("HOST.VdISR.missing.after_grace");
                }
                s_isr_missing_logged = true;
            }



            // Optional: diff-based write-watch on the System Command Buffer to detect PM4 construction
            static const bool s_sysbuf_watch = [](){
                if (const char* v = std::getenv("MW05_PM4_SYSBUF_WATCH"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false; // default OFF
            }();
            static uint32_t s_watch_base_ea = 0;
            static bool s_sysbuf_write_logged_once = false;
            static int  s_sysbuf_write_log_budget = 32; // cap verbose logs
            static const bool s_sysbuf_watch_verbose = [](){
                if (const char* v = std::getenv("MW05_PM4_SYSBUF_WATCH_VERBOSE"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            constexpr uint32_t kWatchDwords = 16384; // 64 KiB window (full sysbuf)
            static uint32_t s_snap[kWatchDwords] = {};
            static bool s_snap_inited = false;
            if (s_sysbuf_watch) {
                uint32_t sysbuf = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
                if (sysbuf) {
                    if (s_watch_base_ea != sysbuf) { s_watch_base_ea = sysbuf; s_snap_inited = false; s_sysbuf_write_logged_once = false; s_sysbuf_write_log_budget = 32; }
                    if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(sysbuf))) {
                        uint32_t cur[kWatchDwords];
                        for (uint32_t i = 0; i < kWatchDwords; ++i) {
                        #if defined(_MSC_VER)
                            cur[i] = _byteswap_ulong(p[i]);
                        #else
                            cur[i] = __builtin_bswap32(p[i]);
                        #endif
                        }
                        if (!s_snap_inited) {
                            for (uint32_t i = 0; i < kWatchDwords; ++i) s_snap[i] = cur[i];
                            s_snap_inited = true;
                        } else {
                            uint32_t off = kWatchDwords;
                            for (uint32_t i = 0; i < kWatchDwords; ++i) { if (cur[i] != s_snap[i]) { off = i; break; } }
                            if (off < kWatchDwords) {
                                // Compute a rough span length until zeros or window end
                                uint32_t span = 0;
                                for (uint32_t j = off; j < kWatchDwords; ++j) { if (cur[j] == 0) break; ++span; }
                                uint32_t d0 = (off < kWatchDwords) ? cur[off + 0] : 0;
                                uint32_t d1 = (off + 1 < kWatchDwords) ? cur[off + 1] : 0;
                                uint32_t d2 = (off + 2 < kWatchDwords) ? cur[off + 2] : 0;
                                uint32_t d3 = (off + 3 < kWatchDwords) ? cur[off + 3] : 0;
                                if (!s_sysbuf_write_logged_once || s_sysbuf_watch_verbose) {
                                    if (!s_sysbuf_watch_verbose || s_sysbuf_write_log_budget > 0) {
                                        KernelTraceHostOpF("HOST.PM4.SysBufWrite.hit base=%08X off=%u bytes=%u d0=%08X d1=%08X d2=%08X d3=%08X",
                                                           sysbuf, off * 4u, span * 4u, d0, d1, d2, d3);
                                        if (s_sysbuf_watch_verbose) {
                                            --s_sysbuf_write_log_budget;
                                        } else {
                                            s_sysbuf_write_logged_once = true;
                                        }
                                    }
                                    // Optional: immediately bridge sysbuf -> ring on detected write
                                    {
                                        static const bool s_sysbuf_to_ring = [](){
                                            if (const char* v = std::getenv("MW05_PM4_SYSBUF_TO_RING"))
                                                return !(v[0]=='0' && v[1]=='\0');
                                            return false;
                                        }();
                                        if (s_sysbuf_to_ring)
                                        {
                                            uint32_t sysbufEA = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
                                            uint32_t rbBase   = g_RbBase.load(std::memory_order_acquire);
                                            uint32_t rbLenL2  = g_RbLen.load(std::memory_order_acquire);
                                            const uint32_t rbSizeBytes = (rbLenL2 < 32u) ? (1u << (rbLenL2 & 31u)) : 0u;
                                            auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(g_RbWriteBackPtr.load(std::memory_order_acquire)));
                                            uint8_t* sysHost = reinterpret_cast<uint8_t*>(g_memory.Translate(sysbufEA));
                                            uint8_t* rbHost  = reinterpret_cast<uint8_t*>(g_memory.Translate(rbBase));
                                            if (sysHost && rbHost && rptr && rbSizeBytes)
                                            {
                                                const uint32_t headSkip = 0x10u; // skip 16-byte header
                                                const uint32_t payloadBytes = (rbSizeBytes > headSkip) ? (rbSizeBytes - headSkip) : 0u;
                                                if (payloadBytes)
                                                {
                                                    memcpy(rbHost, sysHost + headSkip, payloadBytes);
                                                    const uint32_t offs = payloadBytes & (rbSizeBytes - 1u);
                                                    *rptr = offs ? offs : 0x20u;
                                                    KernelTraceHostOpF("HOST.PM4.SysBufBridge.copy bytes=%u offs=%04X (on_write)", payloadBytes, offs);
                                                    PM4_OnRingBufferWrite(offs);
                                                }
                                            }
                                        }
                                    }

                                }
                                // Update snapshot to the new content
                                for (uint32_t i = 0; i < kWatchDwords; ++i) s_snap[i] = cur[i];
                            }
                        }
                    }
                }
            }


            // Optionally invoke the guest graphics interrupt callback at vblank.
            // Many titles rely on this ISR to drive internal state machines.
            static const bool cb_on = [](){
                // Strong override
                if (const char* f = std::getenv("MW05_VBLANK_CB_FORCE"))
                    return !(f[0]=='0' && f[1]=='\0');
                // Honor explicit toggle
                if (const char* v = std::getenv("MW05_VBLANK_CB"))
                    return !(v[0]=='0' && v[1]=='\0');
                // When forcing presents or kicking video early, avoid calling guest ISR
                // to prevent crashes from partially initialized guest state.
                // FIX: Check the VALUE of the env vars, not just their existence!
                auto is_enabled = [](const char* name) -> bool {
                    const char* v = std::getenv(name);
                    return v && !(v[0]=='0' && v[1]=='\0');
                };
                bool force_present = is_enabled("MW05_FORCE_PRESENT");
                bool force_present_bg = is_enabled("MW05_FORCE_PRESENT_BG");
                bool kick_video = is_enabled("MW05_KICK_VIDEO");

                // DIAGNOSTIC: Log the decision
                KernelTraceHostOpF("HOST.VblankPump.cb_on_init force_present=%d force_present_bg=%d kick_video=%d",
                                  (int)force_present, (int)force_present_bg, (int)kick_video);

                if (force_present || force_present_bg || kick_video) {
                    // Normally suppress guest ISR during forced-present bring-up, but allow
                    // the host-side default ISR if explicitly enabled.
                    if (const char* d = std::getenv("MW05_DEFAULT_VD_ISR"))
                        return !(d[0]=='0' && d[1]=='\0');
                    KernelTraceHostOp("HOST.VblankPump.cb_on_init DISABLED due to force_present/bg/kick");
                    return false;
                }
                // Default: enabled only when not in forced-present bring-up paths
                KernelTraceHostOp("HOST.VblankPump.cb_on_init ENABLED");
                return true;
            }();
            if (cb_on) {
                Mw05MaybeInstallDefaultVdIsr();

                const uint32_t cb = VdGetGraphicsInterruptCallback();
                if (cb == kHostDefaultVdIsrMagic) {
                    KernelTraceHostOp("HOST.VblankPump.host_isr");
                    Mw05RunHostDefaultVdIsrNudge("vblank");
                } else if (cb) {
                    const uint32_t ctx = VdGetGraphicsInterruptContext();

                    // DEBUG: Check the VD ISR flag value before calling the callback
                    static uint32_t s_debug_flag_check_count = 0;
                    if (s_debug_flag_check_count < 5) {
                        const uint32_t flag_ea = 0x7FC86544;
                        if (void* flag_ptr = g_memory.Translate(flag_ea)) {
                            uint32_t flag_value = *(volatile uint32_t*)flag_ptr;
                            fprintf(stderr, "[VD-ISR-FLAG-CHECK] Before callback: ea=0x%08X value=0x%08X (count=%u)\n",
                                    flag_ea, flag_value, s_debug_flag_check_count);
                            fflush(stderr);
                        } else {
                            fprintf(stderr, "[VD-ISR-FLAG-CHECK] ERROR: Failed to translate flag address 0x%08X\n", flag_ea);
                            fflush(stderr);
                        }
                        s_debug_flag_check_count++;
                    }

                    // Gate guest ISR dispatch for a few ticks after startup to avoid early-boot crashes
                    static const uint32_t s_guest_isr_delay3 = [](){
                        if (const char* v = std::getenv("MW05_GUEST_ISR_DELAY_TICKS"))
                            return (uint32_t)std::strtoul(v, nullptr, 10);
                        return 0u; // default: no delay unless configured
                    }();
                    const uint32_t ticks3 = g_vblankTicks.load(std::memory_order_acquire);
                    if (ticks3 < s_guest_isr_delay3) {
                        KernelTraceHostOpF("HOST.VblankPump.guest_isr.skip.early ticks=%u<%u", (unsigned)ticks3, (unsigned)s_guest_isr_delay3);
                    } else {
                        static int s_isr_call_count = 0;
                        if (s_isr_call_count < 5 || s_isr_call_count % 60 == 0) {
                            KernelTraceHostOpF("HOST.VblankPump.guest_isr.call ticks=%u cb=%08X ctx=%08X count=%d",
                                              (unsigned)ticks3, cb, ctx, s_isr_call_count);
                        }
                        s_isr_call_count++;
                        EnsureGuestContextForThisThread("VblankPump");

                        // CRITICAL DEBUG: Log before calling guest ISR
                        if (currentTick < 20) {
                            fprintf(stderr, "[VBLANK-BEFORE-GUEST-ISR] tick=%u about to call guest ISR cb=0x%08X ctx=0x%08X\n", currentTick, cb, ctx);
                            fflush(stderr);
                        }

                        // CRITICAL FIX: Call guest ISR directly - NO NEW THREAD!
                        // Creating a new thread for every VBlank tick (60 Hz) causes massive memory leak!
                        // The VBlank pump already runs in a separate thread, so this is already async.
                        #if defined(_WIN32)
                            __try {
                                GuestToHostFunction<void>(cb, 0u, ctx);
                            } __except (EXCEPTION_EXECUTE_HANDLER) {
                                DWORD exceptionCode = GetExceptionCode();

                                // Log first exception only to avoid spam
                                static std::atomic<bool> s_logged_exception{false};
                                if (!s_logged_exception.exchange(true, std::memory_order_relaxed)) {
                                    fprintf(stderr, "[VBLANK-ISR-EXCEPTION] Graphics callback threw exception (context not initialized yet)\n");
                                    fprintf(stderr, "[VBLANK-ISR-EXCEPTION]   Exception code: 0x%08lX\n", exceptionCode);
                                    fprintf(stderr, "[VBLANK-ISR-EXCEPTION]   Callback: 0x%08X\n", cb);
                                    fprintf(stderr, "[VBLANK-ISR-EXCEPTION]   Context: 0x%08X\n", ctx);
                                    fprintf(stderr, "[VBLANK-ISR-EXCEPTION]   Will continue calling callback - it should work once context is initialized\n");
                                    fflush(stderr);
                                }
                            }
                        #else
                            GuestToHostFunction<void>(cb, 0u, ctx);
                        #endif

                        // CRITICAL DEBUG: Log after calling guest ISR
                        if (currentTick < 20) {
                            fprintf(stderr, "[VBLANK-AFTER-GUEST-ISR] tick=%u guest ISR called asynchronously\n", currentTick);
                            fflush(stderr);
                        }
                    }
                } else if (const char* d = std::getenv("MW05_DEFAULT_VD_ISR")) {
                    if (!(d[0]=='0' && d[1]=='\0')) {
                        KernelTraceHostOp("HOST.VblankPump.default_isr");
                        uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);
                        if (wb) {
                            if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb))) {
                                uint32_t cur = *rptr;
                                uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
                                uint32_t mask = len_log2 ? ((1u << len_log2) - 1u) : 0xFFFFu;
                                uint32_t next = (cur + 0x40u) & mask;
                                *rptr = next ? next : 0x20u;
                            }
                        }
                        Video::RequestPresentFromBackground();
                    }
                }
            }

            // Optional: request a present each vblank to keep swapchain moving.
            // Do not call Present() from the background thread; signal the main thread instead.
            // Keep swapchain/fps moving until the guest has performed at least one swap.
            // Additionally, if no Present has occurred for MW05_PRESENT_HEARTBEAT_MS, request one to keep UI/FPS responsive.
            // DEFAULT: 100ms heartbeat to ensure FPS counter never goes stale
            static const uint64_t s_present_heartbeat_ms = [](){
                if (const char* v = std::getenv("MW05_PRESENT_HEARTBEAT_MS"))
                    return (uint64_t)std::strtoull(v, nullptr, 10);
                return uint64_t(100); // Default: 100ms heartbeat (10 FPS minimum)
            }();
            const uint64_t last_ms = g_lastPresentMs.load(std::memory_order_acquire);
            const uint64_t now_ms  = SDL_GetTicks64();
            const bool stale = s_present_heartbeat_ms && (now_ms - last_ms > s_present_heartbeat_ms);

            // Debug: log heartbeat status every 60 ticks (~1s)
            static int s_hb_dbg = 0;
            if (s_present_heartbeat_ms && ((++s_hb_dbg) % 60) == 0) {
                KernelTraceHostOpF("HOST.PresentHeartbeat.status hb_ms=%llu last_ms=%llu now_ms=%llu delta=%llu stale=%d swapped=%d",
                    s_present_heartbeat_ms, last_ms, now_ms, (now_ms - last_ms), int(stale), int(Mw05HasGuestSwapped()));
            }

            if (s_force_present || !Mw05HasGuestSwapped() || stale) {
                Video::RequestPresentFromBackground();
                if (stale && s_hb_dbg % 10 == 0) {
                    KernelTraceHostOp("HOST.PresentHeartbeat.request_stale");
                }
            }

            // Optional: call VdSwap from vblank pump to drive continuous presents
            // This simulates the guest calling VdSwap repeatedly at 60 Hz
            // DISABLED BY DEFAULT - only enable for testing VdSwap infrastructure
            static const bool s_vblank_vdswap = [](){
                if (const char* v = std::getenv("MW05_VBLANK_VDSWAP"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false; // DEFAULT: OFF - let guest drive VdSwap
            }();
            static bool s_logged_vblank_vdswap = false;
            if (!s_logged_vblank_vdswap) {
                fprintf(stderr, "[VBLANK-CONFIG] MW05_VBLANK_VDSWAP=%d (0=guest drives, 1=host drives)\n", s_vblank_vdswap);
                fflush(stderr);
                s_logged_vblank_vdswap = true;
            }
            if (s_vblank_vdswap) {
                // Call VdSwap with 8 parameters (all zeros for test)
                VdSwap(0, 0, 0, 0, 0, 0, 0, 0);
            }

            // Optional: one-shot nudge into MW05 present-wrapper region to try waking the scheduler
            static const bool s_force_present_wrapper_once = [](){
                if (const char* v = std::getenv("MW05_FORCE_PRESENT_WRAPPER_ONCE"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            static bool s_present_wrapper_fired = false;
            static int s_present_wrapper_delay = [](){
                if (const char* v = std::getenv("MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS"))
                    return (int)std::strtoul(v, nullptr, 10);
                return 240; // ~4s at 60Hz
            }();
            // FPW debug: confirm we reach the FPW block each nudge
            KernelTraceHostOp("HOST.FPW.debug.reach");

            // Debug: periodically log FPW-once status to understand why it may not fire
            static int s_fpwo_dbg = 0;
            if (((++s_fpwo_dbg) % 60) == 0) {
                {
                    const uint32_t seen = Mw05Trace_SchedR3SeenCount();
                    KernelTraceHostOpF(
                        "HOST.ForcePresentWrapperOnce.status enabled=%d fired=%d sawSwap=%d delay=%d seen=%u",
                        int(s_force_present_wrapper_once), int(s_present_wrapper_fired),
                        int(g_sawRealVdSwap.load(std::memory_order_acquire)), s_present_wrapper_delay, seen);
                }
            }

            if (s_force_present_wrapper_once && !s_present_wrapper_fired && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                if (--s_present_wrapper_delay <= 0) {
                    const uint32_t seen = Mw05Trace_SchedR3SeenCount();
                    if (seen < 3u) {
                        KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.defer r3_unstable seen=%u", seen);
                        s_present_wrapper_delay = 60; // retry after ~1s
                    } else {
                        KernelTraceHostOp("HOST.ForcePresentWrapperOnce.fire");
                        // Construct a PPCContext based on the current thread guest context so r1/r2/r13/TOC are valid,
                        // then override only the arguments we care about (r3, r4).
                        PPCContext ctx{};
                        if (auto* cur = GetPPCContext()) {
                            ctx = *cur; // copy full live guest context for this thread
                        }
                        ctx.r3.u32 = Mw05Trace_LastSchedR3();
                        if (ctx.r4.u32 == 0) ctx.r4.u32 = 0x40; // observed typical arg
                        KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.ctx r3=%08X", ctx.r3.u32);
                            // Optional: dump a small window of the scheduler context
                            if (const char* dump = std::getenv("MW05_DUMP_SCHED_CTX")) {
                                if (!(dump[0]=='0' && dump[1]=='\0') && GuestOffsetInRange(ctx.r3.u32, 64)) {
                                    const uint32_t base = ctx.r3.u32;
                                    const uint32_t* p32 = reinterpret_cast<const uint32_t*>(g_memory.Translate(base));
                                    if (p32) {
                                    #if defined(_MSC_VER)
                                        auto bswap = [](uint32_t v){ return _byteswap_ulong(v); };
                                    #else
                                        auto bswap = [](uint32_t v){ return __builtin_bswap32(v); };
                                    #endif
                                        KernelTraceHostOpF("HOST.SchedCtxDump %08X: %08X %08X %08X %08X",
                                                           base + 0, bswap(p32[0]), bswap(p32[1]), bswap(p32[2]), bswap(p32[3]));
                                        KernelTraceHostOpF("HOST.SchedCtxDump %08X: %08X %08X %08X %08X",
                                                           base + 16, bswap(p32[4]), bswap(p32[5]), bswap(p32[6]), bswap(p32[7]));
                                    }
                                }
                            }


                        // If no valid r3 was captured yet, allow an explicit env fallback
                        if (!GuestOffsetInRange(ctx.r3.u32, 4)) {
                            if (const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
                                uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
                                if (GuestOffsetInRange(env_r3, 4)) {
                                    ctx.r3.u32 = env_r3;
                                    KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.ctx.env r3=%08X", ctx.r3.u32);
                                } else {
                                    KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.ctx.env_invalid r3=%08X", env_r3);
                                }
                            }
                        }

                        if (GuestOffsetInRange(ctx.r3.u32, 4)) {
                            uint8_t* base = g_memory.base;
                            KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.enter r3=%08X", ctx.r3.u32);
                            EnsureGuestContextForThisThread("FPWOnce");
                        #if defined(_WIN32)
                            __try {
                                // Call by effective address via the guest call bridge to ensure proper marshalling
                                bool use_inner = false;
                                if (const char* v = std::getenv("MW05_FORCE_PRESENT_INNER"))
                                    use_inner = !(v[0]=='0' && v[1]=='\0');
                                const uint32_t target = use_inner ? 0x825A54F0u : 0x82598A20u;
                                GuestToHostFunction<void>(target, ctx.r3.u32, ctx.r4.u32);
                                KernelTraceHostOp("HOST.ForcePresentWrapperOnce.ret");
                                // Optional: after present-manager returns, probe syscmd/ring headers
                                // Optional: directly kick PM4 builder once if inner present returned but no draws
                                if (const char* k = std::getenv("MW05_FPW_KICK_PM4")) {
                                    if (!(k[0]=='0' && k[1]=='\0') && GuestOffsetInRange(ctx.r3.u32, 4)) {
                                    #if defined(_WIN32)
                                        __try {
                                            GuestToHostFunction<void>(0x82595FC8u, ctx.r3.u32, 64u);
                                            KernelTraceHostOpF("HOST.FPW.kick.pm4 r3=%08X", ctx.r3.u32);
                                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                                            KernelTraceHostOpF("HOST.FPW.kick.pm4.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                        }
                                    #else
                                        GuestToHostFunction<void>(0x82595FC8u, ctx.r3.u32, 64u);
                                        KernelTraceHostOpF("HOST.FPW.kick.pm4 r3=%08X", ctx.r3.u32);
                                    #endif
                                    }
                                }

                                if (const char* e = std::getenv("MW05_FPW_POST_SYSBUF")) {
                                    if (!(e[0]=='0' && e[1]=='\0')) {
                                        // Get system command buffer address
                                        uint32_t sys_ea = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
                                        KernelTraceHostOpF("HOST.FPW.post.sysbuf ea=%08X", sys_ea);
                                        if (sys_ea && GuestOffsetInRange(sys_ea, 32)) {
                                            const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(sys_ea));
                                            if (p) {
                                                KernelTraceHostOpF(
                                                    "HOST.FPW.post.sysbuf.head %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X",
                                                    p[0],p[1],p[2],p[3], p[4],p[5],p[6],p[7], p[8],p[9],p[10],p[11], p[12],p[13],p[14],p[15]);
                                            }
                                        }
                                        // GPU-id writeback address/value, if any
                                        uint32_t gid_ea = g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_acquire);
                                        uint32_t gid_val = 0;
                                        if (gid_ea && GuestOffsetInRange(gid_ea, sizeof(uint32_t))) {
                                            if (auto* pv = reinterpret_cast<uint32_t*>(g_memory.Translate(gid_ea))) gid_val = *pv;
                                        }
                                        KernelTraceHostOpF("HOST.FPW.post.gpuid ea=%08X val=%08X", gid_ea, gid_val);
                                        // Ring write-back pointer value, if configured
                                        uint32_t rb_wb_ea = g_RbWriteBackPtr.load(std::memory_order_acquire);
                                        uint32_t rb_val = 0;
                                        if (rb_wb_ea && GuestOffsetInRange(rb_wb_ea, sizeof(uint32_t))) {
                                            if (auto* rpv = reinterpret_cast<uint32_t*>(g_memory.Translate(rb_wb_ea))) rb_val = *rpv;
                                        }
                                        KernelTraceHostOpF("HOST.FPW.post.rptr_wb ea=%08X val=%08X", rb_wb_ea, rb_val);
                                        // Optional heavy scan of sysbuf for PM4 right now
                                        if (const char* s = std::getenv("MW05_PM4_SCAN_ON_FPW_POST")) {
                                            if (!(s[0]=='0' && s[1]=='\0') && sys_ea) {
                                                extern void PM4_ScanLinear(uint32_t addr, uint32_t bytes);
                                                PM4_ScanLinear(sys_ea, 64u * 1024u);
                                            }
                                        }
                                    }
                                }

                            } __except (EXCEPTION_EXECUTE_HANDLER) {
                                KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                // Fallback: try inner present-manager and/or direct PM4 kick so we can still progress
                                if (GuestOffsetInRange(ctx.r3.u32, 4)) {
                                    __try {
                                        GuestToHostFunction<void>(0x825A54F0u, ctx.r3.u32, ctx.r4.u32 ? ctx.r4.u32 : 0x40u);
                                        KernelTraceHostOp("HOST.FPW.fallback.inner.ret");
                                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                                        KernelTraceHostOpF("HOST.FPW.fallback.inner.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                    }
                                    if (const char* k = std::getenv("MW05_FPW_KICK_PM4")) {
                                        if (!(k[0]=='0' && k[1]=='\0')) {
                                            __try {
                                                GuestToHostFunction<void>(0x82595FC8u, ctx.r3.u32, 64u);
                                                KernelTraceHostOpF("HOST.FPW.kick.pm4 r3=%08X", ctx.r3.u32);
                                            } __except (EXCEPTION_EXECUTE_HANDLER) {
                                                KernelTraceHostOpF("HOST.FPW.kick.pm4.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                            }
                                        }
                                    }
                                }
                            }
                        #else
                            GuestToHostFunction<void>(0x82598A20u, ctx.r3.u32, ctx.r4.u32);
                            KernelTraceHostOp("HOST.ForcePresentWrapperOnce.ret");
                        #endif
                            s_present_wrapper_fired = true;
                        } else {
                            KernelTraceHostOp("HOST.ForcePresentWrapperOnce.defer r3_unsuitable");
                            // Throttle retries: wait ~1s before attempting again
                            s_present_wrapper_delay = 60;
                            // Do not mark fired; try again later when r3 is captured
                        }
                    }
                }
            }
            // Optional: repeat present-manager a few times if no swap/draws yet (diagnostic)
            static int s_fpwo_retries = [](){
                if (const char* v = std::getenv("MW05_FPW_RETRIES")) return (int)std::strtoul(v, nullptr, 10);
                return 0; // default OFF
            }();
            static int s_fpwo_retry_delay = [](){
                if (const char* v = std::getenv("MW05_FPW_RETRY_TICKS")) return (int)std::strtoul(v, nullptr, 10);
                return 120; // ~2s
            }();
            static int s_fpwo_retry_timer = s_fpwo_retry_delay;
            if (s_force_present_wrapper_once && s_present_wrapper_fired && s_fpwo_retries > 0 && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                extern uint64_t PM4_GetDrawCount();
                if (PM4_GetDrawCount() == 0) {
                    if (--s_fpwo_retry_timer <= 0) {
                        const uint32_t seen = Mw05Trace_SchedR3SeenCount();
                        if (seen >= 3u) {
                            PPCContext ctx{};
                            if (auto* cur = GetPPCContext()) ctx = *cur;
                            ctx.r3.u32 = Mw05Trace_LastSchedR3();
                            if (!GuestOffsetInRange(ctx.r3.u32, 4)) {
                                if (const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
                                    uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
                                    if (GuestOffsetInRange(env_r3, 4)) ctx.r3.u32 = env_r3;
                                }
                            }
                            if (GuestOffsetInRange(ctx.r3.u32, 4)) {
                                EnsureGuestContextForThisThread("FPWOnce.refire");
                                bool use_inner = false;
                                if (const char* v = std::getenv("MW05_FORCE_PRESENT_INNER"))
                                    use_inner = !(v[0]=='0' && v[1]=='\0');
                                const uint32_t target = use_inner ? 0x825A54F0u : 0x82598A20u;
                                KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.refire r3=%08X left=%d", ctx.r3.u32, s_fpwo_retries);
                            #if defined(_WIN32)
                                __try {
                                    GuestToHostFunction<void>(target, ctx.r3.u32, ctx.r4.u32 ? ctx.r4.u32 : 0x40u);
                                    KernelTraceHostOp("HOST.ForcePresentWrapperOnce.refire.ret");
                                } __except (EXCEPTION_EXECUTE_HANDLER) {
                                    KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.refire.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                }
                            #else
                                GuestToHostFunction<void>(target, ctx.r3.u32, ctx.r4.u32 ? ctx.r4.u32 : 0x40u);
                                KernelTraceHostOp("HOST.ForcePresentWrapperOnce.refire.ret");
                            #endif
                                --s_fpwo_retries;
                                s_fpwo_retry_timer = s_fpwo_retry_delay;
                            } else {
                                // No valid r3; re-arm quickly to try again
                                s_fpwo_retry_timer = 30; // ~0.5s
                            }
                        } else {
                            // r3 sightings unstable; wait a bit and try again
                            s_fpwo_retry_timer = 60;
                        }
                    }
                }
            }



            // Optional: tick frame counter e70 once per vblank when enabled
            static const bool s_tick_e70 = [](){
                if (const char* v = std::getenv("MW05_VD_TICK_E70"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            if (s_tick_e70) {
                const uint32_t ea = 0x00060E70u;
                if (GuestOffsetInRange(ea, sizeof(uint64_t))) {
                    if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                        uint64_t v = *p;
                    #if defined(_MSC_VER)
                        v = _byteswap_uint64(v);
                    #else
                        v = __builtin_bswap64(v);
                    #endif
                        v += 1;
                    #if defined(_MSC_VER)
                        *p = _byteswap_uint64(v);
                    #else
                        *p = __builtin_bswap64(v);
                    #endif
                    }
                }
            }

            // Optional: toggle e68 bit0 each vblank to emulate a flip flag if enabled
            static const bool s_toggle_e68 = [](){
                if (const char* v = std::getenv("MW05_VD_TOGGLE_E68"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            if (s_toggle_e68) {
                const uint32_t ea = 0x00060E68u;
                if (GuestOffsetInRange(ea, sizeof(uint64_t))) {
                    if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                        uint64_t v = *p;
                    #if defined(_MSC_VER)
                        v = _byteswap_uint64(v);
                    #else
                        v = __builtin_bswap64(v);
                    #endif
                        v ^= 1ull;
                    #if defined(_MSC_VER)
                        *p = _byteswap_uint64(v);
                    #else
                        *p = __builtin_bswap64(v);
                    #endif
                    }
                }
            }

            // Optional: toggle e58 mask each vblank to emulate a changing progress bit
            static const bool s_toggle_e58 = [](){
                if (const char* v = std::getenv("MW05_VD_TOGGLE_E58"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            static const uint64_t s_toggle_e58_mask = [](){
                const char* v = std::getenv("MW05_VD_TOGGLE_E58_MASK");
                if (v && *v) {
                    return std::strtoull(v, nullptr, 0);
                }
                return 0x100ull; // default to 0x100 as seeded by the title
            }();
            if (s_toggle_e58 && s_toggle_e58_mask) {
                const uint32_t ea = 0x00060E58u;
                if (GuestOffsetInRange(ea, sizeof(uint64_t))) {
                    if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                        uint64_t v = *p;
                    #if defined(_MSC_VER)
                        v = _byteswap_uint64(v);
                    #else
                        v = __builtin_bswap64(v);
                    #endif
                        v ^= s_toggle_e58_mask;
                    #if defined(_MSC_VER)
                        *p = _byteswap_uint64(v);
                    #else
                        *p = __builtin_bswap64(v);
                    #endif
                    }
                }
            }

            // Optional: PM4-style frontbuffer-ready writeback each vblank (opt-in)
            static const bool s_pm4_fake_swap = [](){
                if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            if (s_pm4_fake_swap) {
                // OR-mask writeback (default: e68 |= 0x2)
                static const uint32_t s_pm4_fb_addr = [](){
                    if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_ADDR"))
                        return (uint32_t)std::strtoul(v, nullptr, 0);
                    return 0x00060E68u; // e68 by default
                }();
                static const uint64_t s_pm4_fb_or = [](){
                    if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_OR"))
                        return std::strtoull(v, nullptr, 0);
                    return 0x2ull; // ack bit by default
                }();
                if (s_pm4_fb_addr && s_pm4_fb_or && GuestOffsetInRange(s_pm4_fb_addr, sizeof(uint64_t))) {
                    if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(s_pm4_fb_addr))) {
                        uint64_t v = *p;
                    #if defined(_MSC_VER)
                        v = _byteswap_uint64(v);
                    #else
                        v = __builtin_bswap64(v);
                    #endif
                        const uint64_t nv = v | s_pm4_fb_or;
                    #if defined(_MSC_VER)
                        *p = _byteswap_uint64(nv);
                    #else
                        *p = __builtin_bswap64(nv);
                    #endif
                        KernelTraceHostOpF("HOST.PM4.fake_swap.or addr=%08X |= %llX -> %llX", s_pm4_fb_addr, (unsigned long long)s_pm4_fb_or, (unsigned long long)nv);
                    }
                }

                // Optional: second PM4-style OR writeback target (independent addr/mask)
                static const uint32_t s_pm4_fb2_addr = [](){
                    if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP2_ADDR"))
                        return (uint32_t)std::strtoul(v, nullptr, 0);
                    return 0u; // disabled by default
                }();
                static const uint64_t s_pm4_fb2_or = [](){
                    if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP2_OR"))
                        return std::strtoull(v, nullptr, 0);
                    return 0ull; // disabled by default
                }();
                if (s_pm4_fb2_addr && s_pm4_fb2_or && GuestOffsetInRange(s_pm4_fb2_addr, sizeof(uint64_t))) {
                    if (auto* p2 = reinterpret_cast<uint64_t*>(g_memory.Translate(s_pm4_fb2_addr))) {
                        uint64_t v2 = *p2;
                    #if defined(_MSC_VER)
                        v2 = _byteswap_uint64(v2);
                    #else
                        v2 = __builtin_bswap64(v2);
                    #endif
                        const uint64_t nv2 = v2 | s_pm4_fb2_or;
                    #if defined(_MSC_VER)
                        *p2 = _byteswap_uint64(nv2);
                    #else
                        *p2 = __builtin_bswap64(nv2);
                    #endif
                        KernelTraceHostOpF("HOST.PM4.fake_swap2.or addr=%08X |= %llX -> %llX", s_pm4_fb2_addr, (unsigned long long)s_pm4_fb2_or, (unsigned long long)nv2);
                    }
                }


                // Optional token writeback (simulate PM4 write-data)
                static const uint32_t s_pm4_token_addr = [](){
                    if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_TOKEN_ADDR"))
                        return (uint32_t)std::strtoul(v, nullptr, 0);
                    return 0u; // disabled by default
                }();
                static uint32_t s_pm4_token = [](){
                    if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_TOKEN_BASE"))
                        return (uint32_t)std::strtoul(v, nullptr, 0);
                    return 0xC00002F0u; // seen commonly in logs
                }();
                static const uint32_t s_pm4_token_inc = [](){
                    if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_TOKEN_INC"))
                        return (uint32_t)std::strtoul(v, nullptr, 0);
                    return 1u;
                }();
                static const bool s_token_on_flip = [](){
                    if (const char* v = std::getenv("MW05_VD_TOKEN_ON_FLIP"))
                        return !(v[0]=='0' && v[1]=='\0');
                    return false;
                }();
                static int s_prev_flip_for_token = -1;
                if (s_pm4_token_addr && GuestOffsetInRange(s_pm4_token_addr, sizeof(uint32_t))) {
                    bool should_emit_token = true;
                    if (s_token_on_flip) {
                        // Sample flip bit from e68
                        const uint32_t ea_e68 = 0x00060E68u;
                        if (GuestOffsetInRange(ea_e68, sizeof(uint64_t))) {
                            if (auto* p68 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e68))) {
                                uint64_t v68 = *p68;
                            #if defined(_MSC_VER)
                                v68 = _byteswap_uint64(v68);
                            #else
                                v68 = __builtin_bswap64(v68);
                            #endif
                                const int cur_flip = int(v68 & 1ull);
                                if (s_prev_flip_for_token < 0) {
                                    s_prev_flip_for_token = cur_flip;
                                    should_emit_token = false; // don't emit on first observation
                                } else {
                                    should_emit_token = (cur_flip == 1 && s_prev_flip_for_token == 0);
                                    s_prev_flip_for_token = cur_flip;
                                }
                            }
                        }
                    }
                    if (should_emit_token) {
                        if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(s_pm4_token_addr))) {
                            const uint32_t val = s_pm4_token;
                            // big-endian store
                            uint32_t be =
                        #if defined(_MSC_VER)
                                _byteswap_ulong(val);
                        #else
                                __builtin_bswap32(val);
                        #endif
                            *p = be;
                            KernelTraceHostOpF("HOST.PM4.fake_swap.token addr=%08X val=%08X", s_pm4_token_addr, val);
                            s_pm4_token += s_pm4_token_inc;
                        }
                    }
                }

                // Optional: synthesize a VdSwap-equivalent present on rising flip until a real VdSwap happens
                static const bool s_synth_vdswap_on_flip = [](){
                    if (const char* v = std::getenv("MW05_SYNTH_VDSWAP_ON_FLIP"))
                        return !(v[0]=='0' && v[1]=='\0');
                    return false;
                }();
                static int s_prev_flip_for_synth = -1;
                if (s_synth_vdswap_on_flip && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                    const uint32_t ea_e68 = 0x00060E68u;
                    if (GuestOffsetInRange(ea_e68, sizeof(uint64_t))) {
                        if (auto* p68 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e68))) {
                            uint64_t v68 = *p68;
                        #if defined(_MSC_VER)
                            v68 = _byteswap_uint64(v68);
                        #else
                            v68 = __builtin_bswap64(v68);
                        #endif
                            const int cur_flip = int(v68 & 1ull);
                            bool rising = false;
                            if (s_prev_flip_for_synth < 0) {
                                s_prev_flip_for_synth = cur_flip;
                            } else {
                                rising = (cur_flip == 1 && s_prev_flip_for_synth == 0);
                                s_prev_flip_for_synth = cur_flip;
                            }
                            if (rising) {
                                KernelTraceHostOp("HOST.SynthVdSwapOnFlip.fire");
                                Mw05MarkGuestSwappedOnce();
                                Video::RequestPresentFromBackground();
                            }
                        }
                    }
                }

            }

            // Optional: lightweight VD read-trace (sample and log on change)
            static const bool s_vd_read_trace = [](){
                if (const char* v = std::getenv("MW05_VD_READ_TRACE"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            if (s_vd_read_trace) {
                auto rd64 = [](uint32_t ea)->uint64_t{
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0ull;
                    if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                        uint64_t v = *p;
                    #if defined(_MSC_VER)
                        return _byteswap_uint64(v);
                    #else
                        return __builtin_bswap64(v);
                    #endif
                    }
                    return 0ull;
                };
                struct Snap { uint64_t e48,e50,e58,e60,e68,e70,e78,e80; };
                static Snap prev{~0ull,~0ull,~0ull,~0ull,~0ull,~0ull,~0ull,~0ull};
                Snap cur{ rd64(0x00060E48u), rd64(0x00060E50u), rd64(0x00060E58u), rd64(0x00060E60u), rd64(0x00060E68u), rd64(0x00060E70u), rd64(0x00060E78u), rd64(0x00060E80u) };
                if (cur.e48!=prev.e48 || cur.e50!=prev.e50 || cur.e58!=prev.e58 || cur.e60!=prev.e60 || cur.e68!=prev.e68 || cur.e70!=prev.e70 || cur.e78!=prev.e78 || cur.e80!=prev.e80) {
                    KernelTraceHostOpF("HOST.VD.read.trace e48=%016llX e50=%016llX e58=%016llX e60=%016llX e68=%016llX e70=%016llX e78=%016llX e80=%016llX",
                        (unsigned long long)cur.e48,(unsigned long long)cur.e50,(unsigned long long)cur.e58,(unsigned long long)cur.e60,(unsigned long long)cur.e68,(unsigned long long)cur.e70,(unsigned long long)cur.e78,(unsigned long long)cur.e80);
                    prev = cur;
                }
            }

            // Optional: read-only swap-edge detector on e68. Logs when selected bit toggles.
            static const bool s_swap_detect = [](){
                if (const char* v = std::getenv("MW05_PM4_SWAP_DETECT"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            static const uint64_t s_swap_mask = [](){
                if (const char* v = std::getenv("MW05_PM4_SWAP_DETECT_MASK"))
                    return std::strtoull(v, nullptr, 0);
                return 0x1ull; // default: watch bit 0
            }();
            if (s_swap_detect) {
                auto rd64e = [](uint32_t ea)->uint64_t{
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0ull;
                    if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                        uint64_t v = *p;
                    #if defined(_MSC_VER)
                        return _byteswap_uint64(v);
                    #else
                        return __builtin_bswap64(v);
                    #endif
                    }
                    return 0ull;
                };
                static int s_prev_bit = -1;
                static uint64_t s_prev_e68 = ~0ull;
                static const bool s_pm4_swap_present = [](){
                    if (const char* v = std::getenv("MW05_PM4_SWAP_PRESENT"))
                        return !(v[0]=='0' && v[1]=='\0');
                    return false; // default off unless explicitly enabled
                }();
                const uint64_t e68 = rd64e(0x00060E68u);
                const int bit = (e68 & s_swap_mask) ? 1 : 0;
                if (s_prev_bit < 0) {
                    KernelTraceHostOpF("HOST.PM4.swap.init mask=%llX bit=%d e68=%016llX", (unsigned long long)s_swap_mask, bit, (unsigned long long)e68);
                } else if (bit != s_prev_bit) {
                    KernelTraceHostOpF("HOST.PM4.swap.edge mask=%llX %d->%d e68=%016llX", (unsigned long long)s_swap_mask, s_prev_bit, bit, (unsigned long long)e68);
                    if (s_pm4_swap_present && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                        KernelTraceHostOp("HOST.PM4.swap.present");
                        Mw05MarkGuestSwappedOnce();
                        Video::RequestPresentFromBackground();
                    }
                }
                // Optional: proactively scan entire ring for PM4 commands if enabled
                {
                    static int s_scanTicker = 0;
                    extern void PM4_DebugScanAll();
                    if (((++s_scanTicker) & 0x0F) == 0) { // ~every 16 ticks
                        PM4_DebugScanAll();
                    }
                }
                if (e68 != s_prev_e68) {
                    KernelTraceHostOpF("HOST.VD.e68.change %016llX->%016llX", (unsigned long long)s_prev_e68, (unsigned long long)e68);
                }
                s_prev_bit = bit;
                s_prev_e68 = e68;
            }

            // Auto VdSwap heuristic (opt-in): when conditions look ready for N frames, seed a swap once
            // MOVED OUTSIDE nested if blocks so it can execute independently
            static const bool s_auto_vdswap_heur = [](){
                if (const char* v = std::getenv("MW05_AUTO_VDSWAP_HEUR")) {
                    bool enabled = !(v[0]=='0' && v[1]=='\0');
                    fprintf(stderr, "[AUTO-VDSWAP-HEUR-INIT] MW05_AUTO_VDSWAP_HEUR=%s enabled=%d\n", v, enabled);
                    fflush(stderr);
                    return enabled;
                }
                fprintf(stderr, "[AUTO-VDSWAP-HEUR-INIT] MW05_AUTO_VDSWAP_HEUR not set, disabled\n");
                fflush(stderr);
                return false;
            }();
            static const bool s_auto_vdswap_once = [](){
                if (const char* v = std::getenv("MW05_AUTO_VDSWAP_HEUR_ONCE"))
                    return !(v[0]=='0' && v[1]=='\0');
                return true;
            }();
            static int s_auto_vdswap_delay = [](){
                if (const char* v = std::getenv("MW05_AUTO_VDSWAP_HEUR_DELAY"))
                    return std::max(1, (int)std::strtoul(v, nullptr, 0));
                return 8; // default: ~8 frames of ready state
            }();
            static const uint64_t s_auto_e58_mask = [](){
                if (const char* v = std::getenv("MW05_AUTO_VDSWAP_HEUR_E58_MASK"))
                    return std::strtoull(v, nullptr, 0);
                // CRITICAL FIX: e58 is always 0, so disable this check by setting mask to 0
                // This allows the heuristic to fire based on e68 alone
                return 0x0ull;  // Was: 0x700ull
            }();
            static const uint64_t s_auto_e68_mask = [](){
                if (const char* v = std::getenv("MW05_AUTO_VDSWAP_HEUR_E68_MASK"))
                    return std::strtoull(v, nullptr, 0);
                return 0x2ull; // require ack bit
            }();
            static int s_auto_ok_frames = 0;
            static bool s_auto_done = false;

            // DEBUG: Log condition values every 60 frames
            static int s_cond_log_counter = 0;
            if (++s_cond_log_counter >= 60) {
                s_cond_log_counter = 0;
                bool sawVdSwap = g_sawRealVdSwap.load(std::memory_order_acquire);
                fprintf(stderr, "[AUTO-VDSWAP-HEUR-COND] heur=%d done=%d sawVdSwap=%d (IGNORING sawVdSwap)\n",
                        s_auto_vdswap_heur, s_auto_done, sawVdSwap);
                fflush(stderr);
            }

            // CRITICAL FIX: Remove !g_sawRealVdSwap check because game calls VdSwap during init then stops
            // The heuristic should run even if game called VdSwap before, to detect when it stops calling
            if (s_auto_vdswap_heur && !s_auto_done) {
                auto rd64 = [](uint32_t ea)->uint64_t {
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0ull;
                    if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                        uint64_t v = *p;
                    #if defined(_MSC_VER)
                        return _byteswap_uint64(v);
                    #else
                        return __builtin_bswap64(v);
                    #endif
                    }
                    return 0ull;
                };
                const uint64_t e58 = rd64(0x00060E58u);
                const uint64_t e68 = rd64(0x00060E68u);
                const bool e58_ok = (e58 & s_auto_e58_mask) == s_auto_e58_mask;
                const bool e68_ok = (e68 & s_auto_e68_mask) == s_auto_e68_mask;

                // DEBUG: Log e58/e68 values every 60 frames (once per second at 60 Hz)
                static int s_debug_log_counter = 0;
                if (++s_debug_log_counter >= 60) {
                    s_debug_log_counter = 0;
                    fprintf(stderr, "[AUTO-VDSWAP-HEUR] e58=0x%016llX e68=0x%016llX e58_ok=%d e68_ok=%d frames=%d/%d\n",
                            (unsigned long long)e58, (unsigned long long)e68, e58_ok, e68_ok, s_auto_ok_frames, s_auto_vdswap_delay);
                    fflush(stderr);
                }

                if (e58_ok && e68_ok) {
                    if (++s_auto_ok_frames >= s_auto_vdswap_delay) {
                        fprintf(stderr, "[AUTO-VDSWAP-HEUR] FIRING! e58=0x%016llX e68=0x%016llX frames=%d\n",
                                (unsigned long long)e58, (unsigned long long)e68, s_auto_ok_frames);
                        fflush(stderr);
                        KernelTraceHostOp("HOST.AutoVdSwapHeur.fire");
                        Mw05MarkGuestSwappedOnce();
                        Video::RequestPresentFromBackground();
                        if (s_auto_vdswap_once) s_auto_done = true;
                    }
                } else {
                    s_auto_ok_frames = 0;
                }
            }

            // Late PM4 enforcement pass (optional): re-OR after reads to win races with title writes
            static const bool s_pm4_fake_swap_tail = [](){
                if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_TAIL"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            if (s_pm4_fake_swap_tail) {
                    static const uint32_t s_pm4_fb_addr_tail = [](){
                        if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_ADDR"))
                            return (uint32_t)std::strtoul(v, nullptr, 0);
                        return 0x00060E68u; // default to e68
                    }();
                    static const uint64_t s_pm4_fb_or_tail = [](){
                        if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP_OR"))
                            return std::strtoull(v, nullptr, 0);
                        return 0x2ull;
                    }();
                    if (s_pm4_fb_addr_tail && s_pm4_fb_or_tail && GuestOffsetInRange(s_pm4_fb_addr_tail, sizeof(uint64_t))) {
                        if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(s_pm4_fb_addr_tail))) {
                            uint64_t v = *p;
                        #if defined(_MSC_VER)
                            v = _byteswap_uint64(v);
                        #else
                            v = __builtin_bswap64(v);
                        #endif
                            const uint64_t nv = v | s_pm4_fb_or_tail;
                            if (nv != v) {
                            #if defined(_MSC_VER)
                                *p = _byteswap_uint64(nv);
                            #else
                                *p = __builtin_bswap64(nv);
                            #endif
                                KernelTraceHostOpF("HOST.PM4.fake_swap.or.tail addr=%08X |= %llX -> %llX", s_pm4_fb_addr_tail, (unsigned long long)s_pm4_fb_or_tail, (unsigned long long)nv);
                            }
                        }

                            // Optional: second PM4-style tail OR target (independent addr/mask)
                            static const uint32_t s_pm4_fb2_addr_tail = [](){
                                if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP2_ADDR"))
                                    return (uint32_t)std::strtoul(v, nullptr, 0);
                                return 0u; // disabled by default
                            }();
                            static const uint64_t s_pm4_fb2_or_tail = [](){
                                if (const char* v = std::getenv("MW05_PM4_FAKE_SWAP2_OR"))
                                    return std::strtoull(v, nullptr, 0);
                                return 0ull; // disabled by default
                            }();
                            if (s_pm4_fb2_addr_tail && s_pm4_fb2_or_tail && GuestOffsetInRange(s_pm4_fb2_addr_tail, sizeof(uint64_t))) {
                                if (auto* p2 = reinterpret_cast<uint64_t*>(g_memory.Translate(s_pm4_fb2_addr_tail))) {
                                    uint64_t v2 = *p2;
                                #if defined(_MSC_VER)
                                    v2 = _byteswap_uint64(v2);
                                #else
                                    v2 = __builtin_bswap64(v2);
                                #endif
                                    const uint64_t nv2 = v2 | s_pm4_fb2_or_tail;
                                    if (nv2 != v2) {
                                    #if defined(_MSC_VER)
                                        *p2 = _byteswap_uint64(nv2);
                                    #else
                                        *p2 = __builtin_bswap64(nv2);
                                    #endif
                                        KernelTraceHostOpF("HOST.PM4.fake_swap2.or.tail addr=%08X |= %llX -> %llX", s_pm4_fb2_addr_tail, (unsigned long long)s_pm4_fb2_or_tail, (unsigned long long)nv2);
                                    }
                                }
                            }

                    }
                }


                    // Optional: e68 flip/ack handshake; supports pulse-ack mode
                    static const bool s_e68_handshake = [](){
                        if (const char* v = std::getenv("MW05_VD_E68_HANDSHAKE"))
                            return !(v[0]=='0' && v[1]=='\0');
                        return false;
                    }();
                    static const bool s_e68_ack_pulse = [](){
                        if (const char* v = std::getenv("MW05_VD_E68_ACK_PULSE"))
                            return !(v[0]=='0' && v[1]=='\0');
                        return false;
                    }();
                    if (s_e68_handshake) {
                        const uint32_t ea = 0x00060E68u;
                        if (GuestOffsetInRange(ea, sizeof(uint64_t))) {
                            if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                                uint64_t v = *p;
                            #if defined(_MSC_VER)
                                v = _byteswap_uint64(v);
                            #else
                                v = __builtin_bswap64(v);
                            #endif
                                static int prev_flip = -1; // unknown
                                static bool pulse_armed = false; // for pulse mode
                                const int cur_flip = int(v & 1ull);
                                uint64_t nv = v;
                                bool did_set = false, did_clear = false;
                                if (prev_flip < 0) {
                                    // First observation sets baseline; don't touch ack yet
                                    prev_flip = cur_flip;
                                } else if (cur_flip != prev_flip) {
                                    // Edge detected
                                    if (cur_flip) {
                                        // Rising edge: set ack
                                        nv |= 0x2ull;
                                        did_set = true;
                                        if (s_e68_ack_pulse) pulse_armed = true;
                                    } else {
                                        // Falling edge: clear ack
                                        nv &= ~0x2ull;
                                        did_clear = true;
                                        pulse_armed = false;
                                    }
                                    prev_flip = cur_flip;
                                } else {
                                    // No edge; for pulse mode, clear ack on the next pass while flip is high
                                    if (s_e68_ack_pulse && pulse_armed && cur_flip) {
                                        nv &= ~0x2ull;
                                        did_clear = true;
                                        pulse_armed = false;
                                    }
                                }
                                if (nv != v) {
                                #if defined(_MSC_VER)
                                    *p = _byteswap_uint64(nv);
                                #else
                                    *p = __builtin_bswap64(nv);
                                #endif
                                    KernelTraceHostOpF("HOST.VD.e68.handshake %s ack -> %016llX", (did_set?"set":"clear"), (unsigned long long)nv);
                                }
                            }
                        }
                    }


                    // Optional: force e48 low 16 bits; preserve e48 high 48 bits
                    static const bool s_e48_force_low16_enabled = [](){
                        return std::getenv("MW05_VD_E48_LOW16_FORCE") != nullptr;
                    }();
                    static const uint64_t s_e48_force_low16_value = [](){
                        if (const char* v = std::getenv("MW05_VD_E48_LOW16_FORCE"))
                            return std::strtoull(v, nullptr, 0) & 0xFFFFull;
                        return 0ull;
                    }();
                    if (s_e48_force_low16_enabled) {
                        const uint32_t ea_e48 = 0x00060E48u;
                        if (GuestOffsetInRange(ea_e48, sizeof(uint64_t))) {
                            if (auto* p48 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e48))) {
                                uint64_t v48 = *p48;
                            #if defined(_MSC_VER)
                                v48 = _byteswap_uint64(v48);
                            #else
                                v48 = __builtin_bswap64(v48);
                            #endif
                                const uint64_t forced = (v48 & 0xFFFFFFFFFFFF0000ull) | (s_e48_force_low16_value & 0xFFFFull);
                                if (forced != v48) {
                                #if defined(_MSC_VER)
                                    *p48 = _byteswap_uint64(forced);
                                #else
                                    *p48 = __builtin_bswap64(forced);
                                #endif
                                    KernelTraceHostOpF("HOST.VD.e48.low16.force %04llX -> %016llX",
                                        (unsigned long long)(s_e48_force_low16_value & 0xFFFFull),
                                        (unsigned long long)forced);
                                }
                            }
                        }
                    }


                    // Optional: mirror e60 high bits into e58 while preserving e58 low 16 (readiness flags)
                    static const bool s_e58_mirror_hi = [](){
                        if (const char* v = std::getenv("MW05_VD_E58_MIRROR_E60_HI"))
                            return !(v[0]=='0' && v[1]=='\0');
                        return false;
                    }();
                    if (s_e58_mirror_hi) {
                        const uint32_t ea_e58 = 0x00060E58u;
                        const uint32_t ea_e60 = 0x00060E60u;

                    // Optional: force e58 low 16 bits; always mirror e60 high bits
                    static const uint64_t s_e58_force_low16 = [](){
                        if (const char* v = std::getenv("MW05_VD_E58_LOW16_FORCE"))
                            return std::strtoull(v, nullptr, 0) & 0xFFFFull;
                        return 0ull;
                    }();
                    if (s_e58_force_low16) {
                        const uint32_t ea_e58 = 0x00060E58u;
                        const uint32_t ea_e60 = 0x00060E60u;
                        if (GuestOffsetInRange(ea_e58, sizeof(uint64_t)) && GuestOffsetInRange(ea_e60, sizeof(uint64_t))) {
                            if (auto* p58 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e58))) {
                                if (auto* p60 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e60))) {
                                    uint64_t v58 = *p58, v60 = *p60;
                                #if defined(_MSC_VER)
                                    v58 = _byteswap_uint64(v58);
                                    v60 = _byteswap_uint64(v60);
                                #else
                                    v58 = __builtin_bswap64(v58);
                                    v60 = __builtin_bswap64(v60);
                                #endif
                                    const uint64_t forced = (v60 & 0xFFFFFFFFFFFF0000ull) | (s_e58_force_low16 & 0xFFFFull);
                                    if (forced != v58) {
                                    #if defined(_MSC_VER)
                                        *p58 = _byteswap_uint64(forced);
                                    #else
                                        *p58 = __builtin_bswap64(forced);
                                    #endif
                                        KernelTraceHostOpF("HOST.VD.e58.low16.force %04llX -> %016llX", (unsigned long long)(s_e58_force_low16 & 0xFFFFull), (unsigned long long)forced);
                                    }
                                }
                            }
                        }
                    }

                        if (GuestOffsetInRange(ea_e58, sizeof(uint64_t)) && GuestOffsetInRange(ea_e60, sizeof(uint64_t))) {
                            if (auto* p58 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e58))) {
                                if (auto* p60 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e60))) {
                                    uint64_t v58 = *p58, v60 = *p60;
                                #if defined(_MSC_VER)
                                    v58 = _byteswap_uint64(v58);
                                    v60 = _byteswap_uint64(v60);
                                #else
                                    v58 = __builtin_bswap64(v58);
                                    v60 = __builtin_bswap64(v60);
                                #endif
                                    const uint64_t new58 = (v60 & 0xFFFFFFFFFFFF0000ull) | (v58 & 0xFFFFull);
                                    if (new58 != v58) {
                                    #if defined(_MSC_VER)
                                        *p58 = _byteswap_uint64(new58);
                                    #else
                                        *p58 = __builtin_bswap64(new58);
                                    #endif
                                        KernelTraceHostOpF("HOST.VD.e58.mirror_e60_hi %016llX -> %016llX", (unsigned long long)v58, (unsigned long long)new58);
                                    }
                                }
                            }
                        }
                    }

                    // Tail enforcement: ensure e58 low16 is forced after any later pokes in this tick
                    static const uint64_t s_e58_force_low16_tail = [](){
                        if (const char* v = std::getenv("MW05_VD_E58_LOW16_FORCE"))
                            return std::strtoull(v, nullptr, 0) & 0xFFFFull;
                        return 0ull;
                    }();
                    if (s_e58_force_low16_tail) {
                        const uint32_t ea_e58 = 0x00060E58u;
                        const uint32_t ea_e60 = 0x00060E60u;
                        if (GuestOffsetInRange(ea_e58, sizeof(uint64_t)) && GuestOffsetInRange(ea_e60, sizeof(uint64_t))) {
                            if (auto* p58 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e58))) {
                                if (auto* p60 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e60))) {
                                    uint64_t v58 = *p58, v60 = *p60;
                                #if defined(_MSC_VER)
                                    v58 = _byteswap_uint64(v58);
                                    v60 = _byteswap_uint64(v60);
                                #else
                                    v58 = __builtin_bswap64(v58);
                                    v60 = __builtin_bswap64(v60);
                                #endif
                                    const uint64_t forced = (v60 & 0xFFFFFFFFFFFF0000ull) | (s_e58_force_low16_tail & 0xFFFFull);
                                    if (forced != v58) {
                                    #if defined(_MSC_VER)
                                        *p58 = _byteswap_uint64(forced);
                                    #else
                                        *p58 = __builtin_bswap64(forced);
                                    #endif
                                        KernelTraceHostOpF("HOST.VD.e58.low16.force.tail %04llX -> %016llX", (unsigned long long)(s_e58_force_low16_tail & 0xFFFFull), (unsigned long long)forced);
                                    }
                                }
                            }
                        }
                    }


                    // Tail enforcement: ensure e48 low16 is forced after any later pokes in this tick
                    static const bool s_e48_force_low16_tail_enabled = [](){
                        return std::getenv("MW05_VD_E48_LOW16_FORCE") != nullptr;
                    }();
                    static const uint64_t s_e48_force_low16_tail_value = [](){
                        if (const char* v = std::getenv("MW05_VD_E48_LOW16_FORCE"))
                            return std::strtoull(v, nullptr, 0) & 0xFFFFull;
                        return 0ull;
                    }();
                    if (s_e48_force_low16_tail_enabled) {
                        const uint32_t ea_e48 = 0x00060E48u;
                        if (GuestOffsetInRange(ea_e48, sizeof(uint64_t))) {
                            if (auto* p48 = reinterpret_cast<uint64_t*>(g_memory.Translate(ea_e48))) {
                                uint64_t v48 = *p48;
                            #if defined(_MSC_VER)
                                v48 = _byteswap_uint64(v48);
                            #else
                                v48 = __builtin_bswap64(v48);
                            #endif
                                const uint64_t forced = (v48 & 0xFFFFFFFFFFFF0000ull) | (s_e48_force_low16_tail_value & 0xFFFFull);
                                if (forced != v48) {
                                #if defined(_MSC_VER)
                                    *p48 = _byteswap_uint64(forced);
                                #else
                                    *p48 = __builtin_bswap64(forced);
                                #endif
                                    KernelTraceHostOpF("HOST.VD.e48.low16.force.tail %04llX -> %016llX",
                                        (unsigned long long)(s_e48_force_low16_tail_value & 0xFFFFull),
                                        (unsigned long long)forced);
                                }
                            }
                        }
                    }




            // One-shot forced swap/present to validate downstream flow (opt-in)
            static bool s_forcedSwapDone = false;
            static const bool s_forceSwapOnce = [](){
                if (const char* v = std::getenv("MW05_FORCE_VDSWAP_ONCE"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            static int s_forceDelayTicks = 120; // ~2 seconds at 16 ms per tick
            if (s_forceSwapOnce && !s_forcedSwapDone && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                if (--s_forceDelayTicks <= 0) {
                    KernelTraceHostOp("HOST.ForceVdSwapOnce.fire");
                    Mw05MarkGuestSwappedOnce();
                    Video::RequestPresentFromBackground();
                    s_forcedSwapDone = true;
                }
            }

            // Keep the SDL window responsive even if the guest is idle.
            if (s_pump_events) {
                // WARNING: SDL event APIs should generally be used on the main thread.
                // Enable this only for diagnostics when no main-loop is pumping events.
                SDL_PumpEvents();
            }
            // Also nudge generic waiters relying on generation variable.
            NudgeEventWaiters();

            // DIAGNOSTIC: Log loop timing every 10 ticks
            auto loop_end = std::chrono::steady_clock::now();
            auto loop_duration = std::chrono::duration_cast<std::chrono::milliseconds>(loop_end - loop_start);

            // Calculate next target time for precise 60 Hz timing
            // Use sleep_until instead of sleep_for to avoid accumulating drift
            static auto next_tick_time = loop_start + period;
            auto sleep_start = std::chrono::steady_clock::now();

            // CRITICAL DEBUG: Log before sleep for first 20 ticks
            if (currentTick < 20) {
                fprintf(stderr, "[VBLANK-SLEEP] tick=%u before sleep g_vblankPumpRun=%d\n", currentTick, g_vblankPumpRun.load(std::memory_order_acquire) ? 1 : 0);
                fflush(stderr);
            }

            // Only sleep if we haven't already exceeded the target time
            if (sleep_start < next_tick_time) {
                std::this_thread::sleep_until(next_tick_time);
            }

            auto sleep_end = std::chrono::steady_clock::now();
            auto sleep_duration = std::chrono::duration_cast<std::chrono::milliseconds>(sleep_end - sleep_start);
            auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(sleep_end - loop_start);

            // Advance next tick time by one period
            next_tick_time += period;

            if (currentTick <= 5 || currentTick >= 85 || currentTick % 10 == 0) {
                KernelTraceHostOpF("HOST.VblankPump.timing tick=%u loop_ms=%lld sleep_ms=%lld total_ms=%lld gap_ms=%lld elapsed_ms=%lld",
                                  currentTick, (long long)loop_duration.count(), (long long)sleep_duration.count(), (long long)total_duration.count(), (long long)inter_iteration_gap.count(), (long long)elapsed_since_start.count());
            }

            // CRITICAL DEBUG: Log after sleep for first 20 ticks
            if (currentTick < 20) {
                fprintf(stderr, "[VBLANK-AFTER-SLEEP] tick=%u after sleep g_vblankPumpRun=%d\n", currentTick, g_vblankPumpRun.load(std::memory_order_acquire) ? 1 : 0);
                fflush(stderr);
            }

            last_iteration_end = sleep_end;
        }
        // CRITICAL DEBUG: Log when exiting while loop
        fprintf(stderr, "[VBLANK-EXIT] Exiting while loop g_vblankPumpRun=%d\n", g_vblankPumpRun.load(std::memory_order_acquire) ? 1 : 0);
        fflush(stderr);
        #if defined(_WIN32)
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD exceptionCode = GetExceptionCode();
            fprintf(stderr, "[VBLANK-PUMP-CRASH] SEH Exception in VBlank pump: code=0x%08lX\n", exceptionCode);
            fflush(stderr);
            KernelTraceHostOpF("HOST.VblankPump.exception code=0x%08lX", exceptionCode);
        }
        #endif
        KernelTraceHostOp("HOST.VblankPump.exit");
    }).detach();
}

void Mw05RegisterVdInterruptEvent(uint32_t eventEA, bool manualReset)
{
    const bool valid = eventEA && GuestOffsetInRange(eventEA, sizeof(XDISPATCHER_HEADER));
    if (valid) {
        const uint32_t prev = g_vdInterruptEventEA.load(std::memory_order_acquire);
        if (prev == eventEA) {

            if (auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(eventEA))) {
                hdr->SignalState = be<int32_t>(1);
            }
            return;
        }
    }
    g_vdInterruptEventEA.store(valid ? eventEA : 0u, std::memory_order_release);
    if (valid) {
        KernelTraceHostOpF("HOST.VdInterruptEvent.register ea=%08X manual=%u", eventEA, manualReset ? 1u : 0u);
		Mw05LogIsrIfRegisteredOnce();
        Mw05DispatchVdInterruptIfPending();
        Mw05AutoVideoInitIfNeeded();
        Mw05StartVblankPumpOnce();
    }
}

static bool Mw05SignalVdInterruptEvent()
{
    const uint32_t eventEA = g_vdInterruptEventEA.load(std::memory_order_acquire);
    if (!eventEA || !GuestOffsetInRange(eventEA, sizeof(XDISPATCHER_HEADER)))
        return false;

    auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(eventEA));
    if (!hdr)
        return false;

    bool signaled = false;
    if (auto* ev = QueryKernelObject<Event>(*hdr)) {
        KernelTraceHostOpF("HOST.VdInterruptEvent.signal ea=%08X", eventEA);
        ev->Set();
        // Keep guest header in sync for pollers
        hdr->SignalState = be<int32_t>(1);
        signaled = true;
    } else {
        KernelTraceHostOpF("HOST.VdInterruptEvent.signal.raw ea=%08X", eventEA);
        hdr->SignalState = be<int32_t>(1);
        NudgeEventWaiters();
        signaled = true;
    }

    if (signaled) {
        uint32_t cleared_blockEA = 0;
        if (uint32_t blockEA = Mw05ConsumeSchedulerBlockEA()) {
            if (GuestOffsetInRange(blockEA + 8, sizeof(uint64_t))) {
                if (auto* block = reinterpret_cast<uint32_t*>(g_memory.Translate(blockEA))) {
                    auto* fence64 = reinterpret_cast<uint64_t*>(block + 2);
                    if (const char* dump = std::getenv("MW05_DUMP_SCHED_BLOCK")) {
                        if (!(dump[0]=='0' && dump[1]=='\0')) {
                            uint32_t w0 = block[0], w1 = block[1], w2 = block[2], w3 = block[3], w4 = block[4];
                            KernelTraceHostOpF("HOST.SchedBlock.dump.before ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                                               blockEA, w0, w1, w2, w3, w4);
                        }
                    }
                    uint64_t before = fence64 ? *fence64 : 0;
                    if (fence64) *fence64 = 0;
                    KernelTraceHostOpF("HOST.VdInterruptEvent.ack block=%08X before=%016llX",
                                       blockEA, static_cast<unsigned long long>(before));
                    if (const char* dump = std::getenv("MW05_DUMP_SCHED_BLOCK")) {
                        if (!(dump[0]=='0' && dump[1]=='\0')) {
                            uint32_t w0 = block[0], w1 = block[1], w2 = block[2], w3 = block[3], w4 = block[4];
                            KernelTraceHostOpF("HOST.SchedBlock.dump.after  ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                                               blockEA, w0, w1, w2, w3, w4);
                        }
                    }
                    cleared_blockEA = blockEA;
                } else {
                    KernelTraceHostOpF("HOST.VdInterruptEvent.ack block=%08X (unmapped)", blockEA);
                }
            }
        } else if (const char* ackFromEvent = std::getenv("MW05_ACK_FROM_EVENT_FIELD")) {
            if (!(ackFromEvent[0]=='0' && ackFromEvent[1]=='\0')) {
                // Fallback heuristic: some schedulers stash a fence-block pointer near
                // the event header. Probe a few 64-bit BE slots before the header and
                // try to interpret them as a guest EA to a scheduler block. If found,
                // zero [block+8] (the 64-bit fence) to acknowledge.
                const uint32_t eventEA = g_vdInterruptEventEA.load(std::memory_order_acquire);
                const int32_t kProbeOffsets[] = { -8, -16, -24, -32 };
                for (int32_t off : kProbeOffsets) {
                    if (!GuestOffsetInRange(eventEA + off, sizeof(uint64_t))) continue;
                    const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(eventEA + off));
                    if (!p) continue;
                    uint64_t be_ptr64 = *reinterpret_cast<const uint64_t*>(p);
                    // guest writes are big-endian; convert and truncate to 32-bit EA
                    #if defined(_MSC_VER)
                    be_ptr64 = _byteswap_uint64(be_ptr64);
                    #else
                    be_ptr64 = __builtin_bswap64(be_ptr64);
                    #endif
                    const uint32_t blkEA = static_cast<uint32_t>(be_ptr64);
                    // Ignore obvious host/kernel pointers (e.g., 0x82xxxxxx) and zero
                    // candidates; require that [blkEA+8] be within guest memory.
                    if (!blkEA || !GuestOffsetInRange(blkEA + 8, sizeof(uint64_t))) continue;
                    if (auto* blk = reinterpret_cast<uint32_t*>(g_memory.Translate(blkEA))) {
                        auto* fence64 = reinterpret_cast<uint64_t*>(blk + 2);

                        if (const char* dump = std::getenv("MW05_DUMP_SCHED_BLOCK")) {
                            if (!(dump[0]=='0' && dump[1]=='\0')) {
                                uint32_t w0 = blk[0], w1 = blk[1], w2 = blk[2], w3 = blk[3], w4 = blk[4];
                                KernelTraceHostOpF("HOST.SchedBlock.dump.before ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                                                   blkEA, w0, w1, w2, w3, w4);
                            }
                        }
                        uint64_t before = fence64 ? *fence64 : 0;
                        if (fence64) *fence64 = 0;
                        KernelTraceHostOpF("HOST.VdInterruptEvent.ack.fallback block=%08X before=%016llX (off=%d)",
                                           blkEA, static_cast<unsigned long long>(before), (int)off);
                        if (const char* dump = std::getenv("MW05_DUMP_SCHED_BLOCK")) {
                            if (!(dump[0]=='0' && dump[1]=='\0')) {
                                uint32_t w0 = blk[0], w1 = blk[1], w2 = blk[2], w3 = blk[3], w4 = blk[4];
                                KernelTraceHostOpF("HOST.SchedBlock.dump.after  ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                                                   blkEA, w0, w1, w2, w3, w4);
                            }
                        }
                        cleared_blockEA = blkEA;
                        break;
                    }
                }
            }
        }
        // Optional extra nudges when we have a valid block EA that was acked
        if (cleared_blockEA) {
            // 1) Optionally clear the pointer slot stored just before the event header.
            //    Some schedulers treat this as the "consumed" signal.
            if (const char* z = std::getenv("MW05_ZERO_EVENT_PTR_AFTER_ACK")) {
                if (!(z[0]=='0' && z[1]=='\0')) {
                    const uint32_t eventEA = g_vdInterruptEventEA.load(std::memory_order_acquire);
                    if (GuestOffsetInRange(eventEA - 8, sizeof(uint64_t))) {
                        if (auto* p2 = static_cast<uint8_t*>(g_memory.Translate(eventEA - 8))) {
                            *reinterpret_cast<uint64_t*>(p2) = 0ull;
                            KernelTraceHostOpF("HOST.VdInterruptEvent.ptr.zero ea=%08X", eventEA - 8);
                        }
                    }
                }
            }
            // 1b) Optionally clear the event status (at eventEA) after ack.
            //     Some schedulers expect ISR to zero the status to signal consumption.
            if (const char* zs = std::getenv("MW05_ZERO_EVENT_STATUS_AFTER_ACK")) {
                if (!(zs[0]=='0' && zs[1]=='\0')) {
                    const uint32_t eventEA = g_vdInterruptEventEA.load(std::memory_order_acquire);
                    if (GuestOffsetInRange(eventEA, sizeof(uint64_t))) {
                        if (auto* ps = static_cast<uint8_t*>(g_memory.Translate(eventEA))) {
                            *reinterpret_cast<uint64_t*>(ps) = 0ull;
                            KernelTraceHostOpF("HOST.VdInterruptEvent.status.zero ea=%08X", eventEA);
                        }
                    }
                }
            }

            // 2) Optionally clear the whole scheduler block header (first 20 bytes).
            //    Some title loops expect all words to be zeroed after an ack.
            if (const char* clr = std::getenv("MW05_CLEAR_SCHED_BLOCK")) {
                if (!(clr[0]=='0' && clr[1]=='\0')) {
                    if (GuestOffsetInRange(cleared_blockEA, 20)) {
                        if (auto* p = static_cast<uint8_t*>(g_memory.Translate(cleared_blockEA))) {
                            std::memset(p, 0, 20);
                            KernelTraceHostOpF("HOST.VdInterruptEvent.clear block=%08X size=20", cleared_blockEA);
                        }
                    }
                }
            }
        }
        {
            bool cb_enabled = true;
            if (const char* f = std::getenv("MW05_VBLANK_CB_FORCE"))
                cb_enabled = !(f[0]=='0' && f[1]=='\0');
            else if (const char* v = std::getenv("MW05_VBLANK_CB"))
                cb_enabled = !(v[0]=='0' && v[1]=='\0');
            else if (std::getenv("MW05_FORCE_PRESENT") || std::getenv("MW05_FORCE_PRESENT_BG") || std::getenv("MW05_KICK_VIDEO")) {
                // Suppress guest ISR in forced-present bring-up, but keep host default ISR available
                if (const char* d = std::getenv("MW05_DEFAULT_VD_ISR"))
                    cb_enabled = !(d[0]=='0' && d[1]=='\0');
                else
                    cb_enabled = false;
            }

            if (cb_enabled) {
                if (const uint32_t cb = VdGetGraphicsInterruptCallback()) {
                    if (cb == kHostDefaultVdIsrMagic) {
                        KernelTraceHostOp("HOST.VdInterruptEvent.dispatch.host_isr");
                        Mw05RunHostDefaultVdIsrNudge("dispatch");
                    } else {
                        uint32_t ctx = VdGetGraphicsInterruptContext();
                        // Optionally override context with discovered scheduler pointer
                        static const bool s_force_ctx_sched_dispatch = [](){
                            if (const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED")) return !(v[0]=='0' && v[1]=='\0');
                            return false;
                        }();
                        if (s_force_ctx_sched_dispatch) {
                            uint32_t sched = Mw05Trace_LastSchedR3();
                            if (GuestOffsetInRange(sched, 4)) ctx = sched;
                        }
                        KernelTraceHostOpF("HOST.VdInterruptEvent.dispatch cb=%08X ctx=%08X", cb, ctx);
                        EnsureGuestContextForThisThread("VdInterruptEvent");
                        // CRITICAL FIX: Set recursion guard to prevent infinite loop when callback calls VdSwap
                        s_inVdInterruptDispatch = true;
                        GuestToHostFunction<void>(cb, 0u, ctx);
                        s_inVdInterruptDispatch = false;
                    }
                } else if (const char* f = std::getenv("MW05_FORCE_VD_ISR")) {
                    if (!(f[0]=='0' && f[1]=='\0')) {
                        KernelTraceHostOp("HOST.VdInterruptEvent.dispatch.forced.no_cb");
                    }
                } else if (const char* d = std::getenv("MW05_DEFAULT_VD_ISR")) {
                    if (!(d[0]=='0' && d[1]=='\0')) {

                        // Host-side default ISR: nudge GPU/VD paths so waiters make progress
                        KernelTraceHostOp("HOST.VdInterruptEvent.dispatch.default_isr");
                        // Bump ring write-back pointer modestly
                        uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);
                        if (wb) {
                            if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb))) {
                                uint32_t cur = *rptr;
                                uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
                                uint32_t mask = len_log2 ? ((1u << len_log2) - 1u) : 0xFFFFu;
                                uint32_t next = (cur + 0x40u) & mask;
                                *rptr = next ? next : 0x20u;
                            }
                        }
                        // Ask main thread to present to keep swap chain moving
                        Video::RequestPresentFromBackground();
                    }
                }
            }
        }
    }

    return signaled;
}

static void Mw05DispatchVdInterruptIfPending()
{
    bool expected = true;
    if (!g_vdInterruptPending.compare_exchange_strong(expected, false, std::memory_order_acq_rel))
        return;

    if (!Mw05SignalVdInterruptEvent()) {
        g_vdInterruptPending.store(true, std::memory_order_release);
    }
}

extern "C"
{
    void Mw05MarkGuestSwappedOnce()
    {
        bool expected = false;
        if (g_guestHasSwapped.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            KernelTraceHostOp("HOST.FakeVdSwap.marked");
            // Keep event flow moving in case callers poll on display sync
            Mw05DispatchVdInterruptIfPending();
        }
    }

    void Mw05MarkRealVdSwap()
    {
        // Set the flag and log once on first transition to true
        if (!g_sawRealVdSwap.exchange(true, std::memory_order_acq_rel)) {
            KernelTraceHostOp("HOST.MarkRealVdSwap");
        }
    }

    // Expose ring/system buffer regions for tracing purposes (read-only accessors)
    uint32_t Mw05GetRingBaseEA() { return g_RbBase.load(std::memory_order_relaxed); }
    uint32_t Mw05GetRingSizeBytes() {
        const uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
        return (len_log2 < 32u) ? (1u << len_log2) : 0u;
    }
    uint32_t Mw05GetSysBufBaseEA() { return g_VdSystemCommandBuffer.load(std::memory_order_relaxed); }
    uint32_t Mw05GetSysBufSizeBytes() { return 64u * 1024u; }
}

// REMOVED VmArena - using simple heap allocation like UnleashedRecomp
// NtAllocateVirtualMemory and NtFreeVirtualMemory are now stubs

struct Semaphore final : KernelObject, HostObject<XKSEMAPHORE>
{
    std::atomic<uint32_t> count;
    uint32_t maximumCount;
    uint32_t guestHeaderEA{0};


    Semaphore(XKSEMAPHORE* semaphore)
        : count(semaphore->Header.SignalState), maximumCount(semaphore->Limit)
    {
        guestHeaderEA = g_memory.MapVirtual(&semaphore->Header);
    }


    Semaphore(uint32_t count, uint32_t maximumCount)
        : count(count), maximumCount(maximumCount)
    {
        guestHeaderEA = 0;
    }


    uint32_t Wait(uint32_t timeout) override
    {
        if (timeout == 0)
        {
            uint32_t currentCount = count.load();
            if (currentCount != 0)
            {
                if (count.compare_exchange_weak(currentCount, currentCount - 1))
                    return STATUS_SUCCESS;
            }

            return STATUS_TIMEOUT;
        }
        else if (timeout == INFINITE)
        {
            uint32_t currentCount;
            while (true)
            {
                currentCount = count.load();
                if (currentCount != 0)
                {
                    if (count.compare_exchange_weak(currentCount, currentCount - 1))
                        return STATUS_SUCCESS;
                }
                else
                {
                    count.wait(0);
                }
            }

            return STATUS_SUCCESS;
        }
        else
        {
            assert(false && "Unhandled timeout value.");
            return STATUS_TIMEOUT;
        }
    }

    void Release(uint32_t releaseCount, uint32_t* previousCount)
    {
        if (previousCount != nullptr)
            *previousCount = count;

        assert(count + releaseCount <= maximumCount);

        count += releaseCount;
        count.notify_all();
    }
};

// Timer kernel object
struct Timer final : KernelObject
{
    std::atomic<bool> signaled{false};
    bool manualReset{false};

    Timer(bool manual) : manualReset(manual) {}

    uint32_t Wait(uint32_t timeout) override
    {
        if (timeout == 0)
        {
            return signaled.load() ? STATUS_SUCCESS : STATUS_TIMEOUT;
        }
        else if (timeout == INFINITE)
        {
            while (!signaled.load())
            {
                signaled.wait(false);
            }
            if (!manualReset)
                signaled = false;
            return STATUS_SUCCESS;
        }
        else
        {
            // Timed wait not fully implemented
            return STATUS_TIMEOUT;
        }
    }

    void Set()
    {
        signaled = true;
        signaled.notify_all();
    }

    void Reset()
    {
        signaled = false;
    }
};

// Mutant (Mutex) kernel object
struct Mutant final : KernelObject
{
    std::atomic<uint32_t> ownerThreadId{0};
    std::atomic<int32_t> recursionCount{0};

    Mutant() = default;

    uint32_t Wait(uint32_t timeout) override
    {
        uint32_t currentThreadId = GuestThread::GetCurrentThreadId();

        // Check if already owned by current thread
        if (ownerThreadId.load() == currentThreadId)
        {
            recursionCount++;
            return STATUS_SUCCESS;
        }

        // Try to acquire
        if (timeout == 0)
        {
            uint32_t expected = 0;
            if (ownerThreadId.compare_exchange_strong(expected, currentThreadId))
            {
                recursionCount = 1;
                return STATUS_SUCCESS;
            }
            return STATUS_TIMEOUT;
        }
        else if (timeout == INFINITE)
        {
            while (true)
            {
                uint32_t expected = 0;
                if (ownerThreadId.compare_exchange_weak(expected, currentThreadId))
                {
                    recursionCount = 1;
                    return STATUS_SUCCESS;
                }
                ownerThreadId.wait(expected);
            }
        }
        else
        {
            // Timed wait not fully implemented
            return STATUS_TIMEOUT;
        }
    }

    void Release()
    {
        uint32_t currentThreadId = GuestThread::GetCurrentThreadId();
        if (ownerThreadId.load() != currentThreadId)
        {
            // Error: trying to release a mutex not owned by current thread
            return;
        }

        recursionCount--;
        if (recursionCount == 0)
        {
            ownerThreadId = 0;
            ownerThreadId.notify_all();
        }
    }
};

// I/O Completion Port kernel object
struct IoCompletion final : KernelObject
{
    struct CompletionPacket
    {
        uint32_t key;
        uint32_t value;
        uint32_t status;
        uint32_t information;
    };

    std::mutex mutex;
    std::condition_variable cv;
    std::queue<CompletionPacket> packets;

    IoCompletion() = default;

    uint32_t Wait(uint32_t timeout) override
    {
        // Not used for I/O completion ports
        return STATUS_SUCCESS;
    }

    void Post(uint32_t key, uint32_t value, uint32_t status, uint32_t information)
    {
        std::lock_guard<std::mutex> lock(mutex);
        packets.push({key, value, status, information});
        cv.notify_one();
    }

    bool Remove(CompletionPacket& packet, uint32_t timeout)
    {
        std::unique_lock<std::mutex> lock(mutex);

        if (timeout == 0)
        {
            if (packets.empty())
                return false;
            packet = packets.front();
            packets.pop();
            return true;
        }
        else if (timeout == INFINITE)
        {
            cv.wait(lock, [this] { return !packets.empty(); });
            packet = packets.front();
            packets.pop();
            return true;
        }
        else
        {
            // Timed wait
            auto duration = std::chrono::milliseconds(timeout);
            if (cv.wait_for(lock, duration, [this] { return !packets.empty(); }))
            {
                packet = packets.front();
                packets.pop();
                return true;
            }
            return false;
        }
    }
};

inline void CloseKernelObject(XDISPATCHER_HEADER& header)
{
    if (header.WaitListHead.Flink != OBJECT_SIGNATURE)
    {
        return;
    }

    DestroyKernelObject(header.WaitListHead.Blink);
}

// xboxkrnl variable export: XexExecutableModuleHandle (ordinal 0x193)
// Titles may read this directly to get a module handle for the main XEX.
// Provide a stable pseudo-handle that also matches XexGetModuleHandle(null).
be<uint32_t> XexExecutableModuleHandle = be<uint32_t>(0x80000001u);


// Exported variable: ExLoadedImageName (guest pointer to the loaded image name)
be<uint32_t> ExLoadedImageName = be<uint32_t>(0);

// Implemented after Event/Semaphore definitions so we can safely inspect types.
static void Mw05HostIsrSignalLastWaitHandleIfAny()
{
    const uint32_t h = g_lastWaitKernelHandle.load(std::memory_order_acquire);
    if (!h || !IsKernelObject(h)) return;

    if (const char* tlw_h = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
        if (!(tlw_h[0]=='0' && tlw_h[1]=='\0')) {
            KernelTraceHostOpF("HOST.Wait.last.handle current=%08X", h);
        }
    }

    KernelObject* ko = GetKernelObject(h);
    if (!ko || !IsKernelObjectAlive(ko)) return;

    if (auto* ev = dynamic_cast<Event*>(ko)) {
        ev->Set();
        KernelTraceHostOpF("HOST.HostDefaultVdIsr.signal.last_wait.handle event handle=%08X", h);
        return;
    }
    if (auto* sem = dynamic_cast<Semaphore*>(ko)) {
        sem->Release(1, nullptr);
        KernelTraceHostOpF("HOST.HostDefaultVdIsr.signal.last_wait.handle semaphore handle=%08X", h);
        return;
    }

    KernelTraceHostOpF("HOST.HostDefaultVdIsr.last_wait.handle.unsupported handle=%08X", h);
}

// xboxkrnl variable exports expected as pointers to data structures/strings
// Provide minimal definitions so titles can read them without crashing.
be<uint32_t> ExLoadedCommandLine = be<uint32_t>(0);     // guest ptr to UTF-8/ANSI string
be<uint32_t> KeDebugMonitorData  = be<uint32_t>(0);     // guest ptr to struct (unused)
be<uint32_t> ExThreadObjectType  = be<uint32_t>(0);     // guest ptr to object type (unused)
be<uint32_t> ExEventObjectType   = be<uint32_t>(0);     // guest ptr to object type (unused)
be<uint32_t> ExSemaphoreObjectType = be<uint32_t>(0);   // guest ptr to object type (unused)
be<uint32_t> ExTimerObjectType   = be<uint32_t>(0);     // guest ptr to object type (unused)
be<uint32_t> KeCertMonitorData   = be<uint32_t>(0);     // guest ptr to cert monitor (unused)
be<uint32_t> KeTimeStampBundle   = be<uint32_t>(0);     // guest ptr to timestamp bundle (unused)
be<uint32_t> XboxHardwareInfo    = be<uint32_t>(0);     // guest ptr to hw info struct (unused)
be<uint32_t> VdGlobalDevice      = be<uint32_t>(0);     // guest ptr to graphics device (unused)
be<uint32_t> VdGlobalXamDevice   = be<uint32_t>(0);     // guest ptr to XAM graphics device (unused)
be<uint32_t> VdGpuClockInMHz     = be<uint32_t>(500);   // GPU clock speed in MHz
be<uint32_t> VdHSIOCalibrationLock = be<uint32_t>(0);   // guest ptr to HSIO calibration lock (unused)

// Resolve imported variable storage and return its guest address. Allocates on first request.
extern "C" uint32_t GetImportVariableGuestAddress(const char* name)
{
    static std::mutex s_varMutex;
    static std::unordered_map<std::string, uint32_t> s_varMap;
    std::lock_guard guard{s_varMutex};
    if (!name || !name[0]) return 0;

    auto it = s_varMap.find(name);
    if (it != s_varMap.end())
        return it->second;

    // Allocate 4 bytes in guest space for the variable's storage
    void* host = g_userHeap.Alloc(sizeof(uint32_t));
    if (!host)
        return 0;
    uint32_t ea = g_memory.MapVirtual(host);

    auto write_u32 = [&](uint32_t v){ *reinterpret_cast<be<uint32_t>*>(host) = be<uint32_t>(v); };

    // Provide sensible defaults for known variables, otherwise zero-initialize
    uint32_t initial = 0;

    if (std::strcmp(name, "__imp__VdGpuClockInMHz") == 0) {
        initial = 500; // 500 MHz typical
    } else if (std::strcmp(name, "__imp__VdHSIOCalibrationLock") == 0) {
        initial = 0;
    } else if (std::strcmp(name, "__imp__VdGlobalDevice") == 0) {
        initial = VdGlobalDevice.get();
    } else if (std::strcmp(name, "__imp__VdGlobalXamDevice") == 0) {
        initial = VdGlobalXamDevice.get();
    } else if (std::strcmp(name, "__imp__ExLoadedImageName") == 0) {
        initial = ExLoadedImageName.get();
    } else if (std::strcmp(name, "__imp__ExLoadedCommandLine") == 0) {
        initial = ExLoadedCommandLine.get();
    } else if (std::strcmp(name, "__imp__XboxHardwareInfo") == 0) {
        // Leave as 0 for now; can be set up to point to a struct later if needed
        initial = 0;
    } else {
        // Default zero; log once for visibility
        KernelTraceHostOpF("HOST.ImportVar.default name=%s", name);
    }

    write_u32(initial);
    s_varMap.emplace(name, ea);
    KernelTraceHostOpF("HOST.ImportVar.alloc name=%s ea=%08X val=%08X", name, ea, initial);
    return ea;
}


// One-time initializer to allocate and publish basic kernel variables.
void Mw05InitKernelVarExportsOnce()
{
    static std::atomic<int> s_inited{0};
    int expected = 0;
    if (!s_inited.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
        return;

    // Allocate guest strings for image name and command line.
    const char* image = "default_patched.xex";
    const char* cmdln = "";

    auto publish_string = [&](const char* s) -> uint32_t {
        size_t n = std::strlen(s);
        void* host = g_userHeap.Alloc(n + 1);
        if (!host) return 0;
        std::memcpy(host, s, n + 1);
        return g_memory.MapVirtual(host);
    };

    uint32_t img_ea = publish_string(image);
    uint32_t cmd_ea = publish_string(cmdln);

    // ExLoadedImageName is an export too; ensure it exists and set if present.
    // Some games only read ExLoadedCommandLine. We set both consistently.
    extern be<uint32_t> ExLoadedImageName; // declared below (or by export table)

    if (img_ea) ExLoadedImageName = img_ea;
    if (cmd_ea) ExLoadedCommandLine = cmd_ea;

    KernelTraceHostOpF("HOST.KernelVar.init ExLoadedImageName=%08X ExLoadedCommandLine=%08X",
                       img_ea, cmd_ea);
}

uint32_t XGetGameRegion()
{
    if (Config::Language == ELanguage::Japanese)
        return 0x0101;

    return 0x03FF;
}

uint32_t XMsgStartIORequest(uint32_t App, uint32_t Message, XXOVERLAPPED* lpOverlapped, void* Buffer, uint32_t szBuffer)
{
    KernelTraceHostOpF("HOST.XMsgStartIORequest app=%u msg=%08X buf=%08X size=%u ovl=%08X",
                       App, Message, (uint32_t)g_memory.MapVirtual(Buffer), szBuffer,
                       (uint32_t)g_memory.MapVirtual(lpOverlapped));

    // For known messages, dump a small hex preview of the payload to help discovery.
    if (Buffer && szBuffer) {
        const uint32_t bufEA = g_memory.MapVirtual(Buffer);
        const uint8_t* b = reinterpret_cast<const uint8_t*>(g_memory.Translate(bufEA));
        if (b) {
            char hex[64 * 3 + 1] = {};
            const uint32_t to_dump = std::min<uint32_t>(szBuffer, 64);
            for (uint32_t i = 0; i < to_dump; ++i) {
                std::snprintf(hex + i * 3, 4, "%02X ", b[i]);
            }
            KernelTraceHostOpF("HOST.XMsgStartIORequest.dump msg=%08X first=%u: %s", Message, to_dump, hex);
        }
    }

    // Opportunistic decode for msg 0x7001B observed in MW05: buffer layout appears as:
    //   u32 opcode(=2), u32 outEA0, u32 outEA1. Titles likely expect us to populate these outputs.
    if (Message == 0x7001B && Buffer && szBuffer >= 12) {
        const uint32_t bufEA = g_memory.MapVirtual(Buffer);
        const uint8_t* b = reinterpret_cast<const uint8_t*>(g_memory.Translate(bufEA));
        if (b) {
            auto ld32 = [](const uint8_t* p) -> uint32_t {
                return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
            };
            const uint32_t opcode = ld32(b + 0);
            const uint32_t out0EA = ld32(b + 4);
            const uint32_t out1EA = ld32(b + 8);
            if (opcode == 2 && GuestOffsetInRange(out0EA, 4) && GuestOffsetInRange(out1EA, 4)) {
                *reinterpret_cast<be<uint32_t>*>(g_memory.Translate(out0EA)) = 0u;
                *reinterpret_cast<be<uint32_t>*>(g_memory.Translate(out1EA)) = 0u;
                KernelTraceHostOpF("HOST.XMsgStartIORequest(7001B).write out0=%08X out1=%08X => 0,0", out0EA, out1EA);
            }
        }
    }

    // Minimal immediate-complete behavior: mark overlapped as success and signal its event.
    if (lpOverlapped && GuestOffsetInRange((uint32_t)g_memory.MapVirtual(lpOverlapped), sizeof(XXOVERLAPPED))) {
        lpOverlapped->Error = 0;    // STATUS_SUCCESS
        lpOverlapped->Length = 0;
        lpOverlapped->dwExtendedError = 0;
        const uint32_t evEA = lpOverlapped->hEvent;
        if (evEA && GuestOffsetInRange(evEA, sizeof(XDISPATCHER_HEADER))) {
            if (auto* ev = reinterpret_cast<XKEVENT*>(g_memory.Translate(evEA))) {
                KeSetEvent(ev, 0, false);
                KernelTraceHostOpF("HOST.XMsgStartIORequest.signal hEvent=%08X", evEA);
            }
        }
    }
    return STATUS_SUCCESS;
}

uint32_t XamUserGetSigninState(uint32_t userIndex)
{
    uint32_t state = userIndex == 0 ? 1u : 0u;
    KernelTraceHostOpF("HOST.XamUserGetSigninState userIndex=%u -> state=%u", userIndex, state);
    return state;
}

uint32_t XamGetSystemVersion()
{
    // Pack as (Major << 24) | (Minor << 16) | Build; QFE ignored.
    // Match/meet the import library requirement (>= 2.0.1861; prefer 2.0.2135).
    constexpr uint32_t kMajor = 2;
    constexpr uint32_t kMinor = 0;
    constexpr uint32_t kBuild = 2135; // 0x0857
    const uint32_t version = (kMajor << 24) | (kMinor << 16) | kBuild;
    KernelTraceHostOpF("HOST.XamGetSystemVersion -> %08X (major=%u minor=%u build=%u)", version, kMajor, kMinor, kBuild);
    return version;
}

void XamContentDelete()
{
    LOG_UTILITY("!!! STUB !!!");
}

// -------- XamLoader launch data helpers --------
// Minimal implementation: no launch data present.
uint32_t XamLoaderGetLaunchDataSize(be<uint32_t>* pcbData)
{
    if (pcbData) *pcbData = 0u;
    KernelTraceHostOp("HOST.XamLoaderGetLaunchDataSize size=0");
    return 0; // STATUS_SUCCESS
}

uint32_t XamLoaderGetLaunchData(void* pBuffer, uint32_t cbBuffer, be<uint32_t>* pcbData)
{
    if (pcbData) *pcbData = 0u;
    // No data to copy; succeed with zero bytes to avoid gating title init paths.
    KernelTraceHostOpF("HOST.XamLoaderGetLaunchData buf=%08X len=%u -> 0 bytes",
                       (uint32_t)g_memory.MapVirtual(pBuffer), cbBuffer);
    return 0; // STATUS_SUCCESS
}

uint32_t XamLoaderSetLaunchData(const void* pBuffer, uint32_t cbBuffer)
{
    // Accept and ignore; titles may use this to pass control info between phases.
    KernelTraceHostOpF("HOST.XamLoaderSetLaunchData buf=%08X len=%u",
                       (uint32_t)g_memory.MapVirtual(pBuffer), cbBuffer);
    return 0; // STATUS_SUCCESS
}

uint32_t XamContentGetCreator(uint32_t userIndex, const XCONTENT_DATA* contentData, be<uint32_t>* isCreator, be<uint64_t>* xuid, XXOVERLAPPED* overlapped)
{
    if (isCreator)
        *isCreator = true;

    if (xuid)
        *xuid = 0xE03000004259BB1B;

    return 0;
}

uint32_t XamContentGetDeviceState(uint32_t deviceId, uint32_t overlappedPtr)
{
    KernelTraceHostOpF("HOST.XamContentGetDeviceState deviceId=%u overlappedPtr=%08X", deviceId, overlappedPtr);

    // Device IDs (from Xenia):
    // 1 = HDD (Hard Disk Drive)
    // 2 = ODD (Optical Disc Drive)

    // Return success for HDD and ODD, error for others
    uint32_t result;
    if (deviceId == 1 || deviceId == 2) {
        // Device is connected and ready
        if (overlappedPtr != 0) {
            // Async mode - complete immediately with success
            // TODO: Implement overlapped completion if needed
            result = 0x3E6; // X_ERROR_IO_PENDING
        } else {
            // Sync mode - return success
            result = 0; // X_ERROR_SUCCESS
        }
    } else {
        // Unknown device
        if (overlappedPtr != 0) {
            // Async mode - complete immediately with error
            result = 0x3E6; // X_ERROR_IO_PENDING
        } else {
            // Sync mode - return error
            result = 0x48F; // X_ERROR_DEVICE_NOT_CONNECTED
        }
    }

    KernelTraceHostOpF("HOST.XamContentGetDeviceState -> result=%08X", result);
    return result;
}

uint32_t XamUserGetSigninInfo(uint32_t userIndex, uint32_t flags, XUSER_SIGNIN_INFO* info)
{
    KernelTraceHostOpF("HOST.XamUserGetSigninInfo userIndex=%u flags=%08X", userIndex, flags);

    if (userIndex == 0)
    {
        memset(info, 0, sizeof(*info));
        info->xuid = 0xE03000004259BB1B;
        info->SigninState = 1;
        strcpy(info->Name, "NAME");
        KernelTraceHostOpF("HOST.XamUserGetSigninInfo -> SUCCESS xuid=%016llX name=%s", info->xuid, info->Name);
        return 0;
    }

    KernelTraceHostOpF("HOST.XamUserGetSigninInfo -> ERROR_NO_SUCH_USER");
    return 0x00000525; // ERROR_NO_SUCH_USER
}

void XamShowSigninUI()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t XamShowDeviceSelectorUI
(
    uint32_t userIndex,
    uint32_t contentType,
    uint32_t contentFlags,
    uint64_t totalRequested,
    be<uint32_t>* deviceId,
    XXOVERLAPPED* overlapped
)
{
    XamNotifyEnqueueEvent(9, true);
    *deviceId = 1;
    XamNotifyEnqueueEvent(9, false);
    return 0;
}

void XamShowDirtyDiscErrorUI()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XamEnableInactivityProcessing()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XamResetInactivity()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XamShowMessageBoxUIEx()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t XGetLanguage()
{
    return (uint32_t)Config::Language.Value;
}

uint32_t XGetAVPack()
{
    return 0;
}

void XamLoaderTerminateTitle()
{
    LOG_UTILITY("!!! STUB !!!");
}

// Return a pointer (in guest EA) to a static XEX_EXECUTION_ID-like struct.
// Prototype (per IDA): NTSTATUS XamGetExecutionId(PXEX_EXECUTION_ID* xid)
// We only populate the common fields titles typically read: MediaId, TitleId,
// SavegameId, DiscNumber, DiscCount, Version, BaseVersion.
struct XamExecutionIdStruct {
    be<uint32_t> MediaId;      // e.g., 0x36775B18
    be<uint32_t> TitleId;      // e.g., 0x454107D9
    be<uint32_t> SavegameId;   // often TitleId
    uint8_t      DiscNumber;   // 0 for single-disc titles
    uint8_t      DiscCount;    // 0 or 1 for single-disc titles
    be<uint16_t> Version;      // optional; 0 if unknown
    be<uint16_t> BaseVersion;  // optional; 0 if unknown
    uint8_t      Platform;     // 2 = Xenon/Xbox 360 (best effort)
    uint8_t      ReservedA;    // pad
    be<uint16_t> ReservedB;    // pad
};

static std::atomic<uint32_t> s_execIdEA{0};

uint32_t XamGetExecutionId(be<uint32_t>* outExecIdEA)
{
    // Allocate and publish once
    uint32_t expect = 0;
    if (s_execIdEA.load(std::memory_order_acquire) == 0) {
        void* host = g_userHeap.Alloc(sizeof(XamExecutionIdStruct));
        if (host) {
            auto* xid = reinterpret_cast<XamExecutionIdStruct*>(host);
            xid->MediaId     = 0x36775B18u;  // from tools/xenia_headers.txt
            xid->TitleId     = 0x454107D9u;  // NFS:MW (EU)
            xid->SavegameId  = 0x454107D9u;
            xid->DiscNumber  = 0;
            xid->DiscCount   = 0;
            xid->Version     = 0;           // unknown; not required by most titles
            xid->BaseVersion = 0;
            xid->Platform    = 2;           // Xbox 360
            xid->ReservedA   = 0;
            xid->ReservedB   = 0;
            s_execIdEA.store(g_memory.MapVirtual(host), std::memory_order_release);
            KernelTraceHostOpF("HOST.XamGetExecutionId.init xid_ea=%08X", s_execIdEA.load());
        }
    }

    const uint32_t ea = s_execIdEA.load(std::memory_order_acquire);
    if (outExecIdEA && ea) {
        *outExecIdEA = ea;
        KernelTraceHostOpF("HOST.XamGetExecutionId -> %08X", ea);
        return 0; // STATUS_SUCCESS
    }

    KernelTraceHostOp("HOST.XamGetExecutionId -> STATUS_UNSUCCESSFUL");
    return 0xC0000001; // STATUS_UNSUCCESSFUL
}

void XamLoaderLaunchTitle()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlInitAnsiString(XANSI_STRING* destination, char* source)
{
    const uint16_t length = source ? (uint16_t)strlen(source) : 0;
    destination->Length = length;
    destination->MaximumLength = length + 1;
    destination->Buffer = source;
}


uint32_t NtCreateFile(
    be<uint32_t>* FileHandle,
    uint32_t DesiredAccess,
    XOBJECT_ATTRIBUTES* Attributes,
    XIO_STATUS_BLOCK* IoStatusBlock,
    uint64_t* AllocationSize,
    uint32_t FileAttributes,
    uint32_t ShareAccess,
    uint32_t CreateDisposition,
    uint32_t CreateOptions)
{
    (void)AllocationSize;

    if (!FileHandle || !Attributes || !IoStatusBlock) {
        if (FileHandle) {
            *FileHandle = GUEST_INVALID_HANDLE_VALUE;
        }
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
            IoStatusBlock->Information = 0;
        }
        return STATUS_INVALID_PARAMETER;
    }

    std::string guestPath = ExtractGuestPath(Attributes);
    guestPath = NormalizeGuestPath(std::move(guestPath));

    // DEBUG: Log first 20 file open attempts to see what's being requested
    static int file_open_count = 0;
    if (++file_open_count <= 20) {
        fprintf(stderr, "[FILE-OPEN #%d] Guest path: '%s'\n", file_open_count, guestPath.c_str());
        fflush(stderr);
    }

    KernelTraceHostOpF("HOST.File.NtCreateFile.open path=%s", guestPath.c_str());

    if (guestPath.empty()) {
        if (file_open_count <= 20) {
            fprintf(stderr, "[FILE-OPEN #%d] FAILED: Empty path\n", file_open_count);
            fflush(stderr);
        }
        *FileHandle = GUEST_INVALID_HANDLE_VALUE;
        IoStatusBlock->Status = STATUS_OBJECT_NAME_INVALID;
        IoStatusBlock->Information = 0;
        return STATUS_OBJECT_NAME_INVALID;
    }

    uint32_t creation = 0;
    if (!MapCreateDisposition(CreateDisposition, creation)) {
        *FileHandle = GUEST_INVALID_HANDLE_VALUE;
        IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
        IoStatusBlock->Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    const uint32_t flags = MapCreateOptions(CreateOptions, FileAttributes);
    auto* handle = XCreateFileA(guestPath.c_str(), DesiredAccess, ShareAccess, nullptr, creation, flags);
    if (IsInvalidKernelObject(handle)) {
        const uint32_t status = (CreateDisposition == FILE_OPEN || CreateDisposition == FILE_OPEN_IF)
                                    ? STATUS_OBJECT_NAME_NOT_FOUND
                                    : STATUS_OBJECT_PATH_NOT_FOUND;
        if (file_open_count <= 20) {
            fprintf(stderr, "[FILE-OPEN #%d] FAILED: File not found, status=0x%08X\n", file_open_count, status);
            fflush(stderr);
        }
        *FileHandle = GUEST_INVALID_HANDLE_VALUE;
        IoStatusBlock->Status = status;
        IoStatusBlock->Information = 0;
        return status;
    }

    if (file_open_count <= 20) {
        fprintf(stderr, "[FILE-OPEN #%d] SUCCESS: File opened\n", file_open_count);
        fflush(stderr);
    }

    const uint32_t guestHandle = GetKernelHandle(static_cast<void*>(handle));
    *FileHandle = guestHandle;

    uint32_t info = FILE_OPENED;
    if (creation == CREATE_NEW) {
        info = FILE_CREATED;
    } else if (creation == CREATE_ALWAYS && (CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OVERWRITE_IF)) {
        info = FILE_OVERWRITTEN;
    }

    IoStatusBlock->Status = STATUS_SUCCESS;
    IoStatusBlock->Information = info;
    return STATUS_SUCCESS;
}

uint32_t NtOpenFile(
    be<uint32_t>* FileHandle,
    uint32_t DesiredAccess,
    XOBJECT_ATTRIBUTES* Attributes,
    XIO_STATUS_BLOCK* IoStatusBlock,
    uint32_t ShareAccess,
    uint32_t OpenOptions)
{
    return NtCreateFile(FileHandle, DesiredAccess, Attributes, IoStatusBlock, nullptr, 0, ShareAccess, FILE_OPEN, OpenOptions);
}


uint32_t NtClose(uint32_t handle)
{
    // Guard obvious invalid sentinel
    if (handle == GUEST_INVALID_HANDLE_VALUE) {
        static int invalid_close_count = 0;
        if (++invalid_close_count <= 5) {
            KernelTraceHostOpF("HOST.File.NtClose.invalid_handle handle=0xFFFFFFFF count=%d", invalid_close_count);
        }
        return STATUS_INVALID_HANDLE; // 0xC0000008
    }

    // Only attempt to destroy kernel objects if the handle is sane and maps
    // to memory we control. Some call sites erroneously pass NTSTATUS values
    // (e.g., 0xC00002F0) to NtClose during bring-up; those should not be
    // treated as valid kernel handles.
    if (IsKernelObject(handle))
    {
        // Validate guest offset before translating to host to avoid AV.
        if (!GuestOffsetInRange(handle, sizeof(void*)))
        {
            return STATUS_INVALID_HANDLE;
        }

        KernelObject* obj = GetKernelObject(handle);
        if (!IsKernelObjectAlive(obj))
        {
            return STATUS_INVALID_HANDLE;
        }

        // Ensure the object pointer lies within one of our heaps before
        // invoking the destructor. This prevents accidental calls on random
        // guest pointers or status codes misinterpreted as handles.
        auto in_range = [](void* p, void* base, size_t size) -> bool {
            return p >= base && p < (static_cast<uint8_t*>(base) + size);
        };

        const bool in_user_heap = in_range(obj, g_userHeap.heapBase, g_userHeap.heapSize);
        const bool in_phys_heap = in_range(obj, g_userHeap.physicalBase, g_userHeap.physicalSize);

        if (obj != nullptr && (in_user_heap || in_phys_heap))
        {
            DestroyKernelObject(handle);
            return STATUS_SUCCESS;
        }

        return STATUS_INVALID_HANDLE;
    }

    // Not a kernel object handle we recognize; treat as invalid for now.
    return STATUS_INVALID_HANDLE;
}

void NtSetInformationFile()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t FscSetCacheElementCount()
{
    return 0;
}

// 2) Typical wait path (single-object) without IsSignaled() or wrong table name
// Decls for pass-through (match your existing linkage)
extern "C" NTSTATUS __imp__NtWaitForSingleObjectEx(
    void* Handle, BOOLEAN Alertable, LARGE_INTEGER* Timeout, ULONG Mode);

// Helpers you already have:
//  - Mw05FastBootEnabled()
//  - Mw05ListShimsEnabled()
//  - GuestOffsetInRange(...)
//  - KeWaitForSingleObject(...)
//  - GuestTimeoutToMilliseconds(...)
//  - IsKernelObject(...), GetKernelObject(...)
//  - GuestThread::LookupHandleByThreadId(...)
extern "C" uint32_t NtWaitForSingleObjectEx(uint32_t Handle,
                                            uint32_t WaitMode,
                                            uint32_t Alertable,
                                            be<int64_t>* Timeout)
{
    static std::atomic<int> s_waitCount{0};
    int count = s_waitCount.fetch_add(1);

    // CRITICAL DEBUG: Log Thread #2 (entry=0x82812ED0) wait calls
    // Log ALL calls to NtWaitForSingleObjectEx to debug Thread #2 issue
    static std::atomic<int> s_allWaitCount{0};
    int waitNum = s_allWaitCount.fetch_add(1);
    DWORD currentTid = GetCurrentThreadId();

    if (waitNum < 50) {  // Log first 50 calls from ALL threads
        fprintf(stderr, "[ALL_WAIT] Call #%d: tid=0x%08X handle=0x%08X WaitMode=%u Alertable=%u\n",
                waitNum + 1, currentTid, Handle, WaitMode, Alertable);
        fflush(stderr);
    }

    if (count < 10) {  // Log first 10 waits
        fprintf(stderr, "[NtWaitForSingleObjectEx] Call #%d: Handle=0x%08X WaitMode=%u Alertable=%u\n",
                count + 1, Handle, WaitMode, Alertable);
        fflush(stderr);
    }

    // CRITICAL FIX: Handle NULL handle - return error instead of success
    // The game should NOT wait on a NULL handle
    // Returning SUCCESS causes the worker loop to continue instead of blocking
    // Returning INVALID_HANDLE will cause the loop to exit (as it should)
    if (Handle == 0) {
        static std::atomic<int> s_nullHandleCount{0};
        int null_count = s_nullHandleCount.fetch_add(1);
        if (null_count < 5) {
            fprintf(stderr, "[NtWaitForSingleObjectEx] NULL handle detected (call #%d), returning INVALID_HANDLE\n", null_count + 1);
            fflush(stderr);
        }
        return STATUS_INVALID_HANDLE;  // Return error for NULL handle
    }

    const bool fastBoot  = Mw05FastBootEnabled();
    const bool listShims = Mw05ListShimsEnabled();
    static const auto t0 = std::chrono::steady_clock::now();

    const uint32_t timeout = GuestTimeoutToMilliseconds(Timeout);

    // --- TEMP diagnostics (rate-limited) ---
    static std::atomic<int> s_diagOnce{0};
    auto log_once = [&](const char* tag){
        int expected = 0;
        if (s_diagOnce.compare_exchange_strong(expected, 1)) {
            const char* tag = "HOST.Wait.NtWaitForSingleObjectEx";   // neutral fallback
            if (fastBoot) {
                tag = "HOST.FastWait.NtWaitForSingleObjectEx";
            } else if (listShims) {
                tag = "HOST.MW05_LIST_SHIMS.NtWaitForSingleObjectEx";
            }

            KernelTraceHostOp(fastBoot
                ? "HOST.FastWait.NtWaitForSingleObjectEx"
                : listShims
                  ? "HOST.MW05_LIST_SHIMS.NtWaitForSingleObjectEx"
                  : "HOST.Wait.NtWaitForSingleObjectEx");
        }
    };

    // --- FAST BOOT: return immediately, don't try to wait ---
    if (fastBoot && (std::chrono::steady_clock::now() - t0) < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.FastWait.NtWaitForSingleObjectEx");
        if (GuestOffsetInRange(Handle, sizeof(XDISPATCHER_HEADER))) {
            if (auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(Handle))) {
                hdr->SignalState = be<int32_t>(1); // nudge to signaled
            }
        }
        HostSleepTiny();
        return STATUS_SUCCESS;
    }

    // --- LIST_SHIMS: optional heuristic, but non-blocking and guarded ---
    if (listShims && (std::chrono::steady_clock::now() - t0) < std::chrono::seconds(30)) {
        // If it's not a known dispatcher EA, but looks like one, try a 0ms poll.
        if (GuestOffsetInRange(Handle, sizeof(XDISPATCHER_HEADER))) {
            if (auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(Handle))) {
                KernelTraceHostOp("HOST.MW05_LIST_SHIMS.NtWaitForSingleObjectEx.EAOverride");
                be<int64_t> zero{}; // 0ms poll
                return KeWaitForSingleObject(hdr, /*WaitReason*/0, WaitMode, Alertable != 0, &zero);
            }
        }
    }

    // Kernel handle path
    if (IsKernelObject(Handle)) {
        log_once("WAIT classify: kernel-handle");

        KernelObject* kernel = GetKernelObject(Handle);
        if (!IsKernelObjectAlive(kernel)) {
            return STATUS_INVALID_HANDLE;
        }



        if (const char* tlw = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
            if (!(tlw[0]=='0' && tlw[1]==0)) {
                KernelTraceHostOpF("HOST.Wait.path.NtWaitForSingleObjectEx.kernel_handle handle=%08X", Handle);
            }
        }
        // Record last-wait kernel handle for ISR fallback
        g_lastWaitKernelHandle.store(Handle, std::memory_order_release);
        if (const char* tlw_h = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
            if (!(tlw_h[0]=='0' && tlw_h[1]=='\0')) {
                KernelTraceHostOpF("HOST.Wait.last.handle NtWaitForSingleObjectEx handle=%08X", Handle);
            }
        }
        // CRITICAL FIX: Wrap ALL kernel object access in SEH to handle access violations
        // This includes dynamic_cast and Wait() calls
        // Use SEH (Structured Exception Handling) because access violations are Windows structured exceptions
        NTSTATUS result = STATUS_INVALID_HANDLE;
        __try {
            // Add detailed logging before calling Wait()
            static std::atomic<int> s_waitCallCount{0};
            int callNum = s_waitCallCount.fetch_add(1);
            if (callNum < 20) {  // Log first 20 calls
                fprintf(stderr, "[WAIT_DEBUG] Call #%d: kernel=%p Handle=0x%08X timeout=%u\n",
                        callNum + 1, (void*)kernel, Handle, timeout);
                fflush(stderr);
            }

            // Record last-wait EA/type if this handle maps to a known guest-backed object
            if (auto* ev = dynamic_cast<Event*>(kernel)) {
                if (ev->guestHeaderEA && GuestOffsetInRange(ev->guestHeaderEA, sizeof(XDISPATCHER_HEADER))) {
                    g_lastWaitEventEA.store(ev->guestHeaderEA, std::memory_order_release);
                    const uint32_t typ = ev->manualReset ? 0u : 1u;
                    g_lastWaitEventType.store(typ, std::memory_order_release);
                    if (const char* tlw2 = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
                        if (!(tlw2[0]=='0' && tlw2[1]=='\0')) {
                            KernelTraceHostOpF("HOST.Wait.last.record ea=%08X type=%u (NtWaitForSingleObjectEx.handle->event)", ev->guestHeaderEA, typ);
                        }
                    }
                }
            } else if (auto* sem = dynamic_cast<Semaphore*>(kernel)) {
                if (sem->guestHeaderEA && GuestOffsetInRange(sem->guestHeaderEA, sizeof(XDISPATCHER_HEADER))) {
                    g_lastWaitEventEA.store(sem->guestHeaderEA, std::memory_order_release);
                    g_lastWaitEventType.store(5u, std::memory_order_release);
                    if (const char* tlw2 = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
                        if (!(tlw2[0]=='0' && tlw2[1]=='\0')) {
                            KernelTraceHostOpF("HOST.Wait.last.record ea=%08X type=5 (NtWaitForSingleObjectEx.handle->semaphore)", sem->guestHeaderEA);
                        }
                    }
                }
            }

            result = kernel->Wait(timeout);

            if (callNum < 20) {
                fprintf(stderr, "[WAIT_DEBUG] Call #%d: SUCCESS result=0x%08lX\n", callNum + 1, (unsigned long)result);
                fflush(stderr);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            static std::atomic<int> s_waitCrashCount{0};
            int crashNum = s_waitCrashCount.fetch_add(1);
            DWORD exceptionCode = GetExceptionCode();
            if (crashNum < 10) {  // Log first 10 occurrences
                fprintf(stderr, "[WAIT_SYNC] SEH Exception (occurrence #%d) - code=0x%08lX kernel=%p Handle=0x%08X\n",
                        crashNum + 1, (unsigned long)exceptionCode, (void*)kernel, Handle);
                fflush(stderr);
            }
            return STATUS_INVALID_HANDLE;
        }

        return result;
    }

    // Thread-id path
    if (uint32_t kh = GuestThread::LookupHandleByThreadId(Handle)) {
        log_once("WAIT classify: thread-id->kernel-handle");
        KernelObject* kernel = GetKernelObject(kh);
        if (!IsKernelObjectAlive(kernel)) {
            return STATUS_INVALID_HANDLE;
        }
        return kernel->Wait(timeout);
    }

    // Dispatcher-pointer path (guest EA)
    if (GuestOffsetInRange(Handle, sizeof(XDISPATCHER_HEADER))) {
        log_once("WAIT classify: dispatcher-EA");
        // DumpRawHeader16(Handle);  // see helper below
        auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(Handle));
        if (hdr) {
            Mw05RegisterVdInterruptEvent(Handle, hdr->Type == 0);

	        Mw05ForceVdInitOnce();
	        Mw05LogIsrIfRegisteredOnce();
        }
        const uint8_t  T   = hdr ? hdr->Type : 0;        // byte 0
        const uint8_t  Abs = hdr ? hdr->Absolute : 0;    // byte 1 (union)
        const uint8_t  Sz  = hdr ? hdr->Size : 0;        // byte 2
        const uint8_t  Ins = hdr ? hdr->Inserted : 0;    // byte 3
        const int32_t  Sig = hdr ? static_cast<int32_t>(hdr->SignalState.get()) : 0; // 32-bit at 0x04 (big-endian wrapper handles byte order)

        KernelTraceHostOpF("HOST.Wait.Disp ea=%08X T=%u Abs=%u Sz=%u Ins=%u Sig=%d",
                       Handle, T, Abs, Sz, Ins, Sig);

        {
            // Optional: force-ack the scheduler/event fence prior to blocking
            if (Mw05ForceAckWaitEnabled()) {
                Mw05ForceAckFromEventEA(Handle);
            }
            const uint32_t rc = KeWaitForSingleObject(hdr, /*WaitReason*/0, WaitMode, Alertable != 0, Timeout);
            // Treat the registered Vd interrupt event as pulse-like to avoid
            // a tight re-wait loop on manual-reset events that remain signaled.
            if (rc == STATUS_SUCCESS) {
                const uint32_t reg_ea = g_vdInterruptEventEA.load(std::memory_order_acquire);
                if (reg_ea != 0 && Handle == reg_ea) {
                    if (auto* ev = TryQueryKernelObject<Event>(*hdr)) {
                        if (!ev->manualReset) {
                            ev->Reset();
                            hdr->SignalState = be<int32_t>(0);
                        } else {
                            hdr->SignalState = be<int32_t>(1);
                        }
                    } else {
                        hdr->SignalState = be<int32_t>(0);
                    }
                }
            }
            KernelTraceHostOpF("HOST.Wait.Disp.rc ea=%08X rc=%08X Sig=%d", Handle, rc, hdr ? static_cast<int32_t>(hdr->SignalState.get()) : -1);
            return rc;
        }
    }

    log_once("WAIT classify: INVALID_HANDLE");
    return STATUS_INVALID_HANDLE;
}

uint32_t NtWriteFile(
    uint32_t handleId,
    uint32_t Event,
    uint32_t ApcRoutine,
    uint32_t ApcContext,
    XIO_STATUS_BLOCK* IoStatusBlock,
    const void* Buffer,
    uint32_t Length,
    be<int64_t>* ByteOffset,
    be<uint32_t>* Key)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;

    if (!IoStatusBlock || !Buffer) {
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
            IoStatusBlock->Information = 0;
        }
        return STATUS_INVALID_PARAMETER;
    }

    if (Length == 0) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
        return STATUS_SUCCESS;
    }

    if (!IsKernelObject(handleId)) {
        IoStatusBlock->Status = STATUS_INVALID_HANDLE;
        IoStatusBlock->Information = 0;
        return STATUS_INVALID_HANDLE;
    }

    auto* file = GetKernelObject<FileHandle>(handleId);
    if (!file || !IsKernelObjectAlive(reinterpret_cast<const KernelObject*>(file))) {
        return STATUS_INVALID_HANDLE;
    }

    LARGE_INTEGER originalPos{};
    bool hasOriginal = false;

    if (ByteOffset) {
        const int64_t offset = static_cast<int64_t>(*ByteOffset);
        if (!ApplyAbsoluteOffset(file, offset, originalPos, hasOriginal)) {
            RestoreFileOffset(file, originalPos, hasOriginal);
            IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
            IoStatusBlock->Information = 0;
            return STATUS_INVALID_PARAMETER;
        }
    }

    be<uint32_t> bytesWritten = 0;
    const uint32_t rc = XWriteFile(file, Buffer, Length, &bytesWritten, nullptr);
    const bool ok = (rc != 0);  // optional: if you still want a bool

    RestoreFileOffset(file, originalPos, hasOriginal);

    const uint32_t status = ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    IoStatusBlock->Status = status;
    IoStatusBlock->Information = bytesWritten;
    return status;
}


void vsprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t ExGetXConfigSetting(uint16_t Category, uint16_t Setting, void* Buffer, uint16_t SizeOfBuffer, be<uint32_t>* RequiredSize)
{
    KernelTraceHostOpF("HOST.ExGetXConfigSetting cat=%04X setting=%04X size=%u", Category, Setting, SizeOfBuffer);

    uint32_t data[4]{};

    switch (Category)
    {
        // XCONFIG_SECURED_CATEGORY
        case 0x0002:
        {
            switch (Setting)
            {
                // XCONFIG_SECURED_AV_REGION
                case 0x0002:
                    // CRITICAL FIX: Init6 (sub_8262E7F8) checks if (v8 & 0xFF00) == 0x300
                    // This means the upper byte must be 0x03, not 0x10
                    // The correct value is 0x00000300 (NTSC region code)
                    data[0] = ByteSwap(0x00000300); // NTSC region (was 0x00001000)
                    break;

                default:
                    return 1;
            }
        }
        break;

        // XCONFIG_USER_CATEGORY
        case 0x0003:
        {
            switch (Setting)
            {
                case 0x0001: // XCONFIG_USER_TIME_ZONE_BIAS
                case 0x0002: // XCONFIG_USER_TIME_ZONE_STD_NAME
                case 0x0003: // XCONFIG_USER_TIME_ZONE_DLT_NAME
                case 0x0004: // XCONFIG_USER_TIME_ZONE_STD_DATE
                case 0x0005: // XCONFIG_USER_TIME_ZONE_DLT_DATE
                case 0x0006: // XCONFIG_USER_TIME_ZONE_STD_BIAS
                case 0x0007: // XCONFIG_USER_TIME_ZONE_DLT_BIAS
                    data[0] = 0;
                    break;

                // XCONFIG_USER_LANGUAGE
                case 0x0009:
                    data[0] = ByteSwap((uint32_t)Config::Language.Value);
                    break;

                // XCONFIG_USER_VIDEO_FLAGS
                case 0x000A:
                    // CRITICAL FIX: Init6 (sub_8262E7F8) checks if ((v9 & 0x800000) != 0 || (v9 & 0x400000) == 0)
                    // Bit 0x800000 = HD mode, Bit 0x400000 = widescreen
                    // Set HD mode bit to satisfy the condition
                    data[0] = ByteSwap(0x00840000); // HD mode + original flags (was 0x00040000)
                    break;

                // XCONFIG_USER_RETAIL_FLAGS
                case 0x000C:
                    data[0] = ByteSwap(1);
                    break;

                // XCONFIG_USER_COUNTRY
                case 0x000E:
                    data[0] = ByteSwap(103);
                    break;

                default:
                    return 1;
            }
        }
        break;

        default:
            return 1;
    }

    if (RequiredSize) *RequiredSize = 4;
    if (Buffer && SizeOfBuffer) {
        memcpy(Buffer, data, std::min((size_t)SizeOfBuffer, sizeof(uint32_t)));
    }

    KernelTraceHostOpF("HOST.ExGetXConfigSetting -> ok val=%08X", ByteSwap(data[0]));
    return 0;
}

uint32_t NtQueryVirtualMemory(
    uint32_t /*ProcessHandle*/,
    uint32_t BaseAddress,
    uint32_t MemoryInformationClass,
    uint32_t Buffer,
    uint32_t Length,
    be<uint32_t>* ReturnLength)
{
    // Very small emulation sufficient for simple probes.
    // Validate guest pointers to avoid host faults.
    auto in_range = [](uint32_t guest_off, size_t bytes) -> bool {
        if (guest_off == 0) return false;
        if (guest_off < 4096) return false; // guard page
        return (size_t)guest_off + bytes <= PPC_MEMORY_SIZE;
    };

    if (ReturnLength && ((size_t)ReturnLength - (size_t)g_memory.base) < PPC_MEMORY_SIZE)
        *ReturnLength = 0;

    if (!in_range(Buffer, Length))
        return 0xC0000005; // STATUS_ACCESS_VIOLATION

    // For MemoryBasicInformation (class 0), report a single committed RW private region from the
    // provided BaseAddress up to the end of guest memory. Fill a minimal 7x u32 struct.
    if (MemoryInformationClass == 0 && Length >= 7 * sizeof(uint32_t))
    {
        uint32_t info[7] = {};
        // inside NtQueryVirtualMemory (class 0 case)
        const size_t base_sz = static_cast<size_t>(BaseAddress);
        const uint32_t base = static_cast<uint32_t>(base_sz);
        const uint32_t alloc_base = base & ~0xFFFu;

        // CRITICAL FIX: Return realistic region size (512 MB) instead of full 4 GB address space!
        // The game uses this to determine how much memory to zero during initialization.
        // Xbox 360 had 512 MB total RAM, so we should report a similar amount.
        // This prevents the game from trying to zero 4 GB of memory!
        constexpr uint32_t XBOX_360_RAM = 0x20000000;  // 512 MB (Xbox 360 total RAM)
        const uint32_t region_size = (base_sz < PPC_MEMORY_SIZE) ? XBOX_360_RAM : 0;

        // Fields: BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type
        info[0] = base;
        info[1] = alloc_base;
        info[2] = PAGE_READWRITE;
        info[3] = region_size;
        info[4] = MEM_COMMIT;      // committed
        info[5] = PAGE_READWRITE;  // current protect
        info[6] = 0x20000;         // MEM_PRIVATE (value used by NT)

        memcpy(g_memory.Translate(Buffer), info, 7 * sizeof(uint32_t));
        if (ReturnLength && ((size_t)ReturnLength - (size_t)g_memory.base) < PPC_MEMORY_SIZE)
            *ReturnLength = 7 * sizeof(uint32_t);

        return 0; // STATUS_SUCCESS
    }

    // Default: zero the buffer up to Length and return success; some callers only check status.
    // CRITICAL FIX: Add bounds checking to prevent zeroing huge regions of memory!
    // The game might pass Length=0xFFFFFFFF or other huge values, which would corrupt the heap.
    const uint32_t MAX_SAFE_LENGTH = 4096;  // Reasonable limit for query results
    if (Length > MAX_SAFE_LENGTH) {
        fprintf(stderr, "[NtQueryVirtualMemory] WARNING: Length=%u (0x%X) exceeds safe limit, capping to %u\n",
                Length, Length, MAX_SAFE_LENGTH);
        fprintf(stderr, "[NtQueryVirtualMemory] BaseAddress=0x%08X Buffer=0x%08X Class=%u\n",
                BaseAddress, Buffer, MemoryInformationClass);
        fflush(stderr);
        Length = MAX_SAFE_LENGTH;
    }

    memset(g_memory.Translate(Buffer), 0, Length);
    return 0; // STATUS_SUCCESS
}

// Kernel expects Xbox-style MmQueryStatistics(&out).
// Provide just enough to stop busy-wait loops.
struct XMM_STATS {
    be<uint32_t> AvailablePages;     // pages of 64 KiB on 360
    be<uint32_t> TotalPhysicalPages; // "
    be<uint32_t> PageSize;           // bytes
    be<uint32_t> Unknown0;           // pad
    be<uint32_t> Unknown1;           // pad
};

uint32_t MmQueryStatistics(XMM_STATS* out_stats)
{
    if (!out_stats) return STATUS_INVALID_PARAMETER;

    // Pick a consistent "page" model; titles mostly sanity-check, not exact match.
    constexpr uint32_t kPageSize = 0x10000; // 64 KiB
    const uint32_t total = static_cast<uint32_t>(g_userHeap.physicalSize / kPageSize);
	// Without exact usage, return a safe non-zero value (half of total).
    const uint32_t avail = total ? (total / 2) : 0;

    out_stats->AvailablePages     = avail;
    out_stats->TotalPhysicalPages = total;
    out_stats->PageSize           = kPageSize;
    out_stats->Unknown0 = 0;
    out_stats->Unknown1 = 0;
    return STATUS_SUCCESS;
}

uint32_t NtCreateEvent(be<uint32_t>* handle, void* objAttributes, uint32_t eventType, uint32_t initialState)
{
    fprintf(stderr, "[NtCreateEvent] CALLED: eventType=%u initialState=%u\n", eventType, initialState);
    fflush(stderr);

    *handle = GetKernelHandle(CreateKernelObject<Event>(!eventType, !!initialState));

    fprintf(stderr, "[NtCreateEvent] Created event handle=0x%08X\n", (uint32_t)*handle);
    fflush(stderr);

    return 0;
}

void DbgPrint()
{
    LOG_UTILITY("!!! STUB !!!");
}

void __C_specific_handler_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t RtlNtStatusToDosError(uint32_t Status)
{
    static int call_count = 0;
    call_count++;

    // Only log first 10 calls and every 1000th call to avoid spam
    if (call_count <= 10 || (call_count % 1000) == 0) {
        fprintf(stderr, "[RtlNtStatusToDosError] Call #%d: Status=0x%08X\n", call_count, Status);
        fflush(stderr);
    }

    // For now, pass through common success and map unknown NTSTATUS to generic ERROR_GEN_FAILURE.
    // Titles often just check for zero/non-zero.
    if (Status == STATUS_SUCCESS) return 0;
    // If it's already a small Win32 error-style code, pass through.
    if ((Status & 0xFFFF0000u) == 0) return Status;
    // Generic failure (31).

    if (call_count <= 10 || (call_count % 1000) == 0) {
        fprintf(stderr, "[RtlNtStatusToDosError] Returning 31\n");
        fflush(stderr);
    }
    return 31u;
}

// Minimal implementation: return not found and null out pointer.
// NTSTATUS XexGetProcedureAddress(HMODULE hModule, uint32_t ordinal, void** out_fn, uint32_t flags)
uint32_t XexGetProcedureAddress(uint32_t hModule, uint32_t Ordinal, be<uint32_t>* OutFnEA, uint32_t /*Flags*/)
{
    KernelTraceHostOpF("HOST.XexGetProcedureAddress hModule=%08X ord=%u", hModule, Ordinal);
    if (OutFnEA) *OutFnEA = 0u;
    return 0xC0000139; // STATUS_ENTRYPOINT_NOT_FOUND
}

// XexGetModuleSection with section bounds matched to MW05 XEX (from xenia.log)
// NTSTATUS XexGetModuleSection(HANDLE module, const char* name, void** base, uint32_t* size)
uint32_t XexGetModuleSection(uint32_t /*hModule*/, const char* name, be<uint32_t>* outBase, be<uint32_t>* outSize)
{
    auto ret = [&](uint32_t base, uint32_t size, const char* sec) -> uint32_t {
        if (outBase) *outBase = base;
        if (outSize) *outSize = size;
        KernelTraceHostOpF("HOST.XexGetModuleSection %s base=%08X size=%08X", sec, base, size);
        return 0; // STATUS_SUCCESS
    };

    // MW05 layout (per Mw05RecompLib/config/xenia.log):
    //   RODATA: 0x82000000..0x820E0000  (size 0x00E0000)
    //   CODE:   0x820E0000..0x828C0000  (size 0x07E0000)
    //   RWDATA: 0x828D0000..0x82C90000  (size 0x03C0000)
    //   RODATA2:0x82C90000..0x82CD0000  (size 0x0040000)
    if (name) {
        const uint32_t kRdataBase  = 0x82000000u;
        const uint32_t kRdataSize  = 0x000E0000u;
        const uint32_t kTextBase   = 0x820E0000u;
        const uint32_t kTextSize   = 0x007E0000u;
        const uint32_t kDataBase   = 0x828D0000u;
        const uint32_t kDataSize   = 0x003C0000u;
        const uint32_t kRdata2Base = 0x82C90000u;
        const uint32_t kRdata2Size = 0x00040000u;

        if (std::strcmp(name, ".text") == 0 || std::strcmp(name, "text") == 0) {
            return ret(kTextBase, kTextSize, ".text");
        }
        if (std::strcmp(name, ".rdata") == 0 || std::strcmp(name, "rdata") == 0) {
            return ret(kRdataBase, kRdataSize, ".rdata");
        }
        if (std::strcmp(name, ".data") == 0 || std::strcmp(name, "data") == 0) {
            return ret(kDataBase, kDataSize, ".data");
        }
        // Some games look for a trailing rodata-like chunk with different spellings
        if (std::strcmp(name, ".rdata2") == 0 || std::strcmp(name, "rdata2") == 0 || std::strcmp(name, ".rconst") == 0) {
            return ret(kRdata2Base, kRdata2Size, ".rdata2");
        }
    }

    if (outBase) *outBase = 0;
    if (outSize) *outSize = 0;
    KernelTraceHostOpF("HOST.XexGetModuleSection name=\"%s\" -> STATUS_OBJECT_NAME_NOT_FOUND", name ? name : "<null>");
    return 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
}

uint32_t RtlUnicodeToMultiByteN(char* MultiByteString, uint32_t MaxBytesInMultiByteString, be<uint32_t>* BytesInMultiByteString, const be<uint16_t>* UnicodeString, uint32_t BytesInUnicodeString)
{
    // Trace a preview of the Unicode string to help discover path construction
    if (KernelTraceEnabled() && UnicodeString && BytesInUnicodeString) {
        const uint32_t chars = BytesInUnicodeString / 2u;
        char preview[96]{}; unsigned i=0;
        for (; i < (sizeof(preview)-1) && i < chars; ++i) {
            const uint16_t w = UnicodeString[i].get();
            if (w == 0) break;
            if (w < 0x20 || w > 0x7E) { preview[i] = '?'; continue; }
            preview[i] = char(w);
        }
        preview[i] = 0;
        KernelTraceHostOpF("HOST.RtlUnicodeToMB src='%s' bytes=%u", preview, BytesInUnicodeString);
    }

    const auto reqSize = BytesInUnicodeString / sizeof(uint16_t);

    if (BytesInMultiByteString)
        *BytesInMultiByteString = reqSize;

    if (reqSize > MaxBytesInMultiByteString)
        return STATUS_INVALID_PARAMETER;

    for (size_t i = 0; i < reqSize; i++)
    {
        const auto c = UnicodeString[i].get();

        MultiByteString[i] = c < 256 ? c : '?';
    }

    return STATUS_SUCCESS;
}

// ---- FIXED KeDelayExecutionThread ----
extern "C"
NTSTATUS KeDelayExecutionThread(KPROCESSOR_MODE /*Mode*/,
                                BOOLEAN Alertable,
                                PLARGE_INTEGER IntervalGuest)
{
    // Mark that the last wait was a time delay, not a dispatcher; helps explain last==0
    g_lastWaitEventEA.store(0u, std::memory_order_release);
    g_lastWaitEventType.store(0xFFu, std::memory_order_release);
    KernelTraceHostOp("HOST.Wait.observe.KeDelayExecutionThread");

    // CRITICAL DEBUG: Log sleep calls to detect stuck threads
    static std::atomic<uint64_t> s_sleep_count{0};
    uint64_t sleep_num = ++s_sleep_count;

    // Read SIGNED 64-bit ticks from guest (100ns units; negative = relative)
    const int64_t ticks = read_guest_i64(IntervalGuest);

    // CRITICAL: Capture LR (link register) to see where the yield is being called from
    static uint32_t s_last_lr = 0;
    PPCContext* ctx = GetPPCContext();
    uint32_t current_lr = ctx ? static_cast<uint32_t>(ctx->lr) : 0;

    if (sleep_num % 10000 == 0 || (ticks == 0 && current_lr != s_last_lr)) {
        fprintf(stderr, "[SLEEP_DEBUG] KeDelayExecutionThread called %llu times, tid=%lx, ticks=%lld, lr=0x%08X\n",
                sleep_num, (unsigned long)GetCurrentThreadId(), (long long)ticks, current_lr);
        fflush(stderr);
        if (ticks == 0) {
            s_last_lr = current_lr;
        }
    }

    // CRITICAL FIX: Check for pending APCs BEFORE sleeping
    // If the thread is alertable and there are pending APCs, process them and return STATUS_USER_APC
    if (Alertable && ApcPendingForCurrentThread()) {
        KernelTraceHostOp("HOST.KeDelayExecutionThread.APC_PENDING");

        // Process the APC
        if (ProcessPendingApcs()) {
            // Return STATUS_USER_APC (0x101 / 257) to indicate that an APC was delivered
            // This will cause the sleep loop in sub_8262F2A0 to continue looping
            return STATUS_USER_APC;
        }
    }

    const bool fastBoot  = Mw05FastBootEnabled();

    // Ensure early video bring-up keeps the UI responsive during waits/delays
	Mw05ForceVdInitOnce();  // opt-in early engines + ring/wb
    Mw05AutoVideoInitIfNeeded();
    Mw05StartVblankPumpOnce();
    // One-time forced VD event registration if requested via env
    Mw05MaybeForceRegisterVdEventFromEnv();

    // Optionally install a host default VD ISR if none is registered yet
    Mw05MaybeInstallDefaultVdIsr();

    // Opportunistic nudge: if FORCE_ACK_WAIT is on, ack the registered VD event even if title is sleeping
    if (Mw05ForceAckWaitEnabled()) {
        const uint32_t reg_ea = g_vdInterruptEventEA.load(std::memory_order_acquire);
        if (reg_ea) Mw05ForceAckFromEventEA(reg_ea);
    }


    // Optional: proactively pulse VD event during sleeps to push idle loops forward
    if (Mw05PulseVdOnSleepEnabled()) {
        if (Mw05SignalVdInterruptEvent()) {
            KernelTraceHostOp("HOST.VdInterruptEvent.pulse.on_sleep");
        }
    }

    const bool listShims = Mw05ListShimsEnabled();

    static const auto t0 = std::chrono::steady_clock::now();
    const auto elapsed   = std::chrono::steady_clock::now() - t0;

    // Fast-boot: bypass during early boot only
    if (fastBoot && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.FastDelay.KeDelayExecutionThread");
        NudgeEventWaiters();                 // <--- wake pollers using generation waits
        return STATUS_SUCCESS;
    }

    // LIST_SHIMS: also bypass during early boot (trace + nudge instead of sleeping)
    if (listShims && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.MW05_LIST_SHIMS.KeDelayExecutionThread");
        NudgeEventWaiters();                 // <--- critical to avoid вЂњstaleвЂќ loops
        return STATUS_SUCCESS;
    }

    // CRITICAL FIX: Add memory fence to ensure visibility of writes from other threads
    // This is necessary because the game uses busy-wait loops that check shared memory
    // without explicit synchronization primitives. Without this fence, Thread #1 might
    // not see the state flag write from Thread #2, causing an infinite wait loop.
    std::atomic_thread_fence(std::memory_order_seq_cst);

    if (ticks == 0) {
        host_sleep(0);                       // yield only
        return STATUS_SUCCESS;
    }

    if (ticks < 0) {
        // Relative delay
        int64_t remaining100 = -ticks;
        while (remaining100 > 0) {
            const int chunk_ms = std::min(ceil_ms_from_100ns(remaining100), 100);
            host_sleep(std::max(chunk_ms, 1));
            remaining100 -= int64_t(chunk_ms) * 10'000;

            // CRITICAL FIX: Check for APCs after each sleep chunk
            if (Alertable && ApcPendingForCurrentThread()) {
                KernelTraceHostOp("HOST.KeDelayExecutionThread.APC_PENDING_AFTER_SLEEP");
                if (ProcessPendingApcs()) {
                    return STATUS_USER_APC;
                }
            }
        }
        return STATUS_SUCCESS;
    }

    // Absolute delay
    const int64_t deadline100 = ticks;
    for (;;) {
        const int64_t now100 = query_system_time_100ns();
        if (now100 >= deadline100) break;
        const int64_t remain100 = deadline100 - now100;
        const int chunk_ms = std::min(ceil_ms_from_100ns(remain100), 100);
        host_sleep(std::max(chunk_ms, 1));

        // CRITICAL FIX: Check for APCs after each sleep chunk
        if (Alertable && ApcPendingForCurrentThread()) {
            KernelTraceHostOp("HOST.KeDelayExecutionThread.APC_PENDING_AFTER_SLEEP");
            if (ProcessPendingApcs()) {
                return STATUS_USER_APC;
            }
        }
    }
    return STATUS_SUCCESS;
}

// Some titles gate functionality behind kernel privilege checks. Be permissive by default.
// CRITICAL FIX: Init6 (sub_8262E7F8) calls XexCheckExecutablePrivilege(0xAu) to check privilege 10
// Privilege 10 = XEX_PRIVILEGE_INSECURE_SOCKETS (allows network access)
// Most Wanted uses this to check if it can access online features
// We need to return TRUE (1) for this privilege to allow Init7 to be called
uint32_t XexCheckExecutablePrivilege(uint32_t Privilege)
{
    KernelTraceHostOpF("HOST.XexCheckExecutablePrivilege privilege=%u", Privilege);

    // Be permissive - allow all privileges
    // Privilege 10 (0xA) = XEX_PRIVILEGE_INSECURE_SOCKETS
    // This is required for Init6 to return TRUE and call Init7
    const uint32_t result = 1; // present

    KernelTraceHostOpF("HOST.XexCheckExecutablePrivilege -> %u (privilege granted)", result);
    return result;
}

void NtQueryInformationFile()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NtQueryVolumeInformationFile()
{
    LOG_UTILITY("!!! STUB !!!");
}

extern "C" uint32_t NtQueryDirectoryFile(
    uint32_t FileHandle,
    uint32_t Event,
    uint32_t ApcRoutine,
    uint32_t ApcContext,
    XIO_STATUS_BLOCK* IoStatusBlock,
    void* FileInformation,
    uint32_t Length,
    uint32_t FileInformationClass,
    uint8_t ReturnSingleEntry,
    void* FileName,
    uint8_t RestartScan)
{
    (void)FileHandle; (void)Event; (void)ApcRoutine; (void)ApcContext; (void)FileInformation;
    (void)Length; (void)FileInformationClass; (void)ReturnSingleEntry; (void)FileName; (void)RestartScan;

    // Minimal, safe-by-default implementation: report no entries.
    // This unblocks callers expecting a concrete NTSTATUS and IoStatusBlock update,
    // instead of our previous stub that returned nothing.
    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_NO_MORE_FILES; // 0x80000006
        IoStatusBlock->Information = 0;
    }

    KernelTraceHostOp("HOST.File.NtQueryDirectoryFile.empty");
    return STATUS_NO_MORE_FILES;
}

void NtReadFileScatter()
{

    LOG_UTILITY("!!! STUB !!!");
}

uint32_t NtReadFile(
    uint32_t handleId,
    uint32_t Event,
    uint32_t ApcRoutine,
    uint32_t ApcContext,
    XIO_STATUS_BLOCK* IoStatusBlock,
    void* Buffer,
    uint32_t Length,
    be<int64_t>* ByteOffset,
    be<uint32_t>* Key)
{
    (void)Key;

    if (!IoStatusBlock || !Buffer) {
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
            IoStatusBlock->Information = 0;
        }
        return STATUS_INVALID_PARAMETER;
    }

    if (Length == 0) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
        return STATUS_SUCCESS;
    }

    if (!IsKernelObject(handleId)) {
        IoStatusBlock->Status = STATUS_INVALID_HANDLE;
        IoStatusBlock->Information = 0;
        return STATUS_INVALID_HANDLE;
    }

    auto* file = GetKernelObject<FileHandle>(handleId);
    if (!file || !IsKernelObjectAlive(reinterpret_cast<const KernelObject*>(file))) {
        return STATUS_INVALID_HANDLE;
    }

    static std::atomic<int> s_loggedReadOnce{0};
    int expected_once = 0;
    if (s_loggedReadOnce.compare_exchange_strong(expected_once, 1)) {
        KernelTraceHostOpF("HOST.File.NtReadFile.called handle=%08X len=%u Event=%08X ApcRoutine=%08X ApcContext=%08X",
                          handleId, Length, Event, ApcRoutine, ApcContext);
    }

    LARGE_INTEGER originalPos{};
    bool hasOriginal = false;

    if (ByteOffset) {

        const int64_t offset = static_cast<int64_t>(*ByteOffset);
        if (!ApplyAbsoluteOffset(file, offset, originalPos, hasOriginal)) {
            RestoreFileOffset(file, originalPos, hasOriginal);
            IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
            IoStatusBlock->Information = 0;
            return STATUS_INVALID_PARAMETER;
        }
    }

    be<uint32_t> bytesRead = 0;
    const uint32_t rc = XReadFile(file, Buffer, Length, &bytesRead, nullptr);
    const bool ok = (rc != 0);  // optional: if you still want a bool

    RestoreFileOffset(file, originalPos, hasOriginal);

    const uint32_t status = ok ? STATUS_SUCCESS
                               : (bytesRead == 0 ? STATUS_END_OF_FILE : STATUS_UNSUCCESSFUL);

    IoStatusBlock->Status = status;
    IoStatusBlock->Information = bytesRead;

    // CRITICAL FIX: Queue the APC callback even for synchronous reads (like Xenia does)
    // The game expects the APC to be called to signal that the read has completed
    // Low bit probably means do not queue to IO ports (Xenia comment)
    if (ApcRoutine && (ApcRoutine & ~1) && status == STATUS_SUCCESS) {
        // Get the current thread handle
        uint32_t currentThreadHandle = GuestThread::GetCurrentThreadId();

        // Queue the APC
        // The APC routine signature is: void ApcRoutine(uint32_t ApcContext, XIO_STATUS_BLOCK* IoStatusBlock, uint32_t Reserved)
        // We pass ApcContext as arg1, IoStatusBlock address as arg2, and 0 as arg3
        uint32_t ioStatusBlockAddr = g_memory.MapVirtual(IoStatusBlock);

        // Queue the APC directly to the APC queue (NtQueueApcThread is defined later in the file)
        ApcEntry apc;
        apc.routine = ApcRoutine & ~1u;
        apc.context = ApcContext;
        apc.arg1 = ioStatusBlockAddr;
        apc.arg2 = 0;

        {
            std::lock_guard<std::mutex> lock(g_apcMutex);
            g_apcQueues[currentThreadHandle].push(apc);
        }

        KernelTraceHostOpF("HOST.File.NtReadFile.APC_QUEUED routine=%08X ctx=%08X iosb=%08X tid=%08X",
                          apc.routine, ApcContext, ioStatusBlockAddr, currentThreadHandle);
    }

    // CRITICAL FIX: Signal the event if provided (like Xenia does)
    if (Event && GuestOffsetInRange(Event, sizeof(XDISPATCHER_HEADER))) {
        if (auto* eventPtr = reinterpret_cast<XKEVENT*>(g_memory.Translate(Event))) {
            // Signal the event to indicate the read has completed
            KeSetEvent(eventPtr, 0, false);
            KernelTraceHostOpF("HOST.File.NtReadFile.EVENT_SIGNALED event=%08X", Event);
        }
    }

    return status;
}


// Pseudo-handle helper: treat any negative handle as "current *"
static inline bool IsPseudoHandle(uint32_t h) {
    return static_cast<int32_t>(h) < 0;
}

// Keep this signature in sync with your import/thunk layer.
uint32_t NtDuplicateObject(uint32_t SourceProcessHandle,
                           uint32_t SourceHandle,
                           uint32_t TargetProcessHandle,
                           uint32_t* TargetHandle,
                           uint32_t DesiredAccess,
                           uint32_t Attributes,
                           uint32_t Options)
{
    // Validate out param
    if (!TargetHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate source handle
    if (SourceHandle == 0 /* or your invalid sentinel */) {
        return STATUS_INVALID_HANDLE;
    }

    // Normalize pseudo process handles (caller uses -1/-2/etc. for current)
    const bool srcIsCurrent = IsPseudoHandle(SourceProcessHandle);
    const bool dstIsCurrent = IsPseudoHandle(TargetProcessHandle);
    (void)srcIsCurrent; (void)dstIsCurrent; // in this shim theyвЂ™re informational

    // If SAME_ACCESS is set, ignore DesiredAccess (Windows semantics)
    if (Options & DUPLICATE_SAME_ACCESS) {
        DesiredAccess = 0;
    }

    // Kernel objects in this project are duplicated by *mirroring* the value.
    // (Do any refcount bump you maintain for these here.)
    if (::IsKernelObject(SourceHandle)) {
        *TargetHandle = SourceHandle;
        if (Options & DUPLICATE_CLOSE_SOURCE) {
            // If you track open/close on kernel objects, perform it here.
            // e.g., KernelClose(SourceHandle);
        }
        return STATUS_SUCCESS;
    }

    // Non-kernel/guest handles: if your runtime doesnвЂ™t create a *new* slot,
    // just mirror the value as well (most titles only require this).
    *TargetHandle = SourceHandle;

    if (Options & DUPLICATE_CLOSE_SOURCE) {
        // Close the source in your table if you maintain one.
        // e.g., GuestCloseHandle(SourceHandle);
        // If you don't track them yet, it's safe to no-op.
    }

    return STATUS_SUCCESS;
}

// ExCreateThread is implemented later in this file (guest thread support)

// FIXED: Actually free memory using RtlFreeHeap
uint32_t NtFreeVirtualMemory(
    uint32_t /*ProcessHandle*/,
    be<uint32_t>* BaseAddress,
    be<uint32_t>* /*RegionSize*/,
    uint32_t /*FreeType*/)
{
    if (!BaseAddress) {
        return 0xC000000DL; // STATUS_INVALID_PARAMETER
    }

    const uint32_t guest_addr = static_cast<uint32_t>(*BaseAddress);
    if (guest_addr == 0) {
        return 0; // STATUS_SUCCESS (freeing NULL is OK)
    }

    // Translate to host pointer and free
    void* host_ptr = g_memory.Translate(guest_addr);
    if (host_ptr) {
        g_userHeap.Free(host_ptr);

        static int call_count = 0;
        if (++call_count <= 10) {
            fprintf(stderr, "[NtFreeVirtualMemory] Call #%d: freed guest=0x%08X (host=%p)\n",
                    call_count, guest_addr, host_ptr);
            fflush(stderr);
        }
    }

    *BaseAddress = 0;
    return 0; // STATUS_SUCCESS
}

// Xbox 360 variant uses 4 parameters from r3..r6
// FIXED: Actually allocate memory using RtlAllocateHeap (like Unleashed would if it needed this)
uint32_t NtAllocateVirtualMemory(
    be<uint32_t>* BaseAddress,
    be<uint32_t>* RegionSize,
    uint32_t AllocationType,
    uint32_t Protect)
{
    if (!BaseAddress || !RegionSize) {
        return 0xC000000DL; // STATUS_INVALID_PARAMETER
    }

    const uint32_t requested_size = static_cast<uint32_t>(*RegionSize);
    if (requested_size == 0) {
        return 0xC000000DL; // STATUS_INVALID_PARAMETER
    }

    // CRITICAL FIX (2025-11-01): Allocate from PHYSICAL heap, not user heap!
    // NtAllocateVirtualMemory is used for large allocations (textures, models, etc.)
    // These should go to physical heap (800 MB) to avoid exhausting user heap (2045 MB)
    // The game was allocating 100+ MB buffers via NtAllocateVirtualMemory, filling the user heap
    void* host_ptr = g_userHeap.AllocPhysical(requested_size, 0x1000);  // 4KB alignment
    if (!host_ptr) {
        fprintf(stderr, "[NtAllocateVirtualMemory] FAILED to allocate %u bytes from physical heap\n", requested_size);
        fflush(stderr);
        return 0xC0000017L; // STATUS_NO_MEMORY
    }

    // CRITICAL FIX: DO NOT zero the memory!
    // The heap allocator already manages this memory, and zeroing it will corrupt the heap metadata.
    // The game's own allocator (sub_8215CB08) will zero memory if needed.
    // Zeroing here was causing heap corruption because we were zeroing memory that contains
    // internal data structures (page table, etc.)
    //
    // if (AllocationType & MEM_COMMIT) {
    //     memset(host_ptr, 0, requested_size);  // THIS WAS CORRUPTING THE HEAP!
    // }

    // Convert to guest address
    const uint32_t guest_addr = g_memory.MapVirtual(host_ptr);

    static int call_count = 0;
    if (++call_count <= 10) {
        fprintf(stderr, "[NtAllocateVirtualMemory] Call #%d: allocated %u bytes at guest=0x%08X (host=%p)\n",
                call_count, requested_size, guest_addr, host_ptr);
        fflush(stderr);
    }

    // Return the allocated address
    *BaseAddress = guest_addr;
    *RegionSize = requested_size;

    // DEBUG: Verify byte-swapping is working correctly
    if (call_count <= 10) {
        uint32_t readback = static_cast<uint32_t>(*BaseAddress);
        fprintf(stderr, "[NtAllocateVirtualMemory] VERIFY: wrote=0x%08X readback=0x%08X (should match!)\n",
                guest_addr, readback);
        if (readback != guest_addr) {
            fprintf(stderr, "[NtAllocateVirtualMemory] ERROR: Byte-swapping mismatch!\n");
        }
        fflush(stderr);
    }

    return 0; // STATUS_SUCCESS
}

// Re-add the missing definition (you still have the forward-decl at the top).
uint32_t KeWaitForSingleObject(XDISPATCHER_HEADER* Object,
                               uint32_t /*WaitReason*/,
                               uint32_t /*WaitMode*/,
                               bool /*Alertable*/,
                               be<int64_t>* Timeout)
{
    if (!Object) return STATUS_INVALID_PARAMETER;

    // PERFORMANCE: Wait debug logging (disabled by default - causes FPS drop)
    static const bool s_debug_wait = [](){
        if (const char* v = std::getenv("MW05_DEBUG_WAIT"))
            return !(v[0]=='0' && v[1]=='\0');
        return false; // DISABLED by default for performance
    }();

    if (s_debug_wait) {
        KernelTraceHostOp("HOST.Wait.enter.KeWaitForSingleObject");
    }

    if (const char* tlw = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
        if (!(tlw[0]=='0' && tlw[1]=='\0')) {
            KernelTraceHostOpF("HOST.Wait.last.record ea=%08X type=%u", g_lastWaitEventEA.load(std::memory_order_relaxed), (unsigned)g_lastWaitEventType.load(std::memory_order_relaxed));
        }
    }

    // Heuristic: register display interrupt event on first wait to ensure vblank pump can signal it.
    if (g_vdInterruptEventEA.load(std::memory_order_acquire) == 0) {
        if (auto ea = g_memory.MapVirtual(Object)) {
            if (GuestOffsetInRange(ea, sizeof(XDISPATCHER_HEADER))) {
                Mw05RegisterVdInterruptEvent(ea, Object->Type == 0);
            }
        }
    }
    // Optional: record last wait EA/type for host-side nudging
    if (uint32_t ea = g_memory.MapVirtual(Object)) {
        g_lastWaitEventEA.store(ea, std::memory_order_release);
        g_lastWaitEventType.store(Object->Type, std::memory_order_release);
    }
    if (const char* tlw2 = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
        if (!(tlw2[0]=='0' && tlw2[1]=='\0')) {
            KernelTraceHostOpF("HOST.Wait.last.record ea=%08X type=%u", g_lastWaitEventEA.load(std::memory_order_relaxed), (unsigned)g_lastWaitEventType.load(std::memory_order_relaxed));
        }
    }


    // Optional: force-ack the scheduler/event fence to break re-arm stalls
    if (Mw05ForceAckWaitEnabled()) {
        if (uint32_t ea = g_memory.MapVirtual(Object)) {
            Mw05ForceAckFromEventEA(ea);
        }
    }


    uint32_t timeout_ms = GuestTimeoutToMilliseconds(Timeout);

    const bool fastBoot  = Mw05FastBootEnabled();
    const bool listShims = Mw05ListShimsEnabled();

    static const auto t0 = std::chrono::steady_clock::now();
    const auto elapsed   = std::chrono::steady_clock::now() - t0;

    // FAST_BOOT: bypass early in boot
    // FAST_BOOT: bypass early in boot
    if (fastBoot && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.FastWait.KeWaitForSingleObject");
        Object->SignalState = 1;      // let caller observe a state change
        NudgeEventWaiters();          // wake pollers using generation waits
        return STATUS_SUCCESS;        // consistent with your Event::Wait()
    }

    // Optionally cap very long waits in fast-boot after the initial window
    if (fastBoot && timeout_ms > 5000) {
        timeout_ms = 1;
    }

    // LIST_SHIMS: trace only; DO NOT bypass the wait
    if (listShims && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.MW05_LIST_SHIMS.KeWaitForSingleObject");
        // fall through to real wait logic
    }

    switch (Object->Type) {
        case 0: // NotificationEvent
        {
            return QueryKernelObject<Event>(*Object)->Wait(timeout_ms);
        }
        case 1: // SynchronizationEvent (auto-reset)
        {
            uint32_t st = QueryKernelObject<Event>(*Object)->Wait(timeout_ms);
            if (st == STATUS_SUCCESS) {
                // Reflect auto-reset consumption in guest header
                Object->SignalState = 0;
            }
            return st;
        }

        case 5: // Semaphore
            return QueryKernelObject<Semaphore>(*Object)->Wait(timeout_ms);

        default:
            // Unknown dispatcher type; avoid assert вЂ” treat as timeout/unsupported.
            return STATUS_TIMEOUT;
    }
}

uint32_t ObDereferenceObject(uint32_t Object)
{
    (void)Object;
    return STATUS_SUCCESS;
}

void KeSetBasePriorityThread(GuestThreadHandle* hThread, int priority)
{
#ifdef _WIN32
    if (priority == 16)
    {
        priority = 15;
    }
    else if (priority == -16)
    {
        priority = -15;
    }

    SetThreadPriority(hThread == GetKernelObject(CURRENT_THREAD_HANDLE) ? GetCurrentThread() : hThread->thread.native_handle(), priority);
#endif
}

uint32_t ObReferenceObjectByHandle(uint32_t handle, uint32_t objectType, be<uint32_t>* object)
{
    *object = handle;
    return 0;
}

void KeQueryBasePriorityThread()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t NtSuspendThread(GuestThreadHandle* hThread, uint32_t* suspendCount)
{
    assert(hThread != GetKernelObject(CURRENT_THREAD_HANDLE) && hThread->GetThreadId() == GuestThread::GetCurrentThreadId());

    hThread->suspended = true;
    hThread->suspended.wait(true);

    return S_OK;
}

uint32_t KeSetAffinityThread(uint32_t Thread, uint32_t Affinity, be<uint32_t>* lpPreviousAffinity)
{
    if (lpPreviousAffinity)
        *lpPreviousAffinity = 2;

    return 0;
}

void RtlLeaveCriticalSection(XRTL_CRITICAL_SECTION* cs)
{
    // Be tolerant of null/invalid pointers during early boot paths to avoid AVs.
    if (!cs)
        return;
    auto* p = reinterpret_cast<uint8_t*>(cs);
    if (p < g_memory.base || p >= (g_memory.base + PPC_MEMORY_SIZE))
        return;

    // CRITICAL FIX (2025-10-31): Reject sentinel value 0xFFFFFFFF
    // The game uses guest address 0xFFFFFFFF as a sentinel for uninitialized/invalid critical sections
    uint32_t guest_addr = static_cast<uint32_t>(p - g_memory.base);
    if (guest_addr == 0xFFFFFFFF) {
        // Silently ignore - this is a sentinel value, not a real critical section
        return;
    }

    // If recursion was never established, do not underflow; leave as-is.
    if (cs->RecursionCount <= 0)
    {
        cs->RecursionCount = 0;
        return;
    }

    cs->RecursionCount--;
    cs->LockCount--;
    if (cs->RecursionCount != 0)
        return;

    // Release ownership only if currently owned.
    if (cs->OwningThread != 0)
    {
        cs->OwningThread = 0;
        cs->LockCount = -1;
        // Use a light yield instead of atomic notify to avoid alignment/atomic issues
        std::this_thread::yield();
    }
}

void RtlEnterCriticalSection(XRTL_CRITICAL_SECTION* cs)
{
    // CRITICAL FIX: cs is a GUEST pointer, not a HOST pointer!
    // We need to translate it to a HOST pointer before dereferencing it.

    // Tolerate null/invalid critical sections during early boot
    if (!cs)
        return;

    // Check if pointer is within guest memory range
    auto* p = reinterpret_cast<uint8_t*>(cs);
    if (p < g_memory.base || p >= (g_memory.base + PPC_MEMORY_SIZE))
        return;

    // CRITICAL FIX (2025-10-31): Reject sentinel value 0xFFFFFFFF
    // The game uses guest address 0xFFFFFFFF as a sentinel for uninitialized/invalid critical sections
    // This corresponds to host pointer (base + 0xFFFFFFFF), which is the last byte of guest memory
    // Attempting to use this as a critical section causes repeated lazy initialization spam
    uint32_t guest_addr = static_cast<uint32_t>(p - g_memory.base);
    if (guest_addr == 0xFFFFFFFF) {
        // Silently ignore - this is a sentinel value, not a real critical section
        return;
    }

    // cs is already a HOST pointer (translated by the import table patching)
    // No need to translate again - just use it directly

    // CRITICAL FIX: Check if the critical section is initialized
    // An uninitialized critical section will have LockCount != -1
    // If not initialized, initialize it lazily to avoid deadlocks
    if (cs->LockCount != -1)
    {
        // Lazily initialize the critical section
        // Use atomic compare-exchange to ensure only one thread initializes it
        int32_t expected = cs->LockCount;
        if (expected != -1)
        {
            // Try to atomically set LockCount to -1 (initialized state)
            if (std::atomic_compare_exchange_strong(
                    reinterpret_cast<std::atomic<int32_t>*>(&cs->LockCount),
                    &expected,
                    -1))
            {
                // Successfully initialized the critical section
                cs->RecursionCount = 0;
                cs->OwningThread = 0;
                cs->Header.Absolute = 0;

                fprintf(stderr, "[RtlEnterCS] Lazy-initialized critical section at %p (guest addr=0x%08X)\n",
                        (void*)cs, (uint32_t)((uint8_t*)cs - g_memory.base));
                fflush(stderr);
            }
        }
    }

    uint32_t thisThread = 0;
    if (auto* ctx = GetPPCContext())
        thisThread = ctx->r13.u32;
    if (thisThread == 0)
        thisThread = 1; // Fallback owner id if TLS not yet established

    // CRITICAL FIX: Use atomic compare-exchange to acquire the lock
    // This prevents race conditions where multiple threads try to acquire the lock simultaneously
    uint32_t expected = 0;
    uint32_t spin_count = 0;
    while (true)
    {
        // Try to atomically acquire the lock if it's free (owner == 0)
        expected = 0;
        if (std::atomic_compare_exchange_weak(
                reinterpret_cast<std::atomic<uint32_t>*>(&cs->OwningThread),
                &expected,
                thisThread))
        {
            // Successfully acquired the lock
            cs->RecursionCount = 1;
            cs->LockCount = (cs->LockCount < -1) ? -1 : cs->LockCount; // clamp
            cs->LockCount++;
            return;
        }

        // Check if we already own the lock (recursive acquisition)
        if (expected == thisThread)
        {
            cs->RecursionCount++;
            cs->LockCount++;
            return;
        }

        // Lock is held by another thread, yield and retry
        spin_count++;
        if (spin_count == 1000000) {
            // After 1 million spins, print a warning
            uint32_t guest_addr = static_cast<uint32_t>((uint8_t*)cs - g_memory.base);
            fprintf(stderr, "[RtlEnterCS] WARNING: Spinning for 1M iterations on CS at 0x%08X (owner=0x%08X, this=0x%08X)\n",
                    guest_addr, expected, thisThread);
            fflush(stderr);
        }
        else if (spin_count > 10000000) {
            // After 10 million spins, this is likely a deadlock - break out
            uint32_t guest_addr = static_cast<uint32_t>((uint8_t*)cs - g_memory.base);
            fprintf(stderr, "[RtlEnterCS] ERROR: Deadlock detected on CS at 0x%08X (owner=0x%08X, this=0x%08X) - BREAKING LOCK!\n",
                    guest_addr, expected, thisThread);
            fflush(stderr);

            // Force-acquire the lock to break the deadlock
            cs->OwningThread = thisThread;
            cs->RecursionCount = 1;
            cs->LockCount = (cs->LockCount < -1) ? -1 : cs->LockCount;
            cs->LockCount++;
            return;
        }

        std::this_thread::yield();
    }
}

// NTSTATUS RtlImageXexHeaderField(void* HeaderBase, uint32_t Field, void** OutPtr)
// Minimal: if Field looks like EXECUTION_INFO, return pointer to our execution id.
uint32_t RtlImageXexHeaderField(uint32_t /*HeaderBaseEA*/, uint32_t Field, be<uint32_t>* OutPtrEA)
{
    KernelTraceHostOpF("HOST.RtlImageXexHeaderField field=%08X", Field);

    // Commonly used IDs for XEX_HEADER_EXECUTION_INFO observed in docs/emulators.
    constexpr uint32_t kExecInfo1 = 0x000002FFu;
    constexpr uint32_t kExecInfo2 = 0x000003FFu;

    if (Field == kExecInfo1 || Field == kExecInfo2)
    {
        be<uint32_t> xidEA = 0u;
        // Ensure we have a published execution id and return its guest EA.
        (void)XamGetExecutionId(&xidEA);
        if (OutPtrEA) *OutPtrEA = xidEA;
        KernelTraceHostOpF("HOST.RtlImageXexHeaderField EXECUTION_INFO -> %08X", (uint32_t)xidEA);
        return 0; // STATUS_SUCCESS
    }

    if (OutPtrEA) *OutPtrEA = 0u;
    return 0xC0000225; // STATUS_NOT_FOUND
}

void HalReturnToFirmware()
{
    // Title requested return to firmware/dashboard. By default, ignore this to allow
    // titles that call it during bring-up to continue. Set MW05_ALLOW_FIRMWARE_RETURN=1
    // to honor the request and exit.
    uint32_t reason = 0;
    if (auto* ctx = GetPPCContext())
        reason = ctx->r3.u32;

    const char* allow = std::getenv("MW05_ALLOW_FIRMWARE_RETURN");
    const bool honor = (allow && allow[0] && !(allow[0]=='0' && allow[1]=='\0'));

    if (honor)
    {
        KernelTraceDumpRecent(16);
#ifdef _WIN32
        char msg[256];
        std::snprintf(msg, sizeof(msg), "Game requested return to firmware (code=%u). Exiting.", reason);
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, GameWindow::GetTitle(), msg, GameWindow::s_pWindow);
#endif
        std::_Exit(0);
    }
    else
    {
        LOGFN("[kernel] HalReturnToFirmware ignored (code={})", reason);
    }
}

void RtlFillMemoryUlong(void* Destination, uint32_t Length, uint32_t Pattern)
{
    // RtlFillMemoryUlong fills a memory block with a ULONG pattern
    // Destination must be ULONG-aligned, Length must be a multiple of sizeof(ULONG)

    if (!Destination || Length == 0)
        return;

    // Validate that the destination is in guest memory
    auto* p = reinterpret_cast<uint8_t*>(Destination);
    if (p < g_memory.base || p >= (g_memory.base + PPC_MEMORY_SIZE))
    {
        fprintf(stderr, "[RtlFillMemoryUlong] ERROR: Invalid destination pointer %p (outside guest memory)\n", Destination);
        fflush(stderr);
        return;
    }

    // Fill the memory with the pattern (4-byte ULONG values)
    // Xbox 360 is big-endian, so we need to byte-swap the pattern
    uint32_t pattern_be;
#if defined(_MSC_VER)
    pattern_be = _byteswap_ulong(Pattern);
#else
    pattern_be = __builtin_bswap32(Pattern);
#endif

    uint32_t* dest = reinterpret_cast<uint32_t*>(Destination);
    uint32_t count = Length / sizeof(uint32_t);

    for (uint32_t i = 0; i < count; i++)
        dest[i] = pattern_be;
}

void KeBugCheckEx(uint32_t bugcheck_code, uint32_t param1, uint32_t param2, uint32_t param3, uint32_t param4)
{
    // CRITICAL FIX (2025-10-30): Skip bugcheck 0xF4 (CRITICAL_OBJECT_TERMINATION)
    // This bugcheck is triggered by worker threads when they try to allocate memory.
    // The allocation function sub_82632570 checks if heap[379] matches KeGetCurrentProcessType().
    // Since we can't easily patch the heap structure before worker threads start,
    // we skip this specific bugcheck to allow worker threads to run.
    if (bugcheck_code == 0xF4) {
        static bool s_logged = false;
        if (!s_logged) {
            fprintf(stderr, "[BUGCHECK] SKIPPING bugcheck 0xF4 (CRITICAL_OBJECT_TERMINATION)\n");
            fprintf(stderr, "[BUGCHECK]   This is a known issue with worker thread heap allocation\n");
            fprintf(stderr, "[BUGCHECK]   Param1: 0x%08X\n", param1);
            fprintf(stderr, "[BUGCHECK]   Param2: 0x%08X (allocation function address)\n", param2);
            fprintf(stderr, "[BUGCHECK]   Param3: 0x%08X\n", param3);
            fprintf(stderr, "[BUGCHECK]   Param4: 0x%08X\n", param4);
            fflush(stderr);
            s_logged = true;
        }
        return;  // Skip the bugcheck - let the thread continue
    }

    fprintf(stderr, "[BUGCHECK] KeBugCheckEx called!\n");
    fprintf(stderr, "[BUGCHECK]   Code: 0x%08X\n", bugcheck_code);
    fprintf(stderr, "[BUGCHECK]   Param1: 0x%08X\n", param1);
    fprintf(stderr, "[BUGCHECK]   Param2: 0x%08X\n", param2);
    fprintf(stderr, "[BUGCHECK]   Param3: 0x%08X\n", param3);
    fprintf(stderr, "[BUGCHECK]   Param4: 0x%08X\n", param4);
    fflush(stderr);

    __builtin_debugtrap();
}

uint32_t KeGetCurrentProcessType()
{
    return 1;
}

// Some titles call KeBugCheck during early init on unsupported environments.
// Treat it as non-fatal by default to allow bring-up to continue.
void KeBugCheck()
{
    const char* honor = std::getenv("MW05_ALLOW_BUGCHECK");
    if (honor && honor[0] && !(honor[0]=='0' && honor[1]=='\0'))
    {
        KernelTraceDumpRecent(16);
#ifdef _WIN32
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), "KeBugCheck requested. Exiting.", GameWindow::s_pWindow);
#endif
        std::_Exit(1);
    }
    LOG_UTILITY("KeBugCheck ignored (continue)");
}

void RtlCompareMemoryUlong()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t RtlInitializeCriticalSection(XRTL_CRITICAL_SECTION* cs)
{
    static int call_count = 0;
    call_count++;

    fprintf(stderr, "[RtlInitCS] Call #%d: cs=%p\n", call_count, (void*)cs);
    fflush(stderr);

    if (!cs) {
        fprintf(stderr, "[RtlInitCS] Call #%d: NULL pointer - returning STATUS_INVALID_PARAMETER\n", call_count);
        fflush(stderr);
        return 0xC000000DL; // STATUS_INVALID_PARAMETER
    }

    // Check if pointer is within guest memory range
    auto* p = reinterpret_cast<uint8_t*>(cs);
    if (p < g_memory.base || p >= (g_memory.base + PPC_MEMORY_SIZE)) {
        fprintf(stderr, "[RtlInitCS] Call #%d: Invalid pointer (outside guest memory) - base=%p size=0x%llX\n",
                call_count, (void*)g_memory.base, (unsigned long long)PPC_MEMORY_SIZE);
        fflush(stderr);
        return 0xC000000DL; // STATUS_INVALID_PARAMETER
    }

    // Calculate guest address for logging
    uint32_t guest_addr = static_cast<uint32_t>(p - g_memory.base);
    fprintf(stderr, "[RtlInitCS] Call #%d: guest_addr=0x%08X host=%p\n", call_count, guest_addr, (void*)cs);
    fflush(stderr);

    cs->Header.Absolute = 0;
    cs->LockCount = -1;
    cs->RecursionCount = 0;
    cs->OwningThread = 0;

    fprintf(stderr, "[RtlInitCS] Call #%d: SUCCESS\n", call_count);
    fflush(stderr);

    return 0; // STATUS_SUCCESS
}

void RtlRaiseException_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KfReleaseSpinLock(uint32_t* spinLock)
{
    // Use volatile write instead of atomic_ref to avoid alignment issues
    volatile uint32_t* vol_ptr = spinLock;
    *vol_ptr = 0;
}

void KfAcquireSpinLock(uint32_t* spinLock)
{
    // Use volatile operations instead of atomic_ref to avoid alignment issues
    volatile uint32_t* vol_ptr = spinLock;
    while (true)
    {
        uint32_t current = *vol_ptr;
        if (current == 0)
        {
            *vol_ptr = g_ppcContext->r13.u32;
            if (*vol_ptr == g_ppcContext->r13.u32)
            {
                break;
            }
        }
        std::this_thread::yield();
    }
}

uint64_t KeQueryPerformanceFrequency()
{
    return 49875000;
}

void MmFreePhysicalMemory(uint32_t type, uint32_t guestAddress)
{
    // CRITICAL FIX: Reject invalid addresses that cause heap corruption
    // 0x00000000 = NULL pointer
    // 0x00000001 = sentinel value (used by game for invalid/uninitialized pointers)
    // 0xFFFFFFFF = -1 (sentinel value used by game for uninitialized pointers)
    // All should be ignored, not freed
    if (guestAddress == 0 || guestAddress == 1 || guestAddress == 0xFFFFFFFF)
        return;

    // NOTE: g_userHeap.Free() automatically detects physical vs user heap addresses
    // Physical heap addresses (0xA0000000-0x100000000) are handled as no-op (bump allocator)
    // User heap addresses (0x00100000-0x7FEA0000) are freed normally via BaseHeap
    g_userHeap.Free(g_memory.Translate(guestAddress));
}

bool VdPersistDisplay(uint32_t /*a1*/, uint32_t* a2)
{
    KernelTraceHostOp("HOST.VdPersistDisplay");
    // Unblock callers waiting for persist to complete.
    if (a2) *a2 = 1;
    return true;
}

// Minimal emulation of the system command buffer used by the guest.
// We expose a guest-visible buffer and return its address via both return value
// and out-parameters to satisfy MW'05 call sites.
// System command buffer - allocate at fixed address to avoid heap corruption
static void* g_SysCmdBufHost = nullptr;
static uint32_t g_SysCmdBufGuest = 0;
static constexpr uint32_t kSysCmdBufSize = 64 * 1024;
static constexpr uint32_t kSysCmdBufFixedAddr = 0x00F00000;  // 15 MB (before heap at 16 MB)

static void EnsureSystemCommandBuffer()
{
    if (g_SysCmdBufGuest == 0)
    {
        g_SysCmdBufGuest = kSysCmdBufFixedAddr;
        g_SysCmdBufHost = g_memory.Translate(g_SysCmdBufGuest);
        g_VdSystemCommandBuffer.store(g_SysCmdBufGuest);

        if (g_SysCmdBufHost) {
            memset(g_SysCmdBufHost, 0, kSysCmdBufSize);
        }
    }
}

uint32_t VdGetSystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue)
{
    EnsureSystemCommandBuffer();

    uint32_t bufAddr = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
    uint32_t bufValue = 0;

    if (outCmdBufPtr) *outCmdBufPtr = bufAddr;
    if (outValue)     *outValue     = bufValue;

    return bufAddr;
}

uint32_t VdQuerySystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue)
{
    return VdGetSystemCommandBuffer(outCmdBufPtr, outValue);
}

void KeReleaseSpinLockFromRaisedIrql(uint32_t* spinLock)
{
    // Use volatile write instead of atomic_ref to avoid alignment issues
    volatile uint32_t* vol_ptr = spinLock;
    *vol_ptr = 0;
}

void KeAcquireSpinLockAtRaisedIrql(uint32_t* spinLock)
{
    // Use volatile operations instead of atomic_ref to avoid alignment issues
    volatile uint32_t* vol_ptr = spinLock;
    while (true)
    {
        uint32_t current = *vol_ptr;
        if (current == 0)
        {
            *vol_ptr = g_ppcContext->r13.u32;
            if (*vol_ptr == g_ppcContext->r13.u32)
            {
                break;
            }
        }
        std::this_thread::yield();
    }
}

uint32_t KiApcNormalRoutineNop()
{
    return 0;
}

void VdEnableRingBufferRPtrWriteBack(uint32_t base)
{
    KernelTraceHostOpF("HOST.VdEnableRingBufferRPtrWriteBack base=%08X", base);
    // Record write-back pointer; zero it to indicate idle.
    g_RbWriteBackPtr = base;
    auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base));
    if (p) *p = 0;
    g_vdInterruptPending.store(true, std::memory_order_release);
    // If the system command buffer GPU-identifier address hasn't been set yet,
    // default it to the write-back area at base+8 so MW05_HOST_ISR_TICK_SYSID has a target.
    if (g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_acquire) == 0) {
        VdSetSystemCommandBufferGpuIdentifierAddress(base + 8);
        KernelTraceHostOpF("HOST.VdSetSystemCommandBufferGpuIdentifierAddress.addr.auto base=%08X ea=%08X", base, base + 8);
    }

    Mw05DispatchVdInterruptIfPending();
    // Ensure vblank pump is running so display waiters can progress.
    Mw05StartVblankPumpOnce();
}

void VdInitializeRingBuffer(uint32_t base, uint32_t len)
{
    fprintf(stderr, "[VD-RINGBUF] VdInitializeRingBuffer: base=%08X len_log2=%u size=%u bytes\n",
            base, len, (len < 32) ? (1u << len) : 0);
    fflush(stderr);

    KernelTraceHostOpF("HOST.VdInitializeRingBuffer base=%08X len_log2=%u", base, len);
    if (auto* ctx = GetPPCContext()) {
        KernelTraceHostOpF("HOST.VdInitializeRingBuffer.caller lr=%08X", (uint32_t)ctx->lr);
    }
    // MW05 (and Xenia logs) pass the ring buffer size as log2(len).
    // Convert to bytes to ensure we zero the correct range so readers see a clean buffer.
    g_RbBase = base;
    g_RbLen = len;
    const uint32_t size_bytes = (len < 32) ? (1u << (len & 31)) : 0u;

    // REMOVED VERBOSE LOGGING - can cause thread concurrency issues

    if (base && size_bytes)
    {
        uint8_t* p = reinterpret_cast<uint8_t*>(g_memory.Translate(base));
        if (p) {
            // Zero-initialize the ring buffer
            // NOTE: This is safe because the ring buffer was allocated from the user heap,
            // and BaseHeap returns pointers to user-allocatable memory (NOT metadata).
            memset(p, 0, size_bytes);
            fprintf(stderr, "[VD-RINGBUF] Ring buffer zeroed at base=%08X size=%u\n", base, size_bytes);
            fflush(stderr);
        }
    }
    // Seed write-back pointer so guest sees progress
    uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);
    if (wb)
    {
        if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb)))
            *rptr = 0x20; // small non-zero value
    }

    // Initialize PM4 parser with ring buffer info
    fprintf(stderr, "[VD-RINGBUF] Calling PM4_SetRingBuffer with base=%08X len_log2=%u\n", base, len);
    fflush(stderr);
    PM4_SetRingBuffer(base, len);

    g_vdInterruptPending.store(true, std::memory_order_release);
    Mw05DispatchVdInterruptIfPending();
}


// Apply optional VD control-block pokes once, even if no default host ISR is installed.
static void Mw05ApplyVdPokesOnce() {
    static std::atomic<bool> s_done{false};
    bool expected = false;
    if (!s_done.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    auto read_be64 = [](uint32_t ea) -> uint64_t {
        if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0ull;
        if (const void* p = g_memory.Translate(ea)) {
            uint64_t v = *reinterpret_cast<const uint64_t*>(p);
        #if defined(_MSC_VER)
            return _byteswap_uint64(v);
        #else
            return __builtin_bswap64(v);
        #endif
        }
        return 0ull;
    };
    auto write_be64 = [](uint32_t ea, uint64_t v64) -> bool {
        if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return false;
        if (auto* p = static_cast<uint8_t*>(g_memory.Translate(ea))) {
        #if defined(_MSC_VER)
            v64 = _byteswap_uint64(v64);
        #else
            v64 = __builtin_bswap64(v64);
        #endif
            *reinterpret_cast<uint64_t*>(p) = v64;
            return true;
        }
        return false;
    };

    auto apply_env_poke = [&](const char* env_name, uint32_t ea, const char* reg_name) {
        const char* s = std::getenv(env_name);
        if (!s || !s[0]) return;
        const bool or_mode = (s[0] == '+');
        const char* val_str = or_mode ? s + 1 : s;
        unsigned long v = std::strtoul(val_str, nullptr, 0);
        const uint64_t ov = read_be64(ea);
        const uint64_t nv = or_mode ? (ov | uint64_t(v)) : uint64_t(v);
        if (ov != nv && write_be64(ea, nv)) {
            KernelTraceHostOpF("HOST.VD.poke%s %s=%016llX (was %016llX)",
                               or_mode ? "|" : "",
                               reg_name,
                               (unsigned long long)nv,
                               (unsigned long long)ov);
        }
    };

    apply_env_poke("MW05_VD_POKE_E58", 0x00060E58u, "e58");
    apply_env_poke("MW05_VD_POKE_E68", 0x00060E68u, "e68");
    apply_env_poke("MW05_VD_POKE_E70", 0x00060E70u, "e70");
}

// ---- forced VD bring-up (enabled by default, disable with MW05_FORCE_VD_INIT=0) ----
static inline bool Mw05ForceVdInitEnabled() {
    if (const char* v = std::getenv("MW05_FORCE_VD_INIT"))
        return !(v[0]=='0' && v[1]=='\0');
    return true;  // CHANGED: Enable by default to ensure graphics initialization
}

static std::atomic<bool> g_forceVdInitDone{false};

// Log once when the guest registers its graphics interrupt callback (ISR)
static std::atomic<bool> g_loggedIsr{false};
void Mw05LogIsrIfRegisteredOnce() {
    if (g_loggedIsr.load(std::memory_order_acquire)) return;
    const uint32_t cb  = VdGetGraphicsInterruptCallback();
    if (!cb) return;
    const uint32_t ctx = VdGetGraphicsInterruptContext();
    bool expected = false;
    if (!g_loggedIsr.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    KernelTraceHostOpF("HOST.VdISR.registered cb=%08X ctx=%08X", cb, ctx);
}


// Force ring + writeback + engines, even earlier than the small auto-init.
extern "C"
{
    uint32_t Mw05Trace_LastSchedR3();
    void Mw05TryBuilderKickNoForward(uint32_t schedEA);
}

void Mw05ForceVdInitOnce() {
    if (!Mw05ForceVdInitEnabled()) {
        static std::atomic<bool> s_logged_disabled{false};
        if (!s_logged_disabled.exchange(true, std::memory_order_relaxed)) {
            fprintf(stderr, "[VD-INIT] Mw05ForceVdInitOnce DISABLED by MW05_FORCE_VD_INIT=0\n");
            fflush(stderr);
        }
        return;
    }

    bool expected = false;
    if (!g_forceVdInitDone.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        static std::atomic<bool> s_logged_already{false};
        if (!s_logged_already.exchange(true, std::memory_order_relaxed)) {
            fprintf(stderr, "[VD-INIT] Mw05ForceVdInitOnce already called, skipping\n");
            fflush(stderr);
        }
        return;
    }

    fprintf(stderr, "[VD-INIT] Mw05ForceVdInitOnce STARTING initialization\n");
    fflush(stderr);

    Mw05MaybeForceRegisterVdEventFromEnv();

    if (g_RbLen.load(std::memory_order_relaxed) == 0 ||
        g_RbWriteBackPtr.load(std::memory_order_relaxed) == 0)
    {
        fprintf(stderr, "[VD-INIT] Ring buffer not initialized, allocating now\n");
        fflush(stderr);
        const uint32_t len_log2 = 16;
        void* ring_host = g_userHeap.Alloc(1u << len_log2);
        if (ring_host)
        {
            const uint32_t ring_guest = g_memory.MapVirtual(ring_host);
            fprintf(stderr, "[VD-INIT] Allocated ring buffer: guest=%08X len_log2=%u\n", ring_guest, len_log2);
            fflush(stderr);
            void* wb_host = g_userHeap.Alloc(64);
            if (wb_host)
            {
                const uint32_t wb_guest = g_memory.MapVirtual(wb_host);
                fprintf(stderr, "[VD-INIT] Allocated writeback buffer: guest=%08X\n", wb_guest);
                fflush(stderr);
                VdInitializeRingBuffer(ring_guest, len_log2);
                VdEnableRingBufferRPtrWriteBack(wb_guest);
                VdSetSystemCommandBufferGpuIdentifierAddress(wb_guest + 8);
            }
        }
    } else {
        fprintf(stderr, "[VD-INIT] Ring buffer already initialized: len=%u wb=%08X\n",
                g_RbLen.load(std::memory_order_relaxed),
                g_RbWriteBackPtr.load(std::memory_order_relaxed));
        fflush(stderr);
    }

    fprintf(stderr, "[VD-INIT] Calling Mw05ApplyVdPokesOnce\n");
    fflush(stderr);
    Mw05ApplyVdPokesOnce();

    // CRITICAL FIX: Call the game's graphics initialization function sub_825A85E0
    // This function calls VdInitializeEngines with the proper callback (sub_825A85C8)
    // and sets up the graphics interrupt callback (sub_825979A8)
    // This is what Xenia does - Thread #7 calls sub_825A85E0 to initialize graphics
    fprintf(stderr, "[VD-INIT] Calling game's graphics init function sub_825A85E0\n");
    fflush(stderr);
    {
        // Set up PPC context for the call
        PPCContext ctx{};
        if (auto* cur = GetPPCContext()) ctx = *cur;  // Preserve TOC/r13 etc.

        // r3 = graphics context address (0x40007180 is the context we allocated in main.cpp)
        ctx.r3.u32 = 0x40007180;

        // Call the game's graphics initialization function
        uint8_t* base = g_memory.base;
        __imp__sub_825A85E0(ctx, base);

        fprintf(stderr, "[VD-INIT] sub_825A85E0 returned: r3=%08X\n", ctx.r3.u32);
        fflush(stderr);
    }

    fprintf(stderr, "[VD-INIT] Calling VdGetSystemCommandBuffer\n");
    fflush(stderr);
    VdGetSystemCommandBuffer(nullptr, nullptr);
    fprintf(stderr, "[VD-INIT] Calling VdCallGraphicsNotificationRoutines\n");
    fflush(stderr);
    VdCallGraphicsNotificationRoutines(0u);
    fprintf(stderr, "[VD-INIT] Calling Mw05StartVblankPumpOnce\n");
    fflush(stderr);
    Mw05StartVblankPumpOnce();
    fprintf(stderr, "[VD-INIT] Mw05ForceVdInitOnce COMPLETE\n");
    fflush(stderr);

    // DEBUG: Check the callback queue state
    auto read_be32 = [](uint32_t ea) -> uint32_t {
        if (!ea) return 0u;
        if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(ea))) {
        #if defined(_MSC_VER)
            return _byteswap_ulong(*p);
        #else
            return __builtin_bswap32(*p);
        #endif
        }
        return 0u;
    };

    uint32_t queue_enabled = read_be32(0x8290965C);
    uint32_t queue_start = read_be32(0x82909650);
    uint32_t queue_current = read_be32(0x82909654);
    uint32_t queue_end = read_be32(0x82909664);
    uint32_t callback_ptr = read_be32(0x82909668);
    fprintf(stderr, "[VD-INIT] Callback queue state:\n");
    fprintf(stderr, "[VD-INIT]   enabled=%08X start=%08X current=%08X end=%08X callback=%08X\n",
            queue_enabled, queue_start, queue_current, queue_end, callback_ptr);
    fflush(stderr);
}

// fwd decls for locally-defined VD bridge helpers used below
void VdSetGraphicsInterruptCallback(uint32_t callback, uint32_t context);
void VdRegisterGraphicsNotificationRoutine(uint32_t callback, uint32_t context);


// Optional: force-register a graphics notify/ISR callback from env (for bring-up)
// Forward declaration for MmAllocatePhysicalMemoryEx (defined later in this file)
uint32_t MmAllocatePhysicalMemoryEx(uint32_t flags, uint32_t size, uint32_t protect,
                                     uint32_t minAddress, uint32_t maxAddress, uint32_t alignment);

// Global variable to store the heap-allocated graphics context address
// Following Xenia's approach: allocate context on heap instead of using static address
static uint32_t g_graphics_context_ea = 0;

// Getter function for external access to the graphics context address
uint32_t Mw05GetGraphicsContextAddress() {
    return g_graphics_context_ea;
}

// Allocate and zero-initialize the graphics context structure on the HEAP
// Following Xenia's approach: use MmAllocatePhysicalMemoryEx instead of static address
// Returns the guest address of the allocated context
static uint32_t Mw05EnsureGraphicsContextAllocated() {
    constexpr uint32_t CTX_SIZE = 0x4000;  // 16KB (minimum is 0x3CF0 based on callback access at +0x3CEC)

    // If already allocated, return the existing address
    if (g_graphics_context_ea != 0) {
        fprintf(stderr, "[GFX-CTX] Context already allocated at 0x%08X\n", g_graphics_context_ea);
        return g_graphics_context_ea;
    }

    // Allocate context on the heap (Xenia-style)
    void* ctx_host = g_userHeap.Alloc(CTX_SIZE);
    if (!ctx_host) {
        fprintf(stderr, "[GFX-CTX] ERROR: Failed to allocate %u bytes for graphics context\n", CTX_SIZE);
        return 0;
    }

    // Zero-initialize
    std::memset(ctx_host, 0, CTX_SIZE);

    // Convert to guest address
    const uint32_t ctx_ea = g_memory.MapVirtual(ctx_host);
    g_graphics_context_ea = ctx_ea;

    fprintf(stderr, "[GFX-CTX] SUCCESS: Allocated %u bytes on HEAP at guest=0x%08X host=%p\n",
            CTX_SIZE, ctx_ea, ctx_host);
    KernelTraceHostOpF("HOST.GfxContext.heap_allocated ea=%08X size=%08X", ctx_ea, CTX_SIZE);

    // CRITICAL FIX: Initialize the "keep running" flag at offset +4
    // The render thread (0x825AA970) checks *(gfx_ctx+4) and exits if it's 0
    // This flag must be non-zero to keep the render thread alive
    be<uint32_t>* keep_running_flag = reinterpret_cast<be<uint32_t>*>(
        static_cast<uint8_t*>(ctx_host) + 4);
    *keep_running_flag = be<uint32_t>(1);  // Set to 1 to keep thread running

    fprintf(stderr, "[GFX-CTX] Initialized keep-running flag at offset +4 to 1\n");
    fflush(stderr);

    // CRITICAL: Allocate and initialize the structure at context+0x2894
    // The graphics callback accesses this pointer and expects a valid 32-byte structure
    // At offset +0x10 of this structure, it checks for magic value 0xBADF00D
    // If the magic value matches, it will crash with an error
    constexpr uint32_t STRUCT_OFFSET = 0x2894;
    constexpr uint32_t STRUCT_SIZE = 0x4000;  // 16KB (same as context size)

    // Allocate the structure using the game's allocator
    void* struct_host = g_userHeap.Alloc(STRUCT_SIZE);
    if (struct_host) {
        // Zero-initialize to ensure +0x10 is NOT 0xBADF00D
        std::memset(struct_host, 0, STRUCT_SIZE);

        // Convert to guest address
        const uint32_t struct_guest = g_memory.MapVirtual(struct_host);

        // Store the pointer at context+0x2894
        // CRITICAL: Store in LITTLE-ENDIAN format (host format) because the shim reads it as uint32_t*
        // The shim does NOT byte-swap when reading, so we should NOT byte-swap when storing
        uint32_t* ctx_struct_ptr = reinterpret_cast<uint32_t*>(
            static_cast<uint8_t*>(ctx_host) + STRUCT_OFFSET);
        *ctx_struct_ptr = struct_guest;  // Store as-is (little-endian)

        fprintf(stderr, "[GFX-CTX] Allocated structure at 0x%08X, stored pointer at context+0x%04X (expects ctx+0x2894)\n",
                struct_guest, STRUCT_OFFSET);
        KernelTraceHostOpF("HOST.GfxContext.struct_allocated ea=%08X offset=%04X",
                         struct_guest, STRUCT_OFFSET);
        // CRITICAL: The inner structure ALSO has a pointer at +0x2894 to a SECOND-LEVEL structure
        // The callback does: r11 = Load32(r31 + 0x2894), then r3 = Load32(r11 + 20)
        // We need to allocate this second-level structure as well
        void* struct2_host = g_userHeap.Alloc(STRUCT_SIZE);
        if (struct2_host) {
            std::memset(struct2_host, 0, STRUCT_SIZE);
            const uint32_t struct2_guest = g_memory.MapVirtual(struct2_host);

            // Store the second-level structure pointer at inner+0x2894
            // CRITICAL: The PPC code reads this with PPC_LOAD_U32 which does byte-swapping,
            // so we need to store it in BIG-ENDIAN format (using be<uint32_t>)
            be<uint32_t>* inner_struct_ptr = reinterpret_cast<be<uint32_t>*>(
                static_cast<uint8_t*>(struct_host) + STRUCT_OFFSET);
            *inner_struct_ptr = struct2_guest;  // Store in big-endian format

            fprintf(stderr, "[GFX-CTX] Allocated second-level structure at 0x%08X, stored pointer at inner+0x%04X\n",
                    struct2_guest, STRUCT_OFFSET);
        } else {
            fprintf(stderr, "[GFX-CTX] ERROR: Failed to allocate second-level structure\n");
        }

        // Initialize important members inside the inner structure that ISR uses
        {
            auto* inner_u32 = reinterpret_cast<uint32_t*>(struct_host);
            // CRITICAL FIX: The VBlank ISR callback reads from offset +0x10 and +0x14 of the inner structure
            // According to decompiled sub_825979A8:
            //   v10 = *(_DWORD *)(a7 + 16);  // offset +0x10 (16)
            //   if ( v10 ) { v8(*(_DWORD **)(a2[2597] + 20)); }  // offset +0x14 (20)
            // So we need to ensure BOTH +0x10 and +0x14 are initialized to 0
            inner_u32[0x10 / 4] = 0;  // +0x10 (16) - callback type/flag
            inner_u32[0x14 / 4] = 0;  // +0x14 (20) - callback function pointer
            // Present function pointer (+0x3CEC) initially 0; will be set before first call
            inner_u32[0x3CEC / 4] = 0;
            // Invocation counter (+0x3CF0)
            inner_u32[0x3CF0 / 4] = 0;
            // Decrement counter (+0x3CF8)
            inner_u32[0x3CF8 / 4] = 0;
            // Scratch (+0x3CF4, +0x3CFC)
            inner_u32[0x3CF4 / 4] = 0;
            inner_u32[0x3CFC / 4] = 0;

            fprintf(stderr, "[GFX-CTX] Initialized inner structure: +0x10=%08X +0x14=%08X +0x3CEC=%08X\n",
                    inner_u32[0x10 / 4], inner_u32[0x14 / 4], inner_u32[0x3CEC / 4]);
            fflush(stderr);
        }

    } else {
        fprintf(stderr, "[GFX-CTX] WARNING: Failed to allocate structure for context+0x%04X\n",
                STRUCT_OFFSET);
        KernelTraceHostOpF("HOST.GfxContext.struct_alloc_failed offset=%04X", STRUCT_OFFSET);
    }

    // CRITICAL: Initialize the spinlock at context+0x2898
    // The graphics callback acquires this spinlock via KeAcquireSpinLockAtRaisedIrql
    // If not initialized, it will corrupt memory or crash
    constexpr uint32_t SPINLOCK_OFFSET = 0x2898;
    uint32_t* spinlock_ptr = reinterpret_cast<uint32_t*>(
            static_cast<uint8_t*>(ctx_host) + SPINLOCK_OFFSET);
    *spinlock_ptr = 0;  // Initialize to unlocked state

    fprintf(stderr, "[GFX-CTX] Initialized spinlock at context+0x%04X\n", SPINLOCK_OFFSET);
    KernelTraceHostOpF("HOST.GfxContext.spinlock_initialized offset=%04X", SPINLOCK_OFFSET);

    // CRITICAL: Initialize other context members accessed by the callback
    // The callback accesses these members after acquiring the spinlock
    // If not initialized, the callback will behave unpredictably

    // Counter at +0x3CF0: Incremented by callback each invocation
    uint32_t* ctx_3CF0 = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(ctx_host) + 0x3CF0);
    *ctx_3CF0 = 0;

    // Counter at +0x3CF8: Decremented by callback, triggers logic when zero
    uint32_t* ctx_3CF8 = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(ctx_host) + 0x3CF8);
    *ctx_3CF8 = 0;  // Start at 0 (won't decrement, won't trigger special logic)

    // Value at +0x3CEC: If non-zero, triggers additional processing
    uint32_t* ctx_3CEC = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(ctx_host) + 0x3CEC);
    *ctx_3CEC = 0;  // No pending work

    // Value at +0x3CF4: Written by callback
    uint32_t* ctx_3CF4 = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(ctx_host) + 0x3CF4);
    *ctx_3CF4 = 0;

    // Value at +0x3CFC: Read by callback when +0x3CEC is non-zero
    uint32_t* ctx_3CFC = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(ctx_host) + 0x3CFC);
    *ctx_3CFC = 0;

    fprintf(stderr, "[GFX-CTX] Initialized context members: +0x3CEC, +0x3CF0, +0x3CF4, +0x3CF8, +0x3CFC\n");
    KernelTraceHostOpF("HOST.GfxContext.members_initialized count=5");

    // CRITICAL FIX: Initialize VdGlobalDevice to point to a pointer to the graphics context
    // The game's allocator wrapper (sub_825960B8) reads a fallback allocator pointer from
    // VdGlobalDevice at offset 0x3D0C when the primary allocator (a1[4]) is NULL.
    // The structure is: VdGlobalDevice → pointer → structure with fallback at +0x3D0C
    // We need to create an extra level of indirection.

    // Allocate a pointer to the graphics context
    void* vd_ptr_host = g_userHeap.Alloc(sizeof(uint32_t));
    if (vd_ptr_host) {
        const uint32_t vd_ptr_ea = g_memory.MapVirtual(vd_ptr_host);

        // Store the graphics context address in the pointer (in big-endian format)
        be<uint32_t>* vd_ptr = reinterpret_cast<be<uint32_t>*>(vd_ptr_host);
        *vd_ptr = be<uint32_t>(ctx_ea);

        // Set VdGlobalDevice to point to the pointer
        VdGlobalDevice = be<uint32_t>(vd_ptr_ea);
        VdGlobalXamDevice = be<uint32_t>(vd_ptr_ea);  // Same for XAM device

        fprintf(stderr, "[GFX-CTX] Set VdGlobalDevice and VdGlobalXamDevice to 0x%08X (points to 0x%08X)\n", vd_ptr_ea, ctx_ea);
        fflush(stderr);

        // CRITICAL FIX: Initialize the static pointers at 0x101BE and 0x101BF
        // These are used by sub_825960B8 when KeGetCurrentProcessType() returns 1 or 2
        // 0x101BE = pointer to VdGlobalDevice (for process type != 2)
        // 0x101BF = pointer to VdGlobalXamDevice (for process type == 2)
        be<uint32_t>* ptr_101BE = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(0x101BE));
        be<uint32_t>* ptr_101BF = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(0x101BF));
        if (ptr_101BE && ptr_101BF) {
            *ptr_101BE = be<uint32_t>(vd_ptr_ea);  // Point to VdGlobalDevice
            *ptr_101BF = be<uint32_t>(vd_ptr_ea);  // Point to VdGlobalXamDevice (same for now)

            fprintf(stderr, "[GFX-CTX] Initialized static pointers: 0x101BE=0x%08X, 0x101BF=0x%08X\n", vd_ptr_ea, vd_ptr_ea);
            fflush(stderr);
        }
    } else {
        fprintf(stderr, "[GFX-CTX] ERROR: Failed to allocate VdGlobalDevice pointer\n");
        fflush(stderr);
    }

    // CRITICAL FIX: Initialize the allocator callback function pointer at offset 0x3538 (13624)
    // The allocator sub_825968B0 calls this function pointer to allocate memory
    // If it's NULL, all allocations fail and the game crashes with NULL-CALL errors
    // We need to find a valid allocator function address from the game
    // For now, set it to 0 and rely on the fallback buffer at 0x3D0C
    be<uint32_t>* allocator_callback_ptr = reinterpret_cast<be<uint32_t>*>(static_cast<uint8_t*>(ctx_host) + 0x3538);
    *allocator_callback_ptr = be<uint32_t>(0);  // NULL for now - will use fallback

    fprintf(stderr, "[GFX-CTX] Set allocator callback at offset 0x3538 to 0x00000000 (will use fallback)\n");
    fflush(stderr);

    // CRITICAL FIX: Initialize the fallback allocator pointer at offset 0x3D0C
    // The game reads this pointer when the primary allocator is NULL
    // We need to provide a valid allocator pointer here
    // For now, we'll set it to point to a small heap-allocated buffer that can be used as a fallback
    constexpr uint32_t FALLBACK_SIZE = 0x1080;  // 4224 bytes (size requested by sub_825960B8)
    void* fallback_host = g_userHeap.Alloc(FALLBACK_SIZE);
    if (fallback_host) {
        std::memset(fallback_host, 0, FALLBACK_SIZE);
        const uint32_t fallback_ea = g_memory.MapVirtual(fallback_host);

        // Write the fallback pointer to offset 0x3D0C in the graphics context
        be<uint32_t>* fallback_ptr = reinterpret_cast<be<uint32_t>*>(static_cast<uint8_t*>(ctx_host) + 0x3D0C);
        *fallback_ptr = be<uint32_t>(fallback_ea);

        fprintf(stderr, "[GFX-CTX] Set fallback allocator at offset 0x3D0C to 0x%08X\n", fallback_ea);
        fflush(stderr);
    } else {
        fprintf(stderr, "[GFX-CTX] WARNING: Failed to allocate fallback buffer\n");
        fflush(stderr);
    }

    return ctx_ea;
}

static void Mw05ForceRegisterGfxNotifyIfRequested() {
    const char* en = std::getenv("MW05_FORCE_GFX_NOTIFY_CB");
    if (!en || (en[0]=='0' && en[1]=='\0')) return;

    // Check if we should delay registration until after video init
    static const uint32_t s_register_delay_ticks = [](){
        if (const char* v = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS"))
            return (uint32_t)std::strtoul(v, nullptr, 10);
        return 0u; // default: no delay
    }();

    const uint32_t current_tick = g_vblankTicks.load(std::memory_order_acquire);
    if (current_tick < s_register_delay_ticks) {
        // Too early - skip registration for now
        static uint32_t s_last_log_tick = 0;
        if (current_tick == 0 || (current_tick - s_last_log_tick) >= 100) {
            KernelTraceHostOpF("HOST.VdISR.force_register.delayed tick=%u<%u", current_tick, s_register_delay_ticks);
            s_last_log_tick = current_tick;
        }
        return;
    }

    // Check if already registered (one-time registration)
    static std::atomic<bool> s_registered{false};
    if (s_registered.load(std::memory_order_acquire)) return;

    // CRITICAL: Ensure the graphics context structure is allocated BEFORE registering the callback
    // The callback at 0x825979A8 accesses memory at context+0x3CEC, which will crash if not allocated
    // Following Xenia's approach: allocate on heap and use the returned address
    uint32_t ctx = Mw05EnsureGraphicsContextAllocated();
    if (ctx == 0) {
        fprintf(stderr, "[GFX-REG] ERROR: Failed to allocate graphics context, cannot register callback\n");
        return;
    }

    // CRITICAL: Call VD initialization functions before registering the callback
    // The game's natural flow calls these before VdSetGraphicsInterruptCallback
    fprintf(stderr, "[GFX-REG] Calling VdInitializeEDRAM before callback registration\n");
    fflush(stderr);
    VdInitializeEDRAM();
    fprintf(stderr, "[GFX-REG] VdInitializeEDRAM completed\n");
    fflush(stderr);

    fprintf(stderr, "[GFX-REG] Calling VdInitializeEngines before callback registration\n");
    fflush(stderr);
    VdInitializeEngines(0, 0, 0, 0, 0);  // Call with all zeros to trigger callback injection
    fprintf(stderr, "[GFX-REG] VdInitializeEngines completed\n");
    fflush(stderr);

    // Default EA from known-good Xenia capture if not provided via MW05_FORCE_GFX_NOTIFY_CB_EA
    uint32_t cb_ea = 0x825979A8u;
    if (const char* s = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_EA")) {
        cb_ea = (uint32_t)std::strtoul(s, nullptr, 0);
    }
    // Use the heap-allocated context address (can be overridden by env var for testing)
    if (const char* c = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_CTX")) {
        ctx = (uint32_t)std::strtoul(c, nullptr, 0);
    }
    // Only install if caller hasn't already set a real ISR (avoid overriding guest)
    if (auto cur = VdGetGraphicsInterruptCallback(); cur == 0 || cur == kHostDefaultVdIsrMagic) {
        fprintf(stderr, "[GFX-REG] About to register callback cb=0x%08X ctx=0x%08X tick=%u\n", cb_ea, ctx, current_tick);
        fflush(stderr);

        KernelTraceHostOpF("HOST.VdISR.force_register cb=%08X ctx=%08X tick=%u", cb_ea, ctx, current_tick);
        VdSetGraphicsInterruptCallback(cb_ea, ctx);

        fprintf(stderr, "[GFX-REG] VdSetGraphicsInterruptCallback completed\n");
        fflush(stderr);

        // Also register into notification list so VdCallGraphicsNotificationRoutines hits it
        VdRegisterGraphicsNotificationRoutine(cb_ea, ctx);

        fprintf(stderr, "[GFX-REG] VdRegisterGraphicsNotificationRoutine completed\n");
        fflush(stderr);

        Mw05LogIsrIfRegisteredOnce();

        fprintf(stderr, "[GFX-REG] Registration complete, returning to VBLANK handler\n");
        fflush(stderr);

        // EXPERIMENTAL: Don't immediately invoke the callback - let it be called naturally
        // by the VBLANK pump or other mechanisms. This gives the game more time to initialize.
        static const bool s_immediate_invoke = [](){
            if (const char* v = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_IMMEDIATE"))
                return !(v[0]=='0' && v[1]=='\0');
            return false; // default: don't invoke immediately
        }();

        if (s_immediate_invoke) {
            fprintf(stderr, "[GFX-CALLBACK] Immediately invoking callback after registration\n");
            fflush(stderr);
            VdCallGraphicsNotificationRoutines(0u);
        } else {
            fprintf(stderr, "[GFX-CALLBACK] Callback registered, will be invoked naturally by VBLANK pump\n");
            fflush(stderr);
        }

        s_registered.store(true, std::memory_order_release);
    } else {
        KernelTraceHostOp("HOST.VdISR.force_register.skipped (already set)\n");
        s_registered.store(true, std::memory_order_release);
    }
}

// Force-call CreateDevice to bypass blocked state machine
// The game is stuck in TitleState loop and never calls CreateDevice naturally
// This function calls CreateDevice (sub_82598230) from host code after graphics init
static void Mw05ForceCallCreateDeviceIfRequested() {
    const char* en = std::getenv("MW05_FORCE_CALL_CREATEDEVICE");
    if (!en || (en[0]=='0' && en[1]=='\0')) {
        return;
    }

    // Check if we should delay CreateDevice call until after graphics init
    static const uint32_t s_call_delay_ticks = [](){
        if (const char* v = std::getenv("MW05_FORCE_CREATEDEVICE_DELAY_TICKS"))
            return (uint32_t)std::strtoul(v, nullptr, 10);
        return 100u; // default: wait 100 ticks (~1.67 seconds at 60 Hz)
    }();

    const uint32_t current_tick = g_vblankTicks.load(std::memory_order_acquire);
    if (current_tick < s_call_delay_ticks) {
        return;
    }

    // Check if already called (one-time call)
    static std::atomic<bool> s_called{false};
    bool expected = false;
    if (!s_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;  // Already called
    }

    fprintf(stderr, "[CREATEDEVICE-FORCE] Force-calling CreateDevice (sub_82598230) at tick=%u\n", current_tick);
    fflush(stderr);

    // Get the graphics context address
    uint32_t gfx_ctx = g_graphics_context_ea;
    if (gfx_ctx == 0) {
        fprintf(stderr, "[CREATEDEVICE-FORCE] ERROR: Graphics context not allocated!\n");
        fflush(stderr);
        return;
    }

    // Call CreateDevice with the graphics context as parameter
    // From analysis: CreateDevice(gfx_ctx, ...) initializes the device and sets gfx_ctx+4
    EnsureGuestContextForThisThread("ForceCallCreateDevice");

    // Get the guest base pointer
    uint8_t* base = MmGetGuestBase();

    #if defined(_WIN32)
    __try {
    #endif
        // Forward declaration of the CreateDevice function
        extern void sub_82598230(PPCContext& ctx, uint8_t* base);

        // Set up PPC context for the call
        PPCContext* ctx = GetPPCContext();
        if (!ctx) {
            fprintf(stderr, "[CREATEDEVICE-FORCE] ERROR: Failed to get PPC context!\n");
            fflush(stderr);
            return;
        }

        // Set parameters for CreateDevice
        // r3 = graphics context address
        ctx->r3.u32 = gfx_ctx;
        ctx->r4.u32 = 0;  // Additional parameters (unknown, set to 0)

        fprintf(stderr, "[CREATEDEVICE-FORCE] Calling sub_82598230 with r3=0x%08X\n", gfx_ctx);
        fflush(stderr);

        // Call CreateDevice
        sub_82598230(*ctx, base);

        fprintf(stderr, "[CREATEDEVICE-FORCE] sub_82598230 returned r3=0x%08X (0=success)\n", ctx->r3.u32);
        fflush(stderr);

        if (ctx->r3.u32 == 0) {
            fprintf(stderr, "[CREATEDEVICE-FORCE] CreateDevice succeeded! Game should now create render threads.\n");
            fflush(stderr);
            KernelTraceHostOp("HOST.CreateDevice.force_call.success");
        } else {
            fprintf(stderr, "[CREATEDEVICE-FORCE] CreateDevice FAILED with code 0x%08X\n", ctx->r3.u32);
            fflush(stderr);
            KernelTraceHostOp("HOST.CreateDevice.force_call.failed");
        }

    #if defined(_WIN32)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[CREATEDEVICE-FORCE] CreateDevice crashed with exception 0x%08X\n", (unsigned)GetExceptionCode());
        fflush(stderr);
        KernelTraceHostOp("HOST.CreateDevice.force_call.exception");
    }
    #endif
}

// Force-call sub_825AAE58 to create the main render thread (0x825AA970)
// This function is called AFTER CreateDevice in the natural flow (sub_825A8698)
// But since sub_825A8698 is never called, we need to force-call sub_825AAE58 directly
static void Mw05ForceCallCreateRenderThreadIfRequested() {
    const char* en = std::getenv("MW05_FORCE_CALL_CREATE_RENDER_THREAD");
    if (!en || (en[0]=='0' && en[1]=='\0')) {
        return;
    }

    // Check if we should delay the call until after CreateDevice succeeds
    static const uint32_t s_call_delay_ticks = [](){
        if (const char* v = std::getenv("MW05_FORCE_CREATE_RENDER_THREAD_DELAY_TICKS"))
            return (uint32_t)std::strtoul(v, nullptr, 10);
        return 500u; // default: wait 500 ticks (~8.33 seconds at 60 Hz) - after CreateDevice at 400
    }();

    const uint32_t current_tick = g_vblankTicks.load(std::memory_order_acquire);
    if (current_tick < s_call_delay_ticks) {
        return;
    }

    // Check if already called (one-time call)
    static std::atomic<bool> s_called{false};
    bool expected = false;
    if (!s_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;  // Already called
    }

    fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] Force-calling sub_825AAE58 at tick=%u\n", current_tick);
    fflush(stderr);

    // Get the graphics context address
    uint32_t gfx_ctx = g_graphics_context_ea;
    if (gfx_ctx == 0) {
        fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] ERROR: Graphics context not allocated!\n");
        fflush(stderr);
        return;
    }

    // Call sub_825AAE58 with the graphics context as parameter
    // From disassembly: sub_825AAE58 is called from sub_825A8698 after CreateDevice
    // It creates the render thread at 0x825AA970
    EnsureGuestContextForThisThread("ForceCallCreateRenderThread");

    // Get the guest base pointer
    uint8_t* base = MmGetGuestBase();

    #if defined(_WIN32)
    __try {
    #endif
        // Forward declaration of the sub_825AAE58 function
        extern void sub_825AAE58(PPCContext& ctx, uint8_t* base);

        // Set up PPC context for the call
        PPCContext* ctx = GetPPCContext();
        if (!ctx) {
            fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] ERROR: Failed to get PPC context!\n");
            fflush(stderr);
            return;
        }

        // Set r3 to the graphics context address (parameter for sub_825AAE58)
        ctx->r3.u32 = gfx_ctx;

        // CRITICAL DEBUG: Check the value at offset +20576 (0x5060)
        // sub_825AAE58 checks if (*(a1 + 20576) & 0x100) != 0 and returns early if true
        void* check_ptr = g_memory.Translate(gfx_ctx + 20576);
        if (check_ptr) {
            uint32_t check_val = __builtin_bswap32(*(uint32_t*)check_ptr);
            fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] CRITICAL: *(gfx_ctx+20576) = 0x%08X (bit 0x100 = %s)\n",
                    check_val, (check_val & 0x100) ? "SET (will skip thread creation!)" : "NOT SET (OK)");
            fflush(stderr);
        }

        fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] Calling sub_825AAE58 with r3=0x%08X\n", ctx->r3.u32);
        fflush(stderr);

        // Call sub_825AAE58
        sub_825AAE58(*ctx, base);

        fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] sub_825AAE58 returned r3=0x%08X\n", ctx->r3.u32);
        fflush(stderr);

        if (ctx->r3.u32 == 0 || ctx->r3.u32 == 1) {
            fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] sub_825AAE58 succeeded! Render thread should now be created.\n");
            fflush(stderr);
            KernelTraceHostOp("HOST.sub_825AAE58.force_call.success");
        } else {
            fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] sub_825AAE58 returned unexpected value 0x%08X\n", ctx->r3.u32);
            fflush(stderr);
            KernelTraceHostOp("HOST.sub_825AAE58.force_call.unexpected");
        }

    #if defined(_WIN32)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[CREATE-RENDER-THREAD-FORCE] sub_825AAE58 crashed with exception 0x%08X\n", (unsigned)GetExceptionCode());
        fflush(stderr);
        KernelTraceHostOp("HOST.sub_825AAE58.force_call.exception");
    }
    #endif
}

// Force-create the render thread if it hasn't been created naturally
// This thread (entry=0x825AA970) is responsible for issuing draw commands
static void Mw05ForceCreateRenderThreadIfRequested() {
    const char* en = std::getenv("MW05_FORCE_RENDER_THREAD");
    if (!en || (en[0]=='0' && en[1]=='\0')) {
        static bool s_logged_disabled = false;
        if (!s_logged_disabled) {
            fprintf(stderr, "[RENDER-THREAD-DEBUG] MW05_FORCE_RENDER_THREAD not set or disabled\n");
            fflush(stderr);
            s_logged_disabled = true;
        }
        return;
    }

    // Check if we should delay thread creation until after graphics init
    static const uint32_t s_create_delay_ticks = [](){
        if (const char* v = std::getenv("MW05_FORCE_RENDER_THREAD_DELAY_TICKS"))
            return (uint32_t)std::strtoul(v, nullptr, 10);
        return 200u; // default: wait 200 ticks to ensure graphics is initialized
    }();

    static bool s_logged_config = false;
    if (!s_logged_config) {
        fprintf(stderr, "[RENDER-THREAD-DEBUG] MW05_FORCE_RENDER_THREAD enabled, delay_ticks=%u\n", s_create_delay_ticks);
        fflush(stderr);
        s_logged_config = true;
    }

    const uint32_t current_tick = g_vblankTicks.load(std::memory_order_acquire);
    if (current_tick < s_create_delay_ticks) {
        // Too early - skip creation for now
        static uint32_t s_last_logged_tick = 0;
        if (current_tick >= s_last_logged_tick + 50) {
            fprintf(stderr, "[RENDER-THREAD-DEBUG] Waiting for tick %u (current=%u)\n", s_create_delay_ticks, current_tick);
            fflush(stderr);
            s_last_logged_tick = current_tick;
        }
        return;
    }

    // Check if already created (one-time creation)
    static std::atomic<bool> s_created{false};
    bool expected = false;
    if (!s_created.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        // Another thread is creating or has created the render thread
        static bool s_logged_already_created = false;
        if (!s_logged_already_created) {
            fprintf(stderr, "[RENDER-THREAD-DEBUG] Render thread already created or being created\n");
            fflush(stderr);
            s_logged_already_created = true;
        }
        return;
    }

    fprintf(stderr, "[RENDER-THREAD-DEBUG] About to create render thread at tick=%u\n", current_tick);
    fflush(stderr);

    // Get the render thread entry point from environment or use default
    uint32_t entry = 0x825AA970u;  // Default from Xenia log
    if (const char* s = std::getenv("MW05_RENDER_THREAD_ENTRY")) {
        entry = (uint32_t)std::strtoul(s, nullptr, 0);
    }

    // Get the context pointer - this should be the scheduler context
    uint32_t ctx = 0x40009D2Cu;  // Default from Xenia log (correct context for render thread)
    if (const char* c = std::getenv("MW05_RENDER_THREAD_CTX")) {
        ctx = (uint32_t)std::strtoul(c, nullptr, 0);
    }

    // Initialize the context structure
    // The render thread expects context+0 to point to a graphics/scheduler context
    // From analysis: r27 = Load32(context+0), then Load32(r27+628) is checked
    // Following Xenia's approach: use heap-allocated graphics context
    uint32_t gfx_ctx = g_graphics_context_ea;
    if (gfx_ctx == 0) {
        // Context not yet allocated - allocate it now
        gfx_ctx = Mw05EnsureGraphicsContextAllocated();
        if (gfx_ctx == 0) {
            fprintf(stderr, "[RENDER-THREAD] ERROR: Failed to allocate graphics context\n");
            return;
        }
    }
    if (auto* ctx_ptr = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(ctx))) {
        *ctx_ptr = be<uint32_t>(gfx_ctx);  // Set pointer to graphics context
        fprintf(stderr, "[RENDER-THREAD] Initialized context+0 at 0x%08X to point to gfx_ctx=0x%08X (heap-allocated)\n", ctx, gfx_ctx);
        fflush(stderr);
    }

    // Initialize the event at ctx+0x20 (this is what the render thread waits on)
    // From disassembly: addi r28, r26, 0x20 -> KeWaitForSingleObject(r28)
    uint32_t event_ea = ctx + 0x20;  // 0x40009D2C + 0x20 = 0x40009D4C
    if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(event_ea))) {
        evt->Type = 0;  // Auto-reset event (Type 0 = NotificationEvent)
        evt->SignalState = be<int32_t>(0);  // Not signaled initially
        fprintf(stderr, "[RENDER-THREAD] Initialized event at 0x%08X (ctx+0x20) type=%u signal=%d\n",
                event_ea, evt->Type, (int)evt->SignalState);
        fflush(stderr);
    } else {
        fprintf(stderr, "[RENDER-THREAD] ERROR: Failed to translate event address 0x%08X\n", event_ea);
        fflush(stderr);
    }

    // APPROACH A: Find and set the flag that gates present calls
    // The render thread checks a flag at r31+10434 before calling present
    // r31 is loaded from a global graphics device structure
    // Try to find and set this flag to enable present calls
    static const bool s_force_present_flag = [](){
        if (const char* v = std::getenv("MW05_FORCE_PRESENT_FLAG")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_force_present_flag) {
        // r31 is loaded from either (0x82000000+2884) or (0x82000000+2888) depending on process type
        // Try both locations
        for (uint32_t offset : {2884u, 2888u}) {
            uint32_t ptr_ea = 0x82000000u + offset;
            if (auto* ptr_ptr = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(ptr_ea))) {
                uint32_t r31_ea = ptr_ptr->get();
                if (r31_ea >= 0x1000 && r31_ea < 0x90000000) {
                    // Found a valid pointer, set the flag at offset 10434
                    uint32_t flag_ea = r31_ea + 10434;
                    if (auto* flag_ptr = reinterpret_cast<uint8_t*>(g_memory.Translate(flag_ea))) {
                        *flag_ptr = 0x08;  // Set bit 3 (the flag checked by the render thread)
                        fprintf(stderr, "[RENDER-THREAD] Set present flag at 0x%08X (r31=0x%08X offset=10434)\n", flag_ea, r31_ea);
                        fflush(stderr);
                    }
                }
            }
        }
    }

    fprintf(stderr, "[RENDER-THREAD] About to create render thread entry=0x%08X ctx=0x%08X tick=%u\n", entry, ctx, current_tick);
    fflush(stderr);

    KernelTraceHostOpF("HOST.RenderThread.force_create entry=%08X ctx=%08X tick=%u", entry, ctx, current_tick);

    // Create the thread using ExCreateThread
    // Flags: 0x00000000 = not suspended (same as Xenia log shows)
    uint32_t stack_size = 0x40000;  // 256KB stack (same as other game threads)

    EnsureGuestContextForThisThread("ForceCreateRenderThread");

    #if defined(_WIN32)
    __try {
    #endif
        // Call ExCreateThread
        // The function signature is: uint32_t ExCreateThread(be<uint32_t>* handle, uint32_t stackSize, be<uint32_t>* threadId, uint32_t xApiThreadStartup, uint32_t startAddress, uint32_t startContext, uint32_t creationFlags)
        // For MW05, xApiThreadStartup is typically 0 (the game uses startAddress directly)

        fprintf(stderr, "[RENDER-THREAD] Calling ExCreateThread...\n");
        fflush(stderr);

        // Forward declaration of ExCreateThread
        extern uint32_t ExCreateThread(be<uint32_t>* handle, uint32_t stackSize, be<uint32_t>* threadId, uint32_t xApiThreadStartup, uint32_t startAddress, uint32_t startContext, uint32_t creationFlags);

        be<uint32_t> thread_handle = 0;
        be<uint32_t> thread_id = 0;

        uint32_t result = ExCreateThread(&thread_handle, stack_size, &thread_id, 0, entry, ctx, 0x00000000);

        fprintf(stderr, "[RENDER-THREAD] ExCreateThread returned 0x%08X, handle=0x%08X, tid=0x%08X\n", result, (uint32_t)thread_handle, (uint32_t)thread_id);
        fflush(stderr);

        if (result == 0) {  // STATUS_SUCCESS
            fprintf(stderr, "[RENDER-THREAD] Render thread created successfully!\n");
            fflush(stderr);
            KernelTraceHostOpF("HOST.RenderThread.force_create.success handle=%08X tid=%08X", (uint32_t)thread_handle, (uint32_t)thread_id);
        } else {
            fprintf(stderr, "[RENDER-THREAD] ExCreateThread failed with status 0x%08X\n", result);
            fflush(stderr);
            KernelTraceHostOpF("HOST.RenderThread.force_create.failed status=%08X", result);
        }

    #if defined(_WIN32)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[RENDER-THREAD] ExCreateThread crashed with exception 0x%08X\n", (unsigned)GetExceptionCode());
        fflush(stderr);
        KernelTraceHostOpF("HOST.RenderThread.force_create.exception code=%08X", (unsigned)GetExceptionCode());
    }
    #endif

    // s_created is already set to true at the beginning of the function via compare_exchange
}

// Verify that the static global context memory is accessible
void VerifyStaticContextMemory() {
    const uint32_t qword_828F1F98_addr = 0x828F1F98;
    const uint32_t dword_828F1F90_addr = 0x828F1F90;
    const uint32_t qword_120E10_addr = 0x00120E10;

    fprintf(stderr, "[STATIC-CONTEXT-VERIFY] Checking static global context memory:\n");

    // Check qword_828F1F98 (the expected context structure)
    void* qword_host = g_memory.Translate(qword_828F1F98_addr);
    if (qword_host == nullptr) {
        fprintf(stderr, "[STATIC-CONTEXT-ERROR] ❌ qword_828F1F98 at 0x%08X is NOT MAPPED!\n", qword_828F1F98_addr);
        fprintf(stderr, "[STATIC-CONTEXT-ERROR] This is CRITICAL - .data section not loaded correctly!\n");
    } else {
        uint64_t* qword_ptr = (uint64_t*)qword_host;
        uint64_t value = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[STATIC-CONTEXT-OK] ✅ qword_828F1F98 at 0x%08X is mapped to host %p\n",
                qword_828F1F98_addr, qword_host);
        fprintf(stderr, "[STATIC-CONTEXT-OK] Current value: 0x%016llX\n", value);
    }

    // Check dword_828F1F90 (the event handle)
    void* dword_host = g_memory.Translate(dword_828F1F90_addr);
    if (dword_host == nullptr) {
        fprintf(stderr, "[STATIC-CONTEXT-ERROR] ❌ dword_828F1F90 at 0x%08X is NOT MAPPED!\n", dword_828F1F90_addr);
    } else {
        uint32_t* dword_ptr = (uint32_t*)dword_host;
        uint32_t value = __builtin_bswap32(*dword_ptr);
        fprintf(stderr, "[STATIC-CONTEXT-OK] ✅ dword_828F1F90 at 0x%08X is mapped to host %p\n",
                dword_828F1F90_addr, dword_host);
        fprintf(stderr, "[STATIC-CONTEXT-OK] Current value: 0x%08X\n", value);
    }

    // Check qword_120E10 (the WRONG context address being used)
    void* qword_120E10_host = g_memory.Translate(qword_120E10_addr);
    if (qword_120E10_host == nullptr) {
        fprintf(stderr, "[STATIC-CONTEXT-ERROR] ❌ qword_120E10 at 0x%08X is NOT MAPPED!\n", qword_120E10_addr);
    } else {
        uint64_t* qword_120E10_ptr = (uint64_t*)qword_120E10_host;
        uint64_t value = __builtin_bswap64(*qword_120E10_ptr);
        fprintf(stderr, "[STATIC-CONTEXT-WARN] ⚠️ qword_120E10 at 0x%08X is mapped to host %p\n",
                qword_120E10_addr, qword_120E10_host);
        fprintf(stderr, "[STATIC-CONTEXT-WARN] Current value: 0x%016llX (This is the WRONG context!)\n", value);
    }

    fflush(stderr);
}

uint32_t MmGetPhysicalAddress(uint32_t address)
{
    LOGF_UTILITY("0x{:x}", address);
    return address;
}

void VdSetSystemCommandBufferGpuIdentifierAddress(uint32_t addr)
{
    KernelTraceHostOpF("HOST.VdSetSystemCommandBufferGpuIdentifierAddress addr=%08X", addr);
    g_VdSystemCommandBufferGpuIdAddr = addr;
}

void VdSetSystemCommandBuffer(uint32_t base, uint32_t len)
{
    if (base != 0) {
        g_VdSystemCommandBuffer.store(base);
        g_SysCmdBufGuest = base;
        g_SysCmdBufHost = g_memory.Translate(base);
    }
    (void)len;
}


void _vsnprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

// Alias to satisfy import name "__imp____vsnprintf" (two underscores before vsnprintf)
PPC_FUNC(__imp____vsnprintf)
{
    // Minimal stub: return 0 chars written
    KernelTraceHostOp("HOST.__vsnprintf (alias stub: return 0)");
    ctx.r3.u32 = 0;
}


void sprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void ExRegisterTitleTerminateNotification()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdShutdownEngines()
{
    LOG_UTILITY("!!! STUB !!!");
    fprintf(stderr, "[VdShutdownEngines] CALLED! Stopping VBlank pump...\n");
    fflush(stderr);
    g_vblankPumpRun.store(false, std::memory_order_release);
}

void VdQueryVideoMode(XVIDEO_MODE* vm)
{
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    KernelTraceHostOp("HOST.VdQueryVideoMode");

    // Log first few calls to confirm it's being called
    if (count < 5) {
        fprintf(stderr, "[VdQueryVideoMode] CALL #%llu: vm=%p\n", count, (void*)vm);
        fflush(stderr);
    }

    memset(vm, 0, sizeof(XVIDEO_MODE));
    vm->DisplayWidth = 1280;
    vm->DisplayHeight = 720;
    vm->IsInterlaced = false;
    vm->IsWidescreen = true;
    vm->IsHighDefinition = true;
    vm->RefreshRate = 0x42700000;
    vm->VideoStandard = 1;
    vm->Unknown4A = 0x4A;
    vm->Unknown01 = 0x01;

    if (count < 5) {
        fprintf(stderr, "[VdQueryVideoMode]   Returned: %ux%u\n", vm->DisplayWidth, vm->DisplayHeight);
        fflush(stderr);
    }
}

void VdGetCurrentDisplayInformation(void* info)
{
    KernelTraceHostOp("HOST.VdGetCurrentDisplayInformation");

    // Fill a minimal display info block expected by MW05 callers.
    // Callers pass a stack buffer and read specific offsets:
    //   lhz +0x98 (width), lhz +0x9A (height), lhz +0xA6 (unknown), lbz +0x54 (flags)
    if (!info) return;
    uint32_t width = 1280, height = 720;
    auto* p = reinterpret_cast<uint8_t*>(info);
    // Big-endian stores for guest reads

    *reinterpret_cast<be<uint16_t>*>(p + 0x98) = static_cast<uint16_t>(width);
    *reinterpret_cast<be<uint16_t>*>(p + 0x9A) = static_cast<uint16_t>(height);
    *reinterpret_cast<be<uint16_t>*>(p + 0xA6) = static_cast<uint16_t>(60); // nominal refresh or aux field
    p[0x54] = 1; // an enable/flag byte the guest reads
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] GetCurrentDisplayInformation w=%u h=%u\n", width, height);
        fflush(stdout);
    }
}

void VdSetDisplayMode(uint32_t /*mode*/)
{
    // Accept and ignore; our renderer manages swapchain independently.
    KernelTraceHostOp("HOST.VdSetDisplayMode");
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] SetDisplayMode()\n");
        fflush(stdout);
    }
}

void VdSetGraphicsInterruptCallback(uint32_t callback, uint32_t context)
{
    // CRITICAL FIX: Initialize the context memory to prevent access violations!
    // The callback at 0x825979A8 tries to access memory at context+0x2894
    // But the game hasn't initialized this memory yet when the callback is first called
    // So we initialize it with zeros to prevent crashes
    uint32_t original_context = context;

    // CRITICAL FIX: Store callback/context pair in the map for multi-context support
    // The game creates TWO GPU contexts and registers a callback for each one
    // We need to store both instead of overwriting the first with the second
    {
        std::lock_guard<std::mutex> lock(g_VdCallbackMapMutex);
        g_VdCallbackMap[context] = std::make_pair(callback, context);

        fprintf(stderr, "[CALLBACK-MAP] Registered callback for context 0x%08X -> callback=0x%08X (total contexts: %zu)\n",
                context, callback, g_VdCallbackMap.size());
        fflush(stderr);
    }

    // Also update deprecated global variables for compatibility
    g_VdGraphicsCallback = callback;
    g_VdGraphicsCallbackCtx = context;

    // Initialize the context memory (16KB should be enough)
    // The callback accesses context[2597] which is at offset 0x2894 (10388 bytes)
    // So we need at least 16KB of initialized memory
    static bool s_context_initialized = false;
    if (!s_context_initialized && context != 0) {
        s_context_initialized = true;

        // Get host pointer to context memory
        void* ctx_host = g_memory.Translate(context);
        if (ctx_host) {
            // Initialize 16KB of memory with zeros
            std::memset(ctx_host, 0, 16384);

            fprintf(stderr, "[CONTEXT-INIT] Initialized context memory at 0x%08X (16KB)\n", context);
            fprintf(stderr, "[CONTEXT-INIT]   This prevents access violations in graphics callback\n");
            fflush(stderr);

            // CRITICAL FIX: Initialize the inner structure at context+0x2894
            // The VBlank ISR callback reads from this structure:
            //   v10 = *(_DWORD *)(a7 + 16);  // offset +0x10 (16) from inner structure
            //   if ( v10 ) { v8(*(_DWORD **)(a2[2597] + 20)); }  // offset +0x14 (20) from inner structure
            // We need to ensure offset +0x10 is 0 to prevent the callback from being called
            constexpr uint32_t STRUCT_OFFSET = 0x2894;
            constexpr uint32_t STRUCT_SIZE = 0x4000;  // 16KB

            // Allocate the inner structure
            void* struct_host = g_userHeap.Alloc(STRUCT_SIZE);
            if (struct_host) {
                // Zero-initialize
                std::memset(struct_host, 0, STRUCT_SIZE);

                // Convert to guest address
                const uint32_t struct_guest = g_memory.MapVirtual(struct_host);

                // Store the pointer at context+0x2894 (in BIG-ENDIAN format)
                be<uint32_t>* ctx_struct_ptr = reinterpret_cast<be<uint32_t>*>(
                    static_cast<uint8_t*>(ctx_host) + STRUCT_OFFSET);
                *ctx_struct_ptr = be<uint32_t>(struct_guest);

                fprintf(stderr, "[CONTEXT-INIT] Allocated inner structure at 0x%08X, stored pointer at context+0x%04X\n",
                        struct_guest, STRUCT_OFFSET);
                fflush(stderr);

                // Initialize important members inside the inner structure that ISR uses
                {
                    auto* inner_u32 = reinterpret_cast<uint32_t*>(struct_host);
                    // CRITICAL FIX: The VBlank ISR callback reads from offset +0x10 and +0x14 of the inner structure
                    // According to decompiled sub_825979A8:
                    //   v10 = *(_DWORD *)(a7 + 16);  // offset +0x10 (16)
                    //   if ( v10 ) { v8(*(_DWORD **)(a2[2597] + 20)); }  // offset +0x14 (20)
                    // So we need to ensure BOTH +0x10 and +0x14 are initialized to 0
                    inner_u32[0x10 / 4] = 0;  // +0x10 (16) - callback type/flag
                    inner_u32[0x14 / 4] = 0;  // +0x14 (20) - callback function pointer
                    // Present function pointer (+0x3CEC) initially 0; will be set before first call
                    inner_u32[0x3CEC / 4] = 0;
                    // Invocation counter (+0x3CF0)
                    inner_u32[0x3CF0 / 4] = 0;
                    // Decrement counter (+0x3CF8)
                    inner_u32[0x3CF8 / 4] = 0;
                    // Scratch (+0x3CF4, +0x3CFC)
                    inner_u32[0x3CF4 / 4] = 0;
                    inner_u32[0x3CFC / 4] = 0;

                    fprintf(stderr, "[CONTEXT-INIT] Initialized inner structure: +0x10=%08X +0x14=%08X +0x3CEC=%08X\n",
                            inner_u32[0x10 / 4], inner_u32[0x14 / 4], inner_u32[0x3CEC / 4]);
                    fflush(stderr);
                }
            } else {
                fprintf(stderr, "[CONTEXT-INIT] WARNING: Failed to allocate inner structure\n");
                fflush(stderr);
            }
        }
    }

    // Monitor when the game NATURALLY registers a callback (not forced by us)
    static bool s_first_natural_registration = true;
    if (s_first_natural_registration) {
        s_first_natural_registration = false;
        fprintf(stderr, "\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "[NATURAL-REG] Game naturally registered graphics callback!\n");
        fprintf(stderr, "[NATURAL-REG]   Callback: 0x%08X\n", callback);
        fprintf(stderr, "[NATURAL-REG]   Context:  0x%08X\n", context);
        fprintf(stderr, "[NATURAL-REG]   Tick:     %u\n", g_vblankTicks.load());
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\n");
        fflush(stderr);
    }

    LOGFN("[vd] SetGraphicsInterruptCallback cb=0x{:08X} ctx=0x{:08X}", callback, context);
    KernelTraceHostOpF("HOST.VdSetGraphicsInterruptCallback cb=%08X ctx=%08X", callback, context);
}
void VdRegisterGraphicsNotificationRoutine(uint32_t callback, uint32_t context)
{
    // NO REDIRECTION - use the context address provided by the game
    // We initialize the context memory at 0x40007180 in VdSetGraphicsInterruptCallback
    // so there's no need to redirect to a heap-allocated address

    KernelTraceHostOpF("HOST.VdRegisterGraphicsNotificationRoutine cb=%08X ctx=%08X", callback, context);
    {
        std::scoped_lock lk(g_VdNotifMutex);
        for (auto& p : g_VdNotifList) {
            if (p.first == callback) { p.second = context; goto after_store; }
        }
        g_VdNotifList.emplace_back(callback, context);
    }
after_store:
    // Some titles expect an immediate notify on registration to catch up.
    // Make this opt-in via MW05_NOTIFY_IMMEDIATE=1 to reduce early-boot risk.
    static const bool s_notify_immediate = [](){
        if (const char* v = std::getenv("MW05_NOTIFY_IMMEDIATE"))
            return !(v[0]=='0' && v[1]=='\0');
        return false; // default: off
    }();
    if (s_notify_immediate) {
        if (callback == kHostDefaultVdIsrMagic) {
            KernelTraceHostOp("HOST.VdNotify.host_isr.immediate");
            Mw05RunHostDefaultVdIsrNudge("notify");
        } else if (callback) {
            KernelTraceHostOp("HOST.VdNotify.dispatch.immediate");
            GuestToHostFunction<void>(callback, 0u, context);
        }
    }
}

void VdUnregisterGraphicsNotificationRoutine(uint32_t callback)
{
    KernelTraceHostOpF("HOST.VdUnregisterGraphicsNotificationRoutine cb=%08X", callback);
    std::scoped_lock lk(g_VdNotifMutex);
    g_VdNotifList.erase(std::remove_if(g_VdNotifList.begin(), g_VdNotifList.end(),
        [callback](const auto& p){ return p.first == callback; }), g_VdNotifList.end());
}


void VdInitializeEngines(uint32_t unk0, uint32_t callback_ea, uint32_t callback_arg, uint32_t pfp_ptr, uint32_t me_ptr)
{
    static int call_count = 0;
    call_count++;

    // Log to both stderr and trace file (matching Xenia's parameter names)
    // Log ALL calls to see if the function is being called multiple times
    fprintf(stderr, "[VdInitEngines #%d] ENTRY: unk0=%08X cb=%08X arg=%08X pfp_ptr=%08X me_ptr=%08X tid=%lx\n",
            call_count, unk0, callback_ea, callback_arg, pfp_ptr, me_ptr, GetCurrentThreadId());
    fflush(stderr);

    KernelTraceHostOpF("HOST.VdInitializeEngines.CALL#%d unk0=%08X cb=%08X arg=%08X pfp_ptr=%08X me_ptr=%08X",
                       call_count, unk0, callback_ea, callback_arg, pfp_ptr, me_ptr);

    Mw05ApplyVdPokesOnce();
    // Consider engines initialized; also start the vblank pump to ensure
    // display-related waiters can make progress during bring-up.
    Mw05AutoVideoInitIfNeeded();
    Mw05StartVblankPumpOnce();

    // CRITICAL FIX: Always ensure graphics context is allocated BEFORE calling any callback
    // The VdGlobalDevice and VdGlobalXamDevice variables must be initialized for file I/O to work
    // This is required regardless of which callback is used
    if (g_graphics_context_ea == 0) {
        uint32_t ctx = Mw05EnsureGraphicsContextAllocated();
        if (ctx == 0) {
            fprintf(stderr, "[VdInitEngines #%d] ERROR: Failed to allocate graphics context\n", call_count);
            return;
        }
        fprintf(stderr, "[VdInitEngines #%d] Allocated graphics context at 0x%08X\n", call_count, ctx);
        fflush(stderr);
    }

    // CRITICAL FIX: If callback_ea is 0, inject a default callback to initialize graphics device
    // The game sometimes calls VdInitializeEngines with cb=0, which skips graphics device initialization
    // This causes ISR-present to fail because it can't find the graphics device structure
    if (callback_ea == 0) {
        // Check if we should inject a default callback
        static const bool inject_enabled = []() -> bool {
            if (const char* v = std::getenv("MW05_INJECT_VD_CALLBACK"))
                return !(v[0] == '0' && v[1] == '\0');
            return true;  // Enabled by default
        }();

        if (inject_enabled) {
            // Use the known-good callback address from Xenia traces
            callback_ea = 0x825979A8u;
            // Use the heap-allocated graphics context address as the callback argument
            callback_arg = g_graphics_context_ea;

            fprintf(stderr, "[VdInitEngines #%d] INJECTING default callback: cb=0x%08X arg=0x%08X (was cb=0)\n",
                    call_count, callback_ea, callback_arg);
            fflush(stderr);
            KernelTraceHostOpF("HOST.VdInitializeEngines.INJECT_CB cb=%08X arg=%08X", callback_ea, callback_arg);
        } else {
            fprintf(stderr, "[VdInitEngines #%d] No callback (cb=0), call_count=%d\n", call_count, call_count);
            fflush(stderr);
            return;
        }
    }

    // Call the callback (this initializes the graphics context structure)
    fprintf(stderr, "[VdInitEngines #%d] Calling callback at 0x%08X with arg=%08X\n",
            call_count, callback_ea, callback_arg);
    fflush(stderr);

    // Check if the callback address is valid
    if (!GuestOffsetInRange(callback_ea, 4)) {
        fprintf(stderr, "[VdInitEngines #%d] ERROR: Callback address 0x%08X is out of range!\n", call_count, callback_ea);
        fflush(stderr);
        return;
    }

        // Dump first 16 bytes at callback address to see if it's code
        if (uint32_t* ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(callback_ea))) {
            uint32_t word0 = _byteswap_ulong(ptr[0]);
            uint32_t word1 = _byteswap_ulong(ptr[1]);
            uint32_t word2 = _byteswap_ulong(ptr[2]);
            uint32_t word3 = _byteswap_ulong(ptr[3]);
            fprintf(stderr, "[VdInitEngines #%d] Callback memory at 0x%08X: %08X %08X %08X %08X\n",
                    call_count, callback_ea, word0, word1, word2, word3);
            fflush(stderr);

            // Check if it looks like PowerPC code (most instructions have high bits set)
            if ((word0 & 0xFC000000) == 0) {
                fprintf(stderr, "[VdInitEngines #%d] WARNING: Callback at 0x%08X doesn't look like code (first word=%08X)\n",
                        call_count, callback_ea, word0);
                fflush(stderr);
            }
        }

        // Get current PPC context to call the callback
        PPCContext* ctx_ptr = GetPPCContext();
        fprintf(stderr, "[VdInitEngines #%d] GetPPCContext() returned %p (tid=%lx)\n",
                call_count, (void*)ctx_ptr, GetCurrentThreadId());
        fflush(stderr);

        // Create temporary context if called from host thread
        PPCContext temp_ctx;
        bool using_temp_ctx = false;

        if (!ctx_ptr) {
            // No PPC context - this is being called from a host/system thread
            // Create a temporary context for the callback
            fprintf(stderr, "[VdInitEngines #%d] No PPC context (host thread), creating temporary context\n", call_count);
            fflush(stderr);

            memset(&temp_ctx, 0, sizeof(temp_ctx));
            ctx_ptr = &temp_ctx;
            using_temp_ctx = true;

            // Install temporary context into TLS
            SetPPCContext(temp_ctx);
            fprintf(stderr, "[VdInitEngines #%d] Temporary context installed, GetPPCContext()=%p\n",
                    call_count, (void*)GetPPCContext());
            fflush(stderr);
        }

        fprintf(stderr, "[VdInitEngines #%d] Got context, calling callback...\n", call_count);
        fflush(stderr);

            // Save original context
            PPCContext saved_ctx = *ctx_ptr;

            // Set up parameter for the callback (r3 = callback_arg)
            ctx_ptr->r3.u32 = callback_arg;

            // Call the callback - need to dereference ctx_ptr and get base pointer
            PPCContext& ctx = *ctx_ptr;
            uint8_t* base = g_memory.base;
            PPC_CALL_INDIRECT_FUNC(callback_ea);

            // Restore context (except return value in r3)
            uint32_t return_value = ctx_ptr->r3.u32;
            *ctx_ptr = saved_ctx;
            ctx_ptr->r3.u32 = return_value;

            fprintf(stderr, "[VdInitEngines #%d] Callback returned r3=0x%08X\n", call_count, return_value);
            fflush(stderr);

            // Clean up temporary context if we created one
            if (using_temp_ctx) {
                g_ppcContext = nullptr;
                fprintf(stderr, "[VdInitEngines #%d] Temporary context removed\n", call_count);
                fflush(stderr);
            }
}

uint32_t VdIsHSIOTrainingSucceeded()
{
    // Unblock caller loops waiting for HSIO training.
    return 1;
}

void VdGetCurrentDisplayGamma()
{
    KernelTraceHostOp("HOST.VdGetCurrentDisplayGamma");
    // Provide a sane default gamma curve; host handles gamma via post-process.
    // No guest state to mutate here; treat as success.
}

void VdQueryVideoFlags()
{
    KernelTraceHostOp("HOST.VdQueryVideoFlags");
    // MW05 reads flags via other queries; nothing required here. No-op success.
}

void VdInitializeEDRAM()
{
    KernelTraceHostOp("HOST.VdInitializeEDRAM");
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] InitializeEDRAM()\n"); fflush(stdout);
    }
}

void VdCallGraphicsNotificationRoutines(uint32_t source) {
    KernelTraceHostOpF("HOST.VdCallGraphicsNotificationRoutines source=%u", source);

    // PERFORMANCE FIX: Mw05ForceCreateMissingWorkerThreads() is DISABLED (just returns immediately)
    // Removed call to avoid wasted function calls

    // First, dispatch any registered graphics notification routines (list),
    // which some titles rely on to advance their render scheduler.
    {
        std::vector<std::pair<uint32_t, uint32_t>> local;
        {
            std::scoped_lock lk(g_VdNotifMutex);
            local = g_VdNotifList; // copy to avoid holding lock while calling guest
        }
        static const bool s_force_ctx_sched = []() {
            if(const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED")) return !(v[0] == '0' && v[1] == '\0');
            return false;
        }
        ();
        for(const auto& [ncb, nctx] : local) {
            if(!ncb) continue;
            if(ncb == kHostDefaultVdIsrMagic) {
                KernelTraceHostOp("HOST.VdNotify.host_isr");
                Mw05RunHostDefaultVdIsrNudge("notify");
            } else {
                // Optionally override context with discovered scheduler pointer

                uint32_t use_ctx = nctx;
                if(s_force_ctx_sched) {
                    uint32_t sched = Mw05Trace_LastSchedR3();
                    if(GuestOffsetInRange(sched, 4)) use_ctx = sched;
                }
                // Gate guest ISR dispatch for a few ticks after startup to avoid early-boot crashes
                static const uint32_t s_guest_isr_delay = []() {
                    if(const char* v = std::getenv("MW05_GUEST_ISR_DELAY_TICKS"))
                        return (uint32_t)std::strtoul(v, nullptr, 10);
                    return 0u; // default: no delay unless configured
                }
                ();
                const uint32_t ticks = g_vblankTicks.load(std::memory_order_acquire);
                if(ticks < s_guest_isr_delay) {
                    KernelTraceHostOpF("HOST.VdNotify.dispatch.skip.early ticks=%u<%u", (unsigned)ticks, (unsigned)s_guest_isr_delay);
                } else {
                    KernelTraceHostOpF("HOST.VdNotify.dispatch cb=%08X ctx=%08X", ncb, use_ctx);
                    // Xbox 360 graphics notify routine typically receives (source, context),
                    // but allow an opt-in param swap for experiments.
                    // Optional: dump a small window of the scheduler context in notify-list dispatch
                    if(const char* dump = std::getenv("MW05_DUMP_SCHED_CTX")) {
                        if(!(dump[0] == '0' && dump[1] == '\0') && GuestOffsetInRange(use_ctx, 64)) {
                            const uint32_t* p32 = reinterpret_cast<const uint32_t*>(g_memory.Translate(use_ctx));
                            if(p32) {
#if defined(_MSC_VER)
                                auto bswap = [](uint32_t v) {
                                    return _byteswap_ulong(v);
                                };
#else
                                auto bswap = [](uint32_t v) {
                                    return __builtin_bswap32(v);
                                };
#endif
                                KernelTraceHostOpF("HOST.SchedCtxDump %08X: %08X %08X %08X %08X", use_ctx + 0, bswap(p32[0]), bswap(p32[1]), bswap(p32[2]), bswap(p32[3]));
                                KernelTraceHostOpF("HOST.SchedCtxDump %08X: %08X %08X %08X %08X", use_ctx + 16, bswap(p32[4]), bswap(p32[5]), bswap(p32[6]), bswap(p32[7]));
                            }
                        }
                    }

                    EnsureGuestContextForThisThread("VdNotifyList");
                    static const bool s_isr_swap = []() {
                        if(const char* v = std::getenv("MW05_VD_ISR_SWAP_PARAMS")) return !(v[0] == '0' && v[1] == '\0');
                        return false;
                    }
                    ();
                    if(s_isr_swap) {
                        KernelTraceHostOp("HOST.VdNotify.dispatch.swap r3<->r4");
                        GuestToHostFunction<void>(ncb, use_ctx, source);
                    } else {
                        GuestToHostFunction<void>(ncb, source, use_ctx);
                    }
                }
            }
        }
    }

    // Also invoke the singular ISR callback if present. This matches titles that
    // expect both paths to be driven by VdCallGraphicsNotificationRoutines.
    const uint32_t cb = VdGetGraphicsInterruptCallback();
    if(cb) {
        if(cb == kHostDefaultVdIsrMagic) {
            KernelTraceHostOp("HOST.VdCallGraphicsNotificationRoutines.host_isr");
            Mw05RunHostDefaultVdIsrNudge("vd_call");
        } else {
            uint32_t ctx = VdGetGraphicsInterruptContext();
            // Optionally override context with discovered scheduler pointer
            static const bool s_force_ctx_sched2 = []() {
                if(const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED")) return !(v[0] == '0' && v[1] == '\0');
                return false;
            }
            ();
            if(s_force_ctx_sched2) {
                uint32_t sched = Mw05Trace_LastSchedR3();
                if(GuestOffsetInRange(sched, 4)) ctx = sched;
            }
            // Gate guest ISR dispatch for a few ticks after startup to avoid early-boot crashes
            static const uint32_t s_guest_isr_delay2 = []() {
                if(const char* v = std::getenv("MW05_GUEST_ISR_DELAY_TICKS"))
                    return (uint32_t)std::strtoul(v, nullptr, 10);
                return 0u; // default: no delay unless configured
            }
            ();
            const uint32_t ticks2 = g_vblankTicks.load(std::memory_order_acquire);
            if(ticks2 < s_guest_isr_delay2) {
                KernelTraceHostOpF("HOST.VdInterruptEvent.dispatch.skip.early ticks=%u<%u (via VdCallGraphicsNotificationRoutines)", (unsigned)ticks2, (unsigned)s_guest_isr_delay2);
            } else {
                KernelTraceHostOpF("HOST.VdInterruptEvent.dispatch cb=%08X ctx=%08X (via VdCallGraphicsNotificationRoutines)", cb, ctx);

                // Monitor context structure to see what the callback is doing
                static uint32_t s_callback_count = 0;
                static const bool s_monitor_context = []() {
                    if(const char* v = std::getenv("MW05_MONITOR_GFX_CONTEXT"))
                        return !(v[0] == '0' && v[1] == '\0');
                    return true; // ENABLED BY DEFAULT for debugging
                }
                ();

                // Monitor ALL context members that the callback accesses
                struct ContextSnapshot {
                    uint32_t offset_2894;      // Structure pointer (ctx+0x2894)
                    uint32_t offset_2898;      // Spinlock (ctx+0x2898)
                    uint32_t offset_ctx_3CEC;  // Direct present fp (ctx+0x3CEC)
                    // Outer (ctx-relative) fields used by source==0 path
                    uint32_t ctx_15596_fp;     // ctx+0x3CEC (15596): function pointer
                    uint32_t ctx_15600_cnt;    // ctx+0x3D10 (15600): frame counter
                    uint32_t ctx_15604_copy;   // ctx+0x3D14 (15604): copy of frame counter
                    uint32_t ctx_15608_down;   // ctx+0x3D18 (15608): countdown
                    uint32_t ctx_15612_arg;    // ctx+0x3D1C (15612): function argument
                    // Inner structure fields (observed on some paths)
                    uint32_t offset_3CEC;      // Pending work flag (inner+0x3CEC)
                    uint32_t offset_3CF0;      // Invocation counter (inner+0x3CF0)
                    uint32_t offset_3CF4;      // Written by callback (inner+0x3CF4)
                    uint32_t offset_3CF8;      // Decrement counter (inner+0x3CF8)
                    uint32_t offset_3CFC;      // Read by callback (inner+0x3CFC)
                    // Inner fields mirroring source==0 path (if used)
                    uint32_t offs_15596_fp;    // inner+0x3CEC (15596): function pointer
                    uint32_t offs_15600_cnt;   // inner+0x3D10 (15600): frame counter
                    uint32_t offs_15604_copy;  // inner+0x3D14 (15604): copy of frame counter
                    uint32_t offs_15608_down;  // inner+0x3D18 (15608): countdown
                    uint32_t offs_15612_arg;   // inner+0x3D1C (15612): function argument
                };

                ContextSnapshot ctx_before = {};
                if(s_monitor_context && ctx) {
                    if(void* ctx_base = g_memory.Translate(ctx)) {
                        auto* ctx_u32 = reinterpret_cast<uint32_t*>(ctx_base);
                        ctx_before.offset_2894 = ctx_u32[0x2894 / 4];
                        ctx_before.offset_2898 = ctx_u32[0x2898 / 4];
                        // Also read the direct (outer) present pointer at ctx+0x3CEC
                        ctx_before.offset_ctx_3CEC = ctx_u32[0x3CEC / 4];
                        // And read outer ctx fields used by source==0 path
                        ctx_before.ctx_15596_fp  = ctx_u32[15596 / 4];
                        ctx_before.ctx_15600_cnt = ctx_u32[15600 / 4];
                        ctx_before.ctx_15604_copy = ctx_u32[15604 / 4];
                        ctx_before.ctx_15608_down = ctx_u32[15608 / 4];
                        ctx_before.ctx_15612_arg = ctx_u32[15612 / 4];
                        // Read inner structure fields if pointer is valid
                        if(GuestOffsetInRange(ctx_before.offset_2894, 4)) {
                            if(void* inner_base = g_memory.Translate(ctx_before.offset_2894)) {
                                auto* inner_u32 = reinterpret_cast<uint32_t*>(inner_base);
                                ctx_before.offset_3CEC = inner_u32[0x3CEC / 4];
                                ctx_before.offset_3CF0 = inner_u32[0x3CF0 / 4];
                                ctx_before.offset_3CF4 = inner_u32[0x3CF4 / 4];
                                ctx_before.offset_3CF8 = inner_u32[0x3CF8 / 4];
                                ctx_before.offset_3CFC = inner_u32[0x3CFC / 4];
                                // Source==0 path fields
                                ctx_before.offs_15596_fp   = inner_u32[15596 / 4];
                                ctx_before.offs_15600_cnt  = inner_u32[15600 / 4];
                                ctx_before.offs_15604_copy = inner_u32[15604 / 4];
                                ctx_before.offs_15608_down = inner_u32[15608 / 4];
                                ctx_before.offs_15612_arg  = inner_u32[15612 / 4];
                            }
                        }

                        // Only log BEFORE state if verbosity is VERBOSE
                        DEBUG_LOG_GRAPHICS(VERBOSE, "[GFX-MONITOR] BEFORE callback #%u:\n", s_callback_count);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  +0x2894 = 0x%08X (structure pointer)\n", ctx_before.offset_2894);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  +0x2898 = 0x%08X (spinlock)\n", ctx_before.offset_2898);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  ctx+0x3CEC = 0x%08X (direct present fp)\n", ctx_before.offset_ctx_3CEC);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  ctx+15596(fp) = 0x%08X\n", ctx_before.ctx_15596_fp);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  ctx+15600(cnt) = 0x%08X\n", ctx_before.ctx_15600_cnt);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  ctx+15604(copy) = 0x%08X\n", ctx_before.ctx_15604_copy);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  ctx+15608(down) = 0x%08X\n", ctx_before.ctx_15608_down);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  ctx+15612(arg) = 0x%08X\n", ctx_before.ctx_15612_arg);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+0x3CEC = 0x%08X (pending work)\n", ctx_before.offset_3CEC);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+0x3CF0 = 0x%08X (invocation counter)\n", ctx_before.offset_3CF0);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+0x3CF4 = 0x%08X\n", ctx_before.offset_3CF4);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+0x3CF8 = 0x%08X (decrement counter)\n", ctx_before.offset_3CF8);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+0x3CFC = 0x%08X\n", ctx_before.offset_3CFC);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+15596(fp) = 0x%08X\n", ctx_before.offs_15596_fp);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+15600(cnt) = 0x%08X\n", ctx_before.offs_15600_cnt);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+15604(copy) = 0x%08X\n", ctx_before.offs_15604_copy);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+15608(down) = 0x%08X\n", ctx_before.offs_15608_down);
                        DEBUG_LOG_GRAPHICS(VERBOSE, "  inner+15612(arg) = 0x%08X\n", ctx_before.offs_15612_arg);
                    }
                }

                DEBUG_LOG_GRAPHICS(VERBOSE, "[GFX-CALLBACK] About to call graphics callback cb=0x%08X ctx=0x%08X source=%u (invocation #%u)\n", cb, ctx, source, s_callback_count);
                EnsureGuestContextForThisThread("VdCallGraphicsNotificationRoutines");
                // Optional: ensure present callback pointer is set before invoking guest ISR
                static const bool s_force_present_cb = []() {
                    if(const char* v = std::getenv("MW05_SET_PRESENT_CB")) return !(v[0] == '0' && v[1] == '\0');
                    return false;
                }
                ();
                {
                    static bool s_env_logged = false;
                    if(!s_env_logged) {
                        s_env_logged = true;
                        const char* envv = std::getenv("MW05_SET_PRESENT_CB");
                        fprintf(stderr, "[GFX-CALLBACK] MW05_SET_PRESENT_CB env=%s s_force_present_cb=%d\n", envv ? envv : "<null>", (int)s_force_present_cb);
                        fflush(stderr);
                    }
                }
                // One-time: log other present-related env flags for visibility
                {
                    static bool s_env_logged2 = false;
                    if(!s_env_logged2) {
                        s_env_logged2 = true;
                        const char* env_on_zero = std::getenv("MW05_FORCE_PRESENT_ON_ZERO");
                        const char* env_every_zero = std::getenv("MW05_FORCE_PRESENT_EVERY_ZERO");
                        const char* env_fpw_once = std::getenv("MW05_FORCE_PRESENT_WRAPPER_ONCE");
                        fprintf(stderr,
                                "[GFX-CALLBACK] ENV: ON_ZERO=%s EVERY_ZERO=%s FPW_ONCE=%s\n",
                                env_on_zero ? env_on_zero : "<null>",
                                env_every_zero ? env_every_zero : "<null>",
                                env_fpw_once ? env_fpw_once : "<null>");
                        fflush(stderr);
                    }
                }


                if(s_force_present_cb && ctx) {
                    // Write present function pointer to BOTH the inner and direct ctx locations.
                    // Case A: inner = *(ctx + 0x2894); inner + 0x3CEC holds present fp (observed on some paths)
                    // Case B: ctx + 0x3CEC holds present fp directly (observed in other disassemblies)
                    if(void* ctx_base2 = g_memory.Translate(ctx)) {
                        auto* ctx_u32 = reinterpret_cast<uint32_t*>(ctx_base2);
                        const uint32_t kPresentEA = 0x82598A20u;
                        // Direct write to ctx+0x3CEC if empty
                        if(ctx_u32[0x3CEC / 4] == 0u) {
                            ctx_u32[0x3CEC / 4] = kPresentEA;


                            fprintf(stderr, "[GFX-CALLBACK] Forcing ctx present fp @+0x3CEC = %08X (pre-call)\n", kPresentEA);
                            fflush(stderr);
                        }
                        // Inner write if inner pointer valid and empty
                        const uint32_t inner_ea = ctx_u32[0x2894 / 4];
                        if(GuestOffsetInRange(inner_ea, 4)) {
                            if(void* inner_base = g_memory.Translate(inner_ea)) {
                                auto* b32 = reinterpret_cast<uint32_t*>(inner_base);
                                if(b32[0x3CEC / 4] == 0u) {
                                    b32[0x3CEC / 4] = kPresentEA;
                                    fprintf(stderr, "[GFX-CALLBACK] Forcing inner present fp @+0x3CEC = %08X (pre-call)\n", kPresentEA);
                                    fflush(stderr);
                                }
                                // Ensure argument at inner+0x3D1C (15612) is set if missing
                                if(b32[15612 / 4] == 0u) {
                                    uint32_t r3_ea = Mw05Trace_LastSchedR3();
                                    if(!GuestOffsetInRange(r3_ea, 4)) {
                                        if(const char* seed = std::getenv("MW05_SCHED_R3_EA"))
                                            r3_ea = (uint32_t)std::strtoul(seed, nullptr, 0);
                                    }
                                    if(GuestOffsetInRange(r3_ea, 4)) {
                                        b32[15612 / 4] = r3_ea;
                                        fprintf(stderr, "[GFX-CALLBACK] Forcing inner arg @+0x3D1C = %08X (pre-call)\n", r3_ea);
                                        fflush(stderr);
                                    }
                                }

                            }
                        }
                    }
                }

                // Emulate global render flag that ISR tests at 0x7FC86544 (bit0 must be set)
                // CORRECTED: The address is 0x7FC86544, not 0x7FE86544 (verified from IDA decompilation)
                static const bool s_set_render_flag = []() {
                    if(const char* v = std::getenv("MW05_SET_RENDER_FLAG")) return !(v[0] == '0' && v[1] == '\0');
                    return true; // default ON during bring-up
                }
                ();
                if(s_set_render_flag && source == 0) {
                    uint32_t ea_flag = []() {
                        if(const char* v = std::getenv("MW05_RENDER_FLAG_ADDR"))
                            return (uint32_t)std::strtoul(v, nullptr, 0);
                        return 0x7FC86544u; // CORRECTED from 0x7FE86544 (verified from IDA decompilation of sub_825979A8)
                    }
                    ();
                    if(GuestOffsetInRange(ea_flag, 4)) {
                        if(auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(ea_flag))) {
                            uint32_t prev = *p;
                            *p = prev | 1u; // set bit0
                            DEBUG_LOG_GRAPHICS(VERBOSE, "[GFX-MONITOR] Set render flag @%08X: %08X -> %08X\n", ea_flag, prev, *p);
                        } else {
                            DEBUG_LOG_GRAPHICS(MINIMAL, "[GFX-MONITOR] WARN: render flag @%08X not mapped (translate failed)\n", ea_flag);
                        }
                    } else {
                        DEBUG_LOG_GRAPHICS(MINIMAL, "[GFX-MONITOR] WARN: render flag @%08X out of guest range\n", ea_flag);
                    }
                }


                static const bool s_isr_swap2 = []() {
                    if(const char* v = std::getenv("MW05_VD_ISR_SWAP_PARAMS")) return !(v[0] == '0' && v[1] == '\0');
                    return false;
                }
                ();
                if(s_isr_swap2) {
                    KernelTraceHostOp("HOST.VdInterruptEvent.dispatch.swap r3<->r4");
                    GuestToHostFunction<void>(cb, ctx, source);
                } else {
                    GuestToHostFunction<void>(cb, source, ctx);
                }

                // CRITICAL FIX: Set the main loop flag EVERY FRAME after the VD ISR callback
                // The main loop at sub_82441CF0 waits for dword_82A2CF40 to be non-zero
                // Normally, this flag is set by a frame callback invoked by the VD ISR
                // But the frame callback pointer at context[3899] is not initialized yet
                // Solution: Set the flag directly after each VD ISR callback invocation
                // This keeps the main loop running until the game initializes the frame callback

                // DEBUG: Log to see if we reach this point
                static uint32_t s_debug_log_count = 0;
                if(s_debug_log_count < 3) {
                    fprintf(stderr, "[VD-ISR-DEBUG] After callback invocation: source=%u ctx=0x%08X\n", source, ctx);
                    fflush(stderr);
                    s_debug_log_count++;
                }

                if(source == 0) {   // Only for VBlank interrupts (source==0)
                    // DEBUG: Log to see if we reach this branch
                    static uint32_t s_debug_source0_count = 0;
                    if(s_debug_source0_count < 3) {
                        fprintf(stderr, "[VD-ISR-DEBUG] source==0 branch reached (count=%u)\n", s_debug_source0_count);
                        fflush(stderr);
                        s_debug_source0_count++;
                    }

                    // NEW FIX: Check if the game has registered a frame callback at context[3899]
                    // If so, invoke it instead of manually setting the flag
                    // This allows the game to progress naturally once it initializes the callback
                    bool frame_callback_invoked = false;
                    if(ctx && GuestOffsetInRange(ctx, 16000)) {
                        if(void* ctx_base = g_memory.Translate(ctx)) {
                            auto* ctx_u32 = reinterpret_cast<uint32_t*>(ctx_base);
                            // Check if frame callback is registered at context[3899]
#if defined(_MSC_VER)
                            const uint32_t callback_flag = _byteswap_ulong(ctx_u32[3899]);
#else
                            const uint32_t callback_flag = __builtin_bswap32(ctx_u32[3899]);
#endif

                            // DEBUG: Log callback_flag value
                            static uint32_t s_debug_callback_flag_count = 0;
                            if(s_debug_callback_flag_count < 3) {
                                fprintf(stderr, "[VD-ISR-DEBUG] callback_flag=0x%08X (count=%u)\n", callback_flag, s_debug_callback_flag_count);
                                fflush(stderr);
                                s_debug_callback_flag_count++;
                            }

                            if(callback_flag != 0) {
                                // Frame callback is registered! Log this important event
                                static bool s_logged_callback_registered = false;
                                if(!s_logged_callback_registered) {
                                    s_logged_callback_registered = true;
                                    fprintf(stderr, "[VD-ISR] FRAME CALLBACK REGISTERED! context[3899]=0x%08X\n", callback_flag);
                                    fflush(stderr);
                                    KernelTraceHostOpF("HOST.VdISR.frame_callback_registered flag=%08X", callback_flag);
                                }

                                // The game has registered a frame callback - let the VD ISR handle it naturally
                                // Don't manually set the main loop flag anymore
                                frame_callback_invoked = true;
                            }
                        }
                    }

                    // REMOVED: Manual flag-setting workaround
                    // Let the game's VBlank callback (0x82598A20) handle flag setting naturally
                }

                s_callback_count++;

                if(s_monitor_context && ctx) {
                    // Read all values after callback and compare
                    if(void* ctx_base = g_memory.Translate(ctx)) {
                        auto* ctx_u32 = reinterpret_cast<uint32_t*>(ctx_base);
                        ContextSnapshot ctx_after = {};
                        ctx_after.offset_2894 = ctx_u32[0x2894 / 4];
                        ctx_after.offset_2898 = ctx_u32[0x2898 / 4];
                        ctx_after.offset_ctx_3CEC = ctx_u32[0x3CEC / 4];
                        // Outer ctx source==0 fields
                        ctx_after.ctx_15596_fp  = ctx_u32[15596 / 4];
                        ctx_after.ctx_15600_cnt = ctx_u32[15600 / 4];
                        ctx_after.ctx_15604_copy = ctx_u32[15604 / 4];
                        ctx_after.ctx_15608_down = ctx_u32[15608 / 4];
                        ctx_after.ctx_15612_arg = ctx_u32[15612 / 4];
                        if(GuestOffsetInRange(ctx_after.offset_2894, 4)) {
                            if(void* inner_base = g_memory.Translate(ctx_after.offset_2894)) {
                                auto* inner_u32 = reinterpret_cast<uint32_t*>(inner_base);
                                ctx_after.offset_3CEC = inner_u32[0x3CEC / 4];


                                ctx_after.offset_3CF0 = inner_u32[0x3CF0 / 4];
                                ctx_after.offset_3CF4 = inner_u32[0x3CF4 / 4];
                                ctx_after.offset_3CF8 = inner_u32[0x3CF8 / 4];
                                ctx_after.offset_3CFC = inner_u32[0x3CFC / 4];
                                // Source==0 path fields
                                ctx_after.offs_15596_fp   = inner_u32[15596 / 4];
                                ctx_after.offs_15600_cnt  = inner_u32[15600 / 4];
                                ctx_after.offs_15604_copy = inner_u32[15604 / 4];
                                ctx_after.offs_15608_down = inner_u32[15608 / 4];
                                ctx_after.offs_15612_arg  = inner_u32[15612 / 4];
                            }
                        }

                        // Show changes (only log if verbosity is NORMAL or higher, or if changes detected)
                        bool any_changed = false;
                        if(ctx_before.offset_2894 != ctx_after.offset_2894) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  +0x2894: 0x%08X -> 0x%08X (structure pointer CHANGED)\n",
                                               ctx_before.offset_2894, ctx_after.offset_2894);
                            any_changed = true;
                        }
                        if(ctx_before.offset_2898 != ctx_after.offset_2898) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  +0x2898: 0x%08X -> 0x%08X (spinlock CHANGED)\n",
                                               ctx_before.offset_2898, ctx_after.offset_2898);
                            any_changed = true;
                        }
                        if(ctx_before.offset_ctx_3CEC != ctx_after.offset_ctx_3CEC) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  ctx+0x3CEC: 0x%08X -> 0x%08X (outer present fp CHANGED)\n",
                                               ctx_before.offset_ctx_3CEC, ctx_after.offset_ctx_3CEC);
                            any_changed = true;
                        }
                        if(ctx_before.ctx_15596_fp != ctx_after.ctx_15596_fp) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  ctx+15596(fp): 0x%08X -> 0x%08X\n", ctx_before.ctx_15596_fp, ctx_after.ctx_15596_fp);
                            any_changed = true;
                        }
                        if(ctx_before.ctx_15600_cnt != ctx_after.ctx_15600_cnt) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  ctx+15600(cnt): 0x%08X -> 0x%08X\n", ctx_before.ctx_15600_cnt, ctx_after.ctx_15600_cnt);
                            any_changed = true;
                        }
                        if(ctx_before.ctx_15604_copy != ctx_after.ctx_15604_copy) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  ctx+15604(copy): 0x%08X -> 0x%08X\n", ctx_before.ctx_15604_copy, ctx_after.ctx_15604_copy);
                            any_changed = true;
                        }
                        if(ctx_before.ctx_15608_down != ctx_after.ctx_15608_down) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  ctx+15608(down): 0x%08X -> 0x%08X\n", ctx_before.ctx_15608_down, ctx_after.ctx_15608_down);
                            any_changed = true;
                        }
                        if(ctx_before.ctx_15612_arg != ctx_after.ctx_15612_arg) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  ctx+15612(arg): 0x%08X -> 0x%08X\n", ctx_before.ctx_15612_arg, ctx_after.ctx_15612_arg);
                            any_changed = true;
                        }
                        if(ctx_before.offset_3CEC != ctx_after.offset_3CEC) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  inner+0x3CEC: 0x%08X -> 0x%08X (pending work CHANGED)\n",
                                               ctx_before.offset_3CEC, ctx_after.offset_3CEC);
                            any_changed = true;
                        }
                        if(ctx_before.offset_3CF0 != ctx_after.offset_3CF0) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  +0x3CF0: 0x%08X -> 0x%08X (invocation counter CHANGED)\n",
                                               ctx_before.offset_3CF0, ctx_after.offset_3CF0);
                            any_changed = true;
                        }
                        if(ctx_before.offset_3CF4 != ctx_after.offset_3CF4) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  +0x3CF4: 0x%08X -> 0x%08X (CHANGED)\n",
                                               ctx_before.offset_3CF4, ctx_after.offset_3CF4);
                            any_changed = true;
                        }
                        if(ctx_before.offset_3CF8 != ctx_after.offset_3CF8) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  +0x3CF8: 0x%08X -> 0x%08X (decrement counter CHANGED)\n",
                                               ctx_before.offset_3CF8, ctx_after.offset_3CF8);
                            any_changed = true;
                        }
                        if(ctx_before.offset_3CFC != ctx_after.offset_3CFC) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "  +0x3CFC: 0x%08X -> 0x%08X (CHANGED)\n",
                                               ctx_before.offset_3CFC, ctx_after.offset_3CFC);
                            any_changed = true;
                        }
                        if(ctx_before.offs_15596_fp != ctx_after.offs_15596_fp ||
                                ctx_before.offs_15600_cnt != ctx_after.offs_15600_cnt ||
                                ctx_before.offs_15604_copy != ctx_after.offs_15604_copy ||
                                ctx_before.offs_15608_down != ctx_after.offs_15608_down ||
                                ctx_before.offs_15612_arg != ctx_after.offs_15612_arg) {
                            DEBUG_LOG_GRAPHICS(NORMAL,
                                               "  inner+{15596,15600,15604,15608,15612}: %08X,%08X,%08X,%08X,%08X -> %08X,%08X,%08X,%08X,%08X\n",
                                               ctx_before.offs_15596_fp, ctx_before.offs_15600_cnt, ctx_before.offs_15604_copy,
                                               ctx_before.offs_15608_down, ctx_before.offs_15612_arg,
                                               ctx_after.offs_15596_fp, ctx_after.offs_15600_cnt, ctx_after.offs_15604_copy,
                                               ctx_after.offs_15608_down, ctx_after.offs_15612_arg);
                            any_changed = true;
                        }

                        // Only log "AFTER callback" header and "no changes" message if changes detected OR verbosity is VERBOSE
                        if(any_changed) {
                            DEBUG_LOG_GRAPHICS(NORMAL, "[GFX-MONITOR] AFTER callback #%u: Changes detected\n", s_callback_count - 1);
                        } else {
                            DEBUG_LOG_GRAPHICS(VERBOSE, "[GFX-MONITOR] AFTER callback #%u: No changes detected\n", s_callback_count - 1);
                        }
                    }
                }

                DEBUG_LOG_GRAPHICS(VERBOSE, "[GFX-CALLBACK] Graphics callback returned successfully (invocation #%u)\n", s_callback_count - 1);

                // Fallback: if source==0 path shows no state changes for many calls, try invoking present directly
                static const bool s_force_present_on_zero = []() {
                    if(const char* v = std::getenv("MW05_FORCE_PRESENT_ON_ZERO"))
                        return !(v[0] == '0' && v[1] == '\0');
                    return true; // default ON in bring-up
                }
                ();
                static unsigned s_zero_seen = 0;
                if(s_force_present_on_zero && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                    if(source == 0) ++s_zero_seen;  // accumulate across alternations
                    // Heuristic: every 60 zero-source callbacks, poke present
                    if(s_zero_seen != 0 && (s_zero_seen % 60u) == 0u) {
                        uint32_t ctx_fp = 0;
                        uint32_t ctx_arg = 0;
                        if(void* ctx_base = g_memory.Translate(ctx)) {
                            auto* ctx_u32 = reinterpret_cast<uint32_t*>(ctx_base);
                            ctx_fp  = ctx_u32[15596 / 4];   // ctx+0x3CEC
                            ctx_arg = ctx_u32[15612 / 4];   // ctx+0x3D1C
                        }
                        // If arg not set, fall back to tracer/env r3
                        if(!GuestOffsetInRange(ctx_arg, 4)) {
                            ctx_arg = Mw05Trace_LastSchedR3();
                            if(!GuestOffsetInRange(ctx_arg, 4)) {
                                if(const char* seed = std::getenv("MW05_SCHED_R3_EA"))
                                    ctx_arg = (uint32_t)std::strtoul(seed, nullptr, 0);
                            }
                        }
                        if(GuestOffsetInRange(ctx_arg, 4) && (ctx_fp != 0)) {
                            // ctx_fp may be byte-swapped depending on storage; detect and fix if needed
                            auto looks_code = [](uint32_t ea) {
                                return (ea & 0xFF000000u) == 0x82000000u || (ea & 0x00F00000u) == 0x00900000u;
                            };
                            uint32_t fp = ctx_fp;

                            // Optional: one-shot present on the first source==0 callback to validate pipeline
                            static const bool s_force_present_on_first_zero = []() {
                                if(const char* v = std::getenv("MW05_FORCE_PRESENT_ON_FIRST_ZERO"))
                                    return !(v[0] == '0' && v[1] == '\0');
                                return false;
                            }
                            ();
                            static bool s_present_first_zero_fired = false;
                            if(s_force_present_on_first_zero && source == 0 && !s_present_first_zero_fired && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                                uint32_t r3_ea = ctx; // default to ISR context, seems valid in our traces
                                // Prefer tracer/env if available
                                uint32_t tr = Mw05Trace_LastSchedR3();
                                if(GuestOffsetInRange(tr, 4)) r3_ea = tr;
                                if(const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
                                    uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
                                    if(GuestOffsetInRange(env_r3, 4)) r3_ea = env_r3;
                                }
                                fprintf(stderr, "[GFX-FORCE] present first-zero fp=%08X r3=%08X\n", 0x82598A20u, r3_ea);
                                fflush(stderr);
#if defined(_WIN32)
                                __try {
                                    GuestToHostFunction<void>(0x82598A20u, r3_ea, 0x40u);
                                    KernelTraceHostOp("HOST.ForcePresent.first_zero.ret");
                                } __except(EXCEPTION_EXECUTE_HANDLER) {
                                    KernelTraceHostOpF("HOST.ForcePresent.first_zero.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                }
#else
                                GuestToHostFunction<void>(0x82598A20u, r3_ea, 0x40u);
                                KernelTraceHostOp("HOST.ForcePresent.first_zero.ret");
#endif
                                s_present_first_zero_fired = true;
                            }

                            if(!looks_code(fp)) {
                                // try byte-swap
                                fp = ((ctx_fp & 0xFF) << 24) | ((ctx_fp & 0xFF00) << 8) | ((ctx_fp & 0xFF0000) >> 8) | ((ctx_fp >> 24) & 0xFF);
                            }
                            fprintf(stderr, "[GFX-FORCE] present poke fp=%08X arg=%08X (zero_seen=%u)\n", fp, ctx_arg, s_zero_seen);
                            fflush(stderr);
#if defined(_WIN32)
                            __try {
                                GuestToHostFunction<void>(fp, ctx_arg, 0x40u);
                                KernelTraceHostOp("HOST.ForcePresent.zero.poked");
                            } __except(EXCEPTION_EXECUTE_HANDLER) {
                                KernelTraceHostOpF("HOST.ForcePresent.zero.seh_abort code=%08X", (unsigned)GetExceptionCode());
                            }
#else
                            GuestToHostFunction<void>(fp, ctx_arg, 0x40u);
                            KernelTraceHostOp("HOST.ForcePresent.zero.poked");
#endif
                        }
                    }


                    // Optional: aggressively call present on every source==0 if requested
                    static const bool s_force_present_every_zero = []() {
                        if(const char* v = std::getenv("MW05_FORCE_PRESENT_EVERY_ZERO"))
                            return !(v[0] == '0' && v[1] == '\0');
                        return false;
                    }
                    ();
                    if(s_force_present_every_zero && source == 0 && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                        uint32_t ctx_fp = 0;
                        uint32_t ctx_arg = 0;
                        if(void* ctx_base = g_memory.Translate(ctx)) {
                            auto* ctx_u32 = reinterpret_cast<uint32_t*>(ctx_base);
                            ctx_fp  = ctx_u32[15596 / 4];   // ctx+0x3CEC
                            ctx_arg = ctx_u32[15612 / 4];   // ctx+0x3D1C
                        }
                        if(!GuestOffsetInRange(ctx_arg, 4)) {
                            ctx_arg = Mw05Trace_LastSchedR3();
                            if(!GuestOffsetInRange(ctx_arg, 4)) {
                                if(const char* seed = std::getenv("MW05_SCHED_R3_EA"))
                                    ctx_arg = (uint32_t)std::strtoul(seed, nullptr, 0);
                            }
                        }
                        if(GuestOffsetInRange(ctx_arg, 4)) {
                            auto looks_code = [](uint32_t ea) {
                                return (ea & 0xFF000000u) == 0x82000000u || (ea & 0x00F00000u) == 0x00900000u;
                            };
                            uint32_t fp = ctx_fp;
                            if(!looks_code(fp)) {
                                fp = ((ctx_fp & 0xFF) << 24) | ((ctx_fp & 0xFF00) << 8) | ((ctx_fp & 0xFF0000) >> 8) | ((ctx_fp >> 24) & 0xFF);
                            }
                            if(!looks_code(fp)) fp = 0x82598A20u;  // last resort: known present EA
                            fprintf(stderr, "[GFX-FORCE] present every-zero fp=%08X arg=%08X\n", fp, ctx_arg);
                            fflush(stderr);
#if defined(_WIN32)
                            __try {
                                GuestToHostFunction<void>(fp, ctx_arg, 0x40u);
                                KernelTraceHostOp("HOST.ForcePresent.every_zero.ret");
                            } __except(EXCEPTION_EXECUTE_HANDLER) {
                                KernelTraceHostOpF("HOST.ForcePresent.every_zero.seh_abort code=%08X", (unsigned)GetExceptionCode());
                            }
#else
                            GuestToHostFunction<void>(fp, ctx_arg, 0x40u);
                            KernelTraceHostOp("HOST.ForcePresent.every_zero.ret");
#endif
                        }
                    }

                    // Optional: try the one-shot present-wrapper nudge from within the ISR
                    // thread context. This more closely matches the title's expected calling
                    // environment than firing from the host pump.
                    static const bool s_force_present_wrapper_once_vd = []() {
                        if(const char* v = std::getenv("MW05_FORCE_PRESENT_WRAPPER_ONCE"))
                            return !(v[0] == '0' && v[1] == '\0');
                        return false;
                    }
                    ();
                    static bool s_present_wrapper_fired_vd = false;
                    if(s_force_present_wrapper_once_vd && !s_present_wrapper_fired_vd && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                        const uint32_t seen = Mw05Trace_SchedR3SeenCount();
                        // Derive r3 from tracer if available, otherwise allow explicit env override
                        uint32_t r3_ea = Mw05Trace_LastSchedR3();
                        if(!GuestOffsetInRange(r3_ea, 4)) {
                            if(const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
                                uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
                                if(GuestOffsetInRange(env_r3, 4)) r3_ea = env_r3;
                            }
                        }
                        if(GuestOffsetInRange(r3_ea, 4)) {
                            KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.vdcall.enter r3=%08X seen=%u", r3_ea, seen);
                            fprintf(stderr, "[FPW] enter r3=%08X seen=%u\n", r3_ea, seen);
                            fflush(stderr);
                            EnsureGuestContextForThisThread("FPWOnce.vdcall");
                            bool use_inner_vd = false;
                            if(const char* v = std::getenv("MW05_FORCE_PRESENT_INNER"))
                                use_inner_vd = !(v[0] == '0' && v[1] == '\0');
                            const uint32_t vd_target = use_inner_vd ? 0x825A54F0u : 0x82598A20u;
#if defined(_WIN32)
                            __try {
                                GuestToHostFunction<void>(vd_target, r3_ea, 0x40u);
                                KernelTraceHostOp("HOST.ForcePresentWrapperOnce.vdcall.ret");
                                // Optional: kick PM4 builder even if the wrapper returned, to see if it produces draws
                                if(const char* k = std::getenv("MW05_FPW_KICK_PM4")) {
                                    if(!(k[0] == '0' && k[1] == '\0')) {
                                        __try {
                                            GuestToHostFunction<void>(0x82595FC8u, r3_ea, 64u);
                                            KernelTraceHostOpF("HOST.FPW.vdcall.kick.pm4 r3=%08X", r3_ea);
                                        } __except(EXCEPTION_EXECUTE_HANDLER) {
                                            KernelTraceHostOpF("HOST.FPW.kick.pm4.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                        }
                                        // Also try the sibling PM4 path sub_825972B0
                                        __try {
                                            GuestToHostFunction<void>(0x825972B0u, r3_ea, 64u);
                                            KernelTraceHostOpF("HOST.FPW.vdcall.kick.pm4b r3=%08X", r3_ea);
                                        } __except(EXCEPTION_EXECUTE_HANDLER) {
                                            KernelTraceHostOpF("HOST.FPW.kick.pm4b.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                        }
                                    }
                                }
                                s_present_wrapper_fired_vd = true;
                            } __except(EXCEPTION_EXECUTE_HANDLER) {
                                KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.vdcall.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                // Fallback on vdcall fault: try inner present-manager and PM4 kick
                                if(GuestOffsetInRange(r3_ea, 4)) {
                                    __try {
                                        GuestToHostFunction<void>(0x825A54F0u, r3_ea, 0x40u);
                                        KernelTraceHostOp("HOST.FPW.vdcall.fallback.inner.ret");
                                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                                        KernelTraceHostOpF("HOST.FPW.vdcall.fallback.inner.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                    }
                                    if(const char* k = std::getenv("MW05_FPW_KICK_PM4")) {
                                        if(!(k[0] == '0' && k[1] == '\0')) {
                                            __try {
                                                GuestToHostFunction<void>(0x82595FC8u, r3_ea, 64u);
                                                KernelTraceHostOpF("HOST.FPW.vdcall.kick.pm4 r3=%08X", r3_ea);
                                            } __except(EXCEPTION_EXECUTE_HANDLER) {
                                                KernelTraceHostOpF("HOST.FPW.vdcall.kick.pm4.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                            }
                                        }
                                    }
                                }
                                s_present_wrapper_fired_vd = true; // avoid repeated faults
                            }
#else
                            GuestToHostFunction<void>(0x82598A20u, r3_ea, 0x40u);
                            KernelTraceHostOp("HOST.ForcePresentWrapperOnce.vdcall.ret");
                            s_present_wrapper_fired_vd = true;
#endif
                        } else {
                            KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.vdcall.defer r3_unsuitable seen=%u", seen);
                            fprintf(stderr, "[FPW] defer r3_unsuitable seen=%u env_r3=%s\n", seen, std::getenv("MW05_SCHED_R3_EA"));
                            fflush(stderr);
                        }
                    }
                }
            }
        }
        // If no callback is registered, emit a trace for visibility.
        if(!cb) {
            const char* f = std::getenv("MW05_FORCE_VD_ISR");
            if(f && !(f[0] == '0' && f[1] == '\0')) {
                KernelTraceHostOp("HOST.VdCallGraphicsNotificationRoutines.forced.no_cb");
            } else {
                KernelTraceHostOp("HOST.VdCallGraphicsNotificationRoutines.no_cb");
            }
        }

        // APPROACH C: Periodically call present function directly from ISR
        // This bypasses the render thread entirely and calls the present function on every N source==0 callbacks
        static const bool s_isr_call_present = []() {
            if(const char* v = std::getenv("MW05_ISR_CALL_PRESENT")) return !(v[0] == '0' && v[1] == '\0');
            return false;
        }
        ();
        static const uint32_t s_isr_present_interval = []() {
            if(const char* v = std::getenv("MW05_ISR_PRESENT_INTERVAL"))
                return (uint32_t)std::strtoul(v, nullptr, 10);
            return 60u; // default: every 60 source==0 callbacks (~1 second at 60Hz)
        }
        ();
        static uint32_t s_isr_present_counter = 0;
        static bool s_isr_present_debug_once = false;
        // IMPORTANT: Don't check g_sawRealVdSwap here because VdSwap sets it even when called by our force-present logic
        // We want to keep calling present until we actually see draw commands being issued
        if(s_isr_call_present && source == 0) {
            if(!s_isr_present_debug_once) {
                fprintf(stderr, "[ISR-PRESENT-DEBUG] Enabled, interval=%u\n", s_isr_present_interval);
                fflush(stderr);
                s_isr_present_debug_once = true;
            }
            s_isr_present_counter++;
            if(s_isr_present_counter >= s_isr_present_interval) {
                s_isr_present_counter = 0;

                // CRITICAL FIX: Use heap-allocated graphics context instead of static globals
                // Following Xenia's approach: the graphics device structure pointer is at context+0x2894
                uint32_t r31_ea = 0;
                uint32_t gfx_ctx = g_graphics_context_ea;
                if(gfx_ctx == 0) {
                    fprintf(stderr, "[ISR-PRESENT] Graphics context not allocated yet\n");
                    fflush(stderr);
                    return;
                }

                // Load the structure pointer from context+0x2894
                if(auto* ctx_ptr = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(gfx_ctx + 0x2894))) {
                    r31_ea = ctx_ptr->get();
                    fprintf(stderr, "[ISR-PRESENT-DEBUG] Loaded r31=0x%08X from heap context+0x2894 (ctx=0x%08X)\n", r31_ea, gfx_ctx);
                    fflush(stderr);
                }

                if(r31_ea == 0 || r31_ea < 0x1000 || r31_ea >= 0x90000000) {
                    fprintf(stderr, "[ISR-PRESENT] Invalid graphics device structure pointer r31=0x%08X (not initialized yet?)\n", r31_ea);
                    fflush(stderr);
                    return;
                }

                // Get r4 = Load32(r31 + 13976)
                uint32_t r4_ea = 0;
                if(auto* r4_ptr = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(r31_ea + 13976))) {
                    r4_ea = r4_ptr->get();
                }

                fprintf(stderr, "[ISR-PRESENT] Calling present function fp=0x82598A20 r3=0x%08X r4=0x%08X r5=0 (interval=%u)\n", r31_ea, r4_ea, s_isr_present_interval);
                fflush(stderr);

#if defined(_WIN32)
                __try {
                    GuestToHostFunction<void>(0x82598A20u, r31_ea, r4_ea, 0u);
                    KernelTraceHostOp("HOST.ISR.CallPresent.ret");
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    KernelTraceHostOpF("HOST.ISR.CallPresent.seh_abort code=%08X", (unsigned)GetExceptionCode());
                    fprintf(stderr, "[ISR-PRESENT] Exception 0x%08X calling present function\n", (unsigned)GetExceptionCode());
                    fflush(stderr);
                }
#else
                GuestToHostFunction<void>(0x82598A20u, r31_ea, r4_ea, 0u);
                KernelTraceHostOp("HOST.ISR.CallPresent.ret");
#endif
            }
        }
    }

// Ensure function scope is closed (balance safety)
}


void VdInitializeScalerCommandBuffer()
{
    KernelTraceHostOp("HOST.VdInitializeScalerCommandBuffer");
    // Ensure system command buffer exists and has a GPU identifier address
    VdGetSystemCommandBuffer(nullptr, nullptr);
    // No specific scaler commands required in our host path; treat as success.
    KernelTraceHostOp("HOST.VdInitializeScalerCommandBuffer.done");
}

void KeLeaveCriticalRegion()
{
    // KeEnterCriticalRegion/KeLeaveCriticalRegion disable/enable normal kernel APCs
    // This prevents the thread from being suspended during critical operations
    // On Xbox 360, this is used to protect critical sections from APC delivery

    // For our recompilation, we don't have a real APC mechanism, so this is a no-op
    // The game uses this to protect critical sections, but we handle that with
    // RtlEnterCriticalSection/RtlLeaveCriticalSection instead

    // No-op: APC delivery control is not needed in our host environment
}

uint32_t VdRetrainEDRAM()
{
    return 0;
}

void VdRetrainEDRAMWorker()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KeEnterCriticalRegion()
{
    // KeEnterCriticalRegion disables normal kernel APCs for the current thread
    // This is paired with KeLeaveCriticalRegion to protect critical code sections

    // For our recompilation, we don't have a real APC mechanism, so this is a no-op
    // The game uses this to protect critical sections, but we handle that with
    // RtlEnterCriticalSection/RtlLeaveCriticalSection instead

    // No-op: APC delivery control is not needed in our host environment
}

uint32_t MmAllocatePhysicalMemoryEx
(
    uint32_t flags,
    uint32_t size,
    uint32_t protect,
    uint32_t minAddress,
    uint32_t maxAddress,
    uint32_t alignment
)
{
    LOGF_UTILITY("0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}", flags, size, protect, minAddress, maxAddress, alignment);

    // PERFORMANCE: Heap debug logging (disabled by default - causes FPS drop)
    static const bool s_debug_heap = [](){
        if (const char* v = std::getenv("MW05_DEBUG_HEAP"))
            return !(v[0]=='0' && v[1]=='\0');
        return false; // DISABLED by default for performance
    }();

    if (s_debug_heap) {
        fprintf(stderr, "[MmAllocPhysicalMemEx] ENTRY: size=%u (%.2f MB) align=%u flags=%08X min=%08X max=%08X\n",
                size, size / (1024.0 * 1024.0), alignment, flags, minAddress, maxAddress);
        fflush(stderr);
    }

    void* ptr = g_userHeap.AllocPhysical(size, alignment);
    uint32_t result = g_memory.MapVirtual(ptr);

    if (result == 0) {
        // Always log allocation failures (critical errors)
        fprintf(stderr, "[MmAllocPhysicalMemEx] FAILED: AllocPhysical returned NULL for size=%u (%.2f MB)\n",
                size, size / (1024.0 * 1024.0));
        fflush(stderr);
    } else {
        // CRITICAL FIX: DO NOT zero-initialize allocated memory!
        // The heap allocator already manages this memory, and zeroing it will corrupt the heap metadata.
        // Zeroing here was causing heap corruption because we were zeroing memory that contains
        // internal data structures (page table, etc.)
        //
        // memset(ptr, 0, size);  // THIS WAS CORRUPTING THE HEAP!

        if (s_debug_heap) {
            fprintf(stderr, "[MmAllocPhysicalMemEx] SUCCESS: allocated %u bytes (%.2f MB) at guest=%08X host=%p\n",
                    size, size / (1024.0 * 1024.0), result, ptr);
            fflush(stderr);

            // TRACE: Log small allocations that might be context structures
            if (size >= 12 && size <= 64) {
                fprintf(stderr, "[CONTEXT-TRACE] Small allocation: size=%u guest=%08X (might be context structure)\n",
                        size, result);
                fflush(stderr);
            }
        }
    }

    return result;
}

void ObDeleteSymbolicLink()
{
    LOG_UTILITY("!!! STUB !!!");
}

void ObCreateSymbolicLink()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t MmQueryAddressProtect(uint32_t guestAddress)
{
    return PAGE_READWRITE;
}

void VdEnableDisableClockGating()
{
    // Titles call this during bring-up; no effect needed on host
    KernelTraceHostOp("HOST.VdEnableDisableClockGating");
}

// KeBugCheck handled earlier; avoid duplicate definition.

void KeLockL2()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KeUnlockL2()
{
    LOG_UTILITY("!!! STUB !!!");
}

bool KeSetEvent(XKEVENT* pEvent, uint32_t Increment, bool Wait)
{
    if (const char* t = std::getenv("MW05_TRACE_KERNEL"); t && t[0] && !(t[0]=='0' && t[1]==0))
    {
        LOGFN("[ke.set] obj=0x{:08X} type={} state={}", g_memory.MapVirtual(pEvent), (unsigned)pEvent->Type, (unsigned)pEvent->SignalState);
    }
    // Reflect signaled state in the guest-visible header so code that polls
    // XDISPATCHER_HEADER::SignalState observes progress.
    pEvent->SignalState = 1;
    bool result = QueryKernelObject<Event>(*pEvent)->Set();

    ++g_keSetEventGeneration;
    g_keSetEventGeneration.notify_all();

    return result;
}

bool KeResetEvent(XKEVENT* pEvent)
{
    if (const char* t = std::getenv("MW05_TRACE_KERNEL"); t && t[0] && !(t[0]=='0' && t[1]==0))
    {
        LOGFN("[ke.reset] obj=0x{:08X} type={} state={}", g_memory.MapVirtual(pEvent), (unsigned)pEvent->Type, (unsigned)pEvent->SignalState);
    }
    // Reflect reset in the guest-visible header.
    pEvent->SignalState = 0;
    return QueryKernelObject<Event>(*pEvent)->Reset();
}

static std::vector<size_t> g_tlsFreeIndices;
static size_t g_tlsNextIndex = 0;
static Mutex g_tlsAllocationMutex;

static uint32_t& KeTlsGetValueRef(size_t index)
{
    // FIXED: Use fixed-size array instead of std::vector to avoid debug build assertions
    // Xbox 360 supports up to 1088 TLS slots (0x440), but we'll use 256 for safety
    constexpr size_t MAX_TLS_SLOTS = 256;
    thread_local std::array<uint32_t, MAX_TLS_SLOTS> s_tlsValues{};

    // Bounds check - if index is out of range, return a dummy value
    // This prevents crashes but logs an error (only once per unique index to reduce spam)
    if (index >= MAX_TLS_SLOTS)
    {
        static thread_local uint32_t s_dummyValue = 0;

        // Only log unique invalid indices to avoid spam (951 errors -> massive FPS drops!)
        static std::unordered_set<size_t> s_loggedIndices;
        static std::mutex s_logMutex;

        {
            std::lock_guard<std::mutex> lock(s_logMutex);
            if (s_loggedIndices.insert(index).second) {
                fprintf(stderr, "[KeTlsGetValueRef] ERROR: TLS index %zu (0x%zX) exceeds MAX_TLS_SLOTS (%zu) - FIRST OCCURRENCE\n",
                        index, index, MAX_TLS_SLOTS);
                fflush(stderr);
            }
        }

        return s_dummyValue;
    }

    return s_tlsValues[index];
}

uint32_t KeTlsGetValue(uint32_t dwTlsIndex)
{
    // CRITICAL FIX: The game loads TLS index from 0x828F2910 which contains garbage (0x69D7401B)
    // This is likely an uninitialized global variable or memory corruption
    // For now, treat obviously invalid indices (> 1088) as index 0 to prevent spam and crashes
    if (dwTlsIndex > 1088) {
        // Log this once for debugging
        static std::atomic<bool> s_logged{false};
        if (!s_logged.exchange(true)) {
            fprintf(stderr, "[KeTlsGetValue] WARNING: Invalid TLS index %u (0x%08X) - treating as index 0\n",
                    dwTlsIndex, dwTlsIndex);
            fprintf(stderr, "[KeTlsGetValue] This is likely from uninitialized global at 0x828F2910\n");
            fflush(stderr);
        }
        dwTlsIndex = 0;  // Use index 0 as fallback
    }

    return KeTlsGetValueRef(dwTlsIndex);
}

uint32_t KeTlsSetValue(uint32_t dwTlsIndex, uint32_t lpTlsValue)
{
    KeTlsGetValueRef(dwTlsIndex) = lpTlsValue;
    return TRUE;
}

uint32_t KeTlsAlloc()
{
    std::lock_guard<Mutex> lock(g_tlsAllocationMutex);
    if (!g_tlsFreeIndices.empty())
    {
        size_t index = g_tlsFreeIndices.back();
        g_tlsFreeIndices.pop_back();
        return index;
    }

    return g_tlsNextIndex++;
}

uint32_t KeTlsFree(uint32_t dwTlsIndex)
{
    std::lock_guard<Mutex> lock(g_tlsAllocationMutex);
    g_tlsFreeIndices.push_back(dwTlsIndex);
    return TRUE;
}

uint32_t XMsgInProcessCall(uint32_t app, uint32_t message, be<uint32_t>* param1, be<uint32_t>* param2)
{
    if (message == 0x7001B)
    {
        uint32_t* ptr = (uint32_t*)g_memory.Translate(param1[1]);
        ptr[0] = 0;
        ptr[1] = 0;
    }

    return 0;
}

void XamUserReadProfileSettings
(
    uint32_t titleId,
    uint32_t userIndex,
    uint32_t xuidCount,
    uint64_t* xuids,
    uint32_t settingCount,
    uint32_t* settingIds,
    be<uint32_t>* bufferSize,
    void* buffer,
    void* overlapped
)
{
    fprintf(stderr, "[PROFILE-READ] titleId=%08X userIndex=%u xuidCount=%u settingCount=%u bufferSize=%u buffer=%p\n",
            titleId, userIndex, xuidCount, settingCount, bufferSize ? (uint32_t)*bufferSize : 0, buffer);

    // Log setting IDs being requested
    if (settingIds && settingCount > 0) {
        fprintf(stderr, "[PROFILE-READ] Requested settings:");
        for (uint32_t i = 0; i < settingCount && i < 10; i++) {
            fprintf(stderr, " %08X", settingIds[i]);
        }
        fprintf(stderr, "\n");
    }

    if (buffer != nullptr)
    {
        memset(buffer, 0, *bufferSize);
        fprintf(stderr, "[PROFILE-READ] -> cleared buffer\n");
    }
    else
    {
        *bufferSize = 4;
        fprintf(stderr, "[PROFILE-READ] -> set bufferSize=4\n");
    }
}

void NetDll_WSAStartup()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_WSACleanup()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_socket()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_closesocket()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_setsockopt()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_bind()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_connect()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_listen()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_accept()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_select()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_recv()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_send()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_inet_addr()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll___WSAFDIsSet()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t XMsgStartIORequestEx(uint32_t App, uint32_t Message, XXOVERLAPPED* lpOverlapped, void* Buffer, uint32_t szBuffer)
{
    // Alias to base implementation; some titles call Ex variant.
    return XMsgStartIORequest(App, Message, lpOverlapped, Buffer, szBuffer);
}

// Minimal XexGetModuleHandle implementation
// Prototype (Xbox360): NTSTATUS XexGetModuleHandle(const char* name, uint32_t* handle)
// Behavior: if name is null, return the current executable module handle; otherwise, return the same handle for any name to keep titles happy.
uint32_t XexGetModuleHandle(const char* name, be<uint32_t>* outHandle)
{
    // Our loader maps a single executable; use a fixed pseudo-handle for now.
    constexpr uint32_t kCurrentModuleHandle = 0x80000001u; // guest-style tagged handle

    if (!name || name[0] == '\0') {
        if (outHandle) *outHandle = kCurrentModuleHandle;
        KernelTraceHostOp("HOST.XexGetModuleHandle current -> SUCCESS");
        return 0; // STATUS_SUCCESS
    }

    // Accept any name and return the current module's handle (some titles pass the image name)
    if (outHandle) *outHandle = kCurrentModuleHandle;
    KernelTraceHostOpF("HOST.XexGetModuleHandle name=\"%s\" -> SUCCESS (alias current)", name);
    return 0; // STATUS_SUCCESS
}

bool RtlTryEnterCriticalSection(XRTL_CRITICAL_SECTION* cs)
{
    // Tolerate null/invalid critical sections during early boot
    if (!cs)
        return true; // nothing to lock
    auto* p = reinterpret_cast<uint8_t*>(cs);
    if (p < g_memory.base || p >= (g_memory.base + PPC_MEMORY_SIZE))
        return true; // ignore invalid guest pointers

    uint32_t thisThread = 0;
    if (auto* ctx = GetPPCContext())
        thisThread = ctx->r13.u32;
    if (thisThread == 0)
        thisThread = 1; // fallback owner id if TLS not yet established

    uint32_t owner = cs->OwningThread;
    if (owner == 0 || owner == thisThread)
    {
        if (owner == 0)
            cs->OwningThread = thisThread;
        cs->RecursionCount++;
        cs->LockCount = (cs->LockCount < -1) ? -1 : cs->LockCount; // clamp
        cs->LockCount++;
        return true;
    }

    return false;
}

void RtlInitializeCriticalSectionAndSpinCount(XRTL_CRITICAL_SECTION* cs, uint32_t spinCount)
{
    cs->Header.Absolute = (spinCount + 255) >> 8;
    cs->LockCount = -1;
    cs->RecursionCount = 0;
    cs->OwningThread = 0;
}

void _vswprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void _vscwprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void _swprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void _snwprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XeCryptBnQwBeSigVerify()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XeKeysGetKey()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XeCryptRotSumSha()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XeCryptSha()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KeEnableFpuExceptions()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlUnwind_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlCaptureContext_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NtQueryFullAttributesFile()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t RtlMultiByteToUnicodeN(be<uint16_t>* UnicodeString, uint32_t MaxBytesInUnicodeString, be<uint32_t>* BytesInUnicodeString, const char* MultiByteString, uint32_t BytesInMultiByteString)
{
    uint32_t length = std::min(MaxBytesInUnicodeString / 2, BytesInMultiByteString);

    for (size_t i = 0; i < length; i++)
        UnicodeString[i] = MultiByteString[i];

    if (BytesInUnicodeString != nullptr)
        *BytesInUnicodeString = length * 2;

    return STATUS_SUCCESS;
}

void DbgBreakPoint()
{
    // No-op: this import is hit frequently; logging here floods output.
    // Enable logging only when explicitly requested via MW05_LOG_DBG_BREAK=1.
    static bool sLog = [](){ const char* v = std::getenv("MW05_LOG_DBG_BREAK"); return v && v[0] && !(v[0]=='0' && v[1]==0); }();
    if (sLog) {
        LOG_UTILITY("DbgBreakPoint()");
    }
}

void MmQueryAllocationSize()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t NtClearEvent(Event* handle, uint32_t* previousState)
{
    handle->Reset();
    return 0;
}

uint32_t NtResumeThread(GuestThreadHandle* hThread, uint32_t* suspendCount)
{
    assert(hThread != GetKernelObject(CURRENT_THREAD_HANDLE));

    // PERFORMANCE: Thread debug logging (disabled by default - causes FPS drop)
    static const bool s_debug_thread = [](){
        if (const char* v = std::getenv("MW05_DEBUG_THREAD"))
            return !(v[0]=='0' && v[1]=='\0');
        return false; // DISABLED by default for performance
    }();

    // Log first 10 thread resumes only
    static int s_resume_count = 0;
    if (s_debug_thread || s_resume_count < 10) {
        fprintf(stderr, "[MW05_FIX] NtResumeThread called: handle=%p tid=%08X\n",
            (void*)hThread, hThread ? hThread->GetThreadId() : 0);
        fflush(stderr);
    }
    s_resume_count++;

    if (s_debug_thread) {
        KernelTraceHostOpF("HOST.NtResumeThread tid=%08X", hThread ? hThread->GetThreadId() : 0);
    }

    // CRITICAL FIX: Set qword_828F1F98 BEFORE resuming ANY thread
    // Thread #2 checks this value immediately upon starting, so it must be set before ANY thread resumes
    // We set it EVERY time to ensure it's always correct, even if it gets corrupted
    const uint32_t qword_addr = 0x828F1F98;
    void* qword_ptr = g_memory.Translate(qword_addr);
    if (qword_ptr) {
        // Calculate: divwu r9, 0xFF676980, 0x64 (100 decimal)
        // CRITICAL FIX: Use UNSIGNED division, not signed!
        // 0xFF676980 = 4284967296 (unsigned) / 100 = 42849672 (0x028E0A78)
        const uint32_t dividend = 0xFF676980;
        const uint32_t divisor = 100;
        const uint64_t result = (uint64_t)dividend / (uint64_t)divisor;

        uint64_t* qword = (uint64_t*)qword_ptr;
        uint64_t old_value = __builtin_bswap64(*qword);
        uint64_t value_be = __builtin_bswap64(result);
        *qword = value_be;

        if (s_debug_thread || s_resume_count <= 10) {
            fprintf(stderr, "[MW05_FIX] NtResumeThread: Set qword_828F1F98 to 0x%016llX (was 0x%016llX) tid=%08X\n",
                    result, old_value, hThread->GetThreadId());
            fflush(stderr);
        }
    }

    hThread->suspended = false;
    hThread->suspended.notify_all();

    if (s_debug_thread || s_resume_count <= 10) {
        fprintf(stderr, "[MW05_FIX] NtResumeThread: thread resumed, tid=%08X\n",
            hThread->GetThreadId());
        fflush(stderr);
    }

    return S_OK;
}

uint32_t NtSetEvent(Event* handle, uint32_t* previousState)
{
    handle->Set();
    return 0;
}

uint32_t NtCreateSemaphore(be<uint32_t>* Handle, XOBJECT_ATTRIBUTES* ObjectAttributes, uint32_t InitialCount, uint32_t MaximumCount)
{
    *Handle = GetKernelHandle(CreateKernelObject<Semaphore>(InitialCount, MaximumCount));
    return STATUS_SUCCESS;
}

uint32_t NtReleaseSemaphore(Semaphore* Handle, uint32_t ReleaseCount, int32_t* PreviousCount)
{
    uint32_t previousCount;
    Handle->Release(ReleaseCount, &previousCount);

    if (PreviousCount != nullptr)
        *PreviousCount = ByteSwap(previousCount);

    return STATUS_SUCCESS;
}

// Timer functions
uint32_t NtCreateTimer(be<uint32_t>* Handle, XOBJECT_ATTRIBUTES* ObjectAttributes, uint32_t TimerType)
{
    fprintf(stderr, "[NtCreateTimer] CALLED: TimerType=%u\n", TimerType);
    fflush(stderr);

    if (!Handle)
        return STATUS_INVALID_PARAMETER;

    // TimerType: 0 = NotificationTimer (manual reset), 1 = SynchronizationTimer (auto reset)
    bool manualReset = (TimerType == 0);
    *Handle = GetKernelHandle(CreateKernelObject<Timer>(manualReset));

    fprintf(stderr, "[NtCreateTimer] Created timer handle=0x%08X manualReset=%d\n", (uint32_t)*Handle, manualReset);
    fflush(stderr);

    return STATUS_SUCCESS;
}

uint32_t NtSetTimerEx(Timer* Handle, be<int64_t>* DueTime, uint32_t Period, uint32_t ApcRoutine, uint32_t ApcContext, uint32_t Resume, uint32_t PreviousState, be<uint32_t>* State)
{
    // NtSetTimerEx sets a timer to fire at a specific time or after a specific interval
    // DueTime: Pointer to a 64-bit value specifying when the timer should fire
    //   - Negative values: relative time (in 100-nanosecond units)
    //   - Positive values: absolute time
    // Period: If non-zero, the timer is periodic and fires every Period milliseconds
    // The game uses this to create a periodic timer that fires repeatedly

    if (!Handle) {
        // Handle is NULL - nothing to do
        return STATUS_SUCCESS;
    }

    // Signal the timer immediately
    // The game expects the timer to fire periodically, so we just signal it
    // The worker thread will wake up, process work items, and call NtSetTimerEx again
    Handle->Set();

    if (State)
        *State = 1; // Timer is now signaled

    return STATUS_SUCCESS;
}

uint32_t NtCancelTimer(Timer* Handle, be<uint32_t>* CurrentState)
{
    if (!Handle)
        return STATUS_INVALID_HANDLE;

    Handle->Reset();

    if (CurrentState)
        *CurrentState = 0; // Timer is now not signaled

    return STATUS_SUCCESS;
}

// Mutant (Mutex) functions
uint32_t NtCreateMutant(be<uint32_t>* Handle, XOBJECT_ATTRIBUTES* ObjectAttributes, uint32_t InitialOwner)
{
    if (!Handle)
        return STATUS_INVALID_PARAMETER;

    auto* mutant = CreateKernelObject<Mutant>();

    // If InitialOwner is true, the creating thread owns the mutex
    if (InitialOwner)
    {
        mutant->ownerThreadId = GuestThread::GetCurrentThreadId();
        mutant->recursionCount = 1;
    }

    *Handle = GetKernelHandle(mutant);
    return STATUS_SUCCESS;
}

uint32_t NtReleaseMutant(Mutant* Handle, be<uint32_t>* PreviousCount)
{
    if (!Handle)
        return STATUS_INVALID_HANDLE;

    if (PreviousCount)
        *PreviousCount = Handle->recursionCount.load();

    Handle->Release();
    return STATUS_SUCCESS;
}

// I/O Completion functions
uint32_t NtCreateIoCompletion(be<uint32_t>* Handle, XOBJECT_ATTRIBUTES* ObjectAttributes, uint32_t NumberOfConcurrentThreads)
{
    if (!Handle)
        return STATUS_INVALID_PARAMETER;

    *Handle = GetKernelHandle(CreateKernelObject<IoCompletion>());
    return STATUS_SUCCESS;
}

uint32_t NtSetIoCompletion(IoCompletion* Handle, uint32_t KeyContext, uint32_t ApcContext, uint32_t IoStatus, uint32_t IoStatusInformation)
{
    if (!Handle)
        return STATUS_INVALID_HANDLE;

    Handle->Post(KeyContext, ApcContext, IoStatus, IoStatusInformation);
    return STATUS_SUCCESS;
}

uint32_t NtRemoveIoCompletion(IoCompletion* Handle, be<uint32_t>* KeyContext, be<uint32_t>* ApcContext, XIO_STATUS_BLOCK* IoStatusBlock, be<int64_t>* Timeout)
{
    if (!Handle || !KeyContext || !ApcContext || !IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    uint32_t timeout_ms = INFINITE;
    if (Timeout)
    {
        int64_t timeout_100ns = Timeout->get();
        if (timeout_100ns < 0)
        {
            // Relative timeout (negative value in 100ns units)
            timeout_ms = static_cast<uint32_t>((-timeout_100ns) / 10000);
        }
        else if (timeout_100ns == 0)
        {
            timeout_ms = 0;
        }
        else
        {
            // Absolute timeout - not fully supported, use infinite
            timeout_ms = INFINITE;
        }
    }

    IoCompletion::CompletionPacket packet;
    if (Handle->Remove(packet, timeout_ms))
    {
        *KeyContext = packet.key;
        *ApcContext = packet.value;
        IoStatusBlock->Status = packet.status;
        IoStatusBlock->Information = packet.information;
        return STATUS_SUCCESS;
    }

    return STATUS_TIMEOUT;
}

// Event functions
uint32_t NtPulseEvent(Event* Handle, be<uint32_t>* PreviousState)
{
    if (!Handle)
        return STATUS_INVALID_HANDLE;

    // Pulse: briefly signal then reset
    Handle->Set();
    Handle->Reset();

    if (PreviousState)
        *PreviousState = 0;

    return STATUS_SUCCESS;
}

// Thread functions
uint32_t NtQueueApcThread(uint32_t ThreadHandle, uint32_t ApcRoutine, uint32_t ApcContext, uint32_t Argument1, uint32_t Argument2)
{
    // Get the thread object
    auto* hThread = GetKernelObject<GuestThreadHandle>(ThreadHandle);
    if (!hThread) {
        KernelTraceHostOpF("HOST.NtQueueApcThread INVALID_HANDLE handle=%08X", ThreadHandle);
        return STATUS_INVALID_HANDLE;
    }

    uint32_t threadId = hThread->GetThreadId();

    // Queue the APC
    {
        std::lock_guard<std::mutex> lock(g_apcMutex);
        ApcEntry apc{ApcRoutine, ApcContext, Argument1, Argument2};
        g_apcQueues[threadId].push(apc);

        KernelTraceHostOpF("HOST.NtQueueApcThread tid=%08X routine=%08X ctx=%08X arg1=%08X arg2=%08X queued=%u",
                          threadId, ApcRoutine, ApcContext, Argument1, Argument2,
                          (unsigned)g_apcQueues[threadId].size());

        // Log to stderr for debugging
        static uint32_t s_apc_log_count = 0;
        if (s_apc_log_count < 10) {
            fprintf(stderr, "[APC] Queued APC for thread %08X: routine=%08X ctx=%08X (queue size=%u)\n",
                    threadId, ApcRoutine, ApcContext, (unsigned)g_apcQueues[threadId].size());
            fflush(stderr);
            s_apc_log_count++;
        }
    }

    // Wake up the thread if it's sleeping in an alertable state
    // The thread will check for pending APCs when it wakes up
    hThread->suspended.notify_all();

    return STATUS_SUCCESS;
}

// Check if there are pending APCs for the current thread
bool ApcPendingForCurrentThread()
{
    uint32_t threadId = GuestThread::GetCurrentThreadId();

    std::lock_guard<std::mutex> lock(g_apcMutex);
    auto it = g_apcQueues.find(threadId);
    if (it != g_apcQueues.end() && !it->second.empty()) {
        return true;
    }
    return false;
}

// Process pending APCs for the current thread
// Returns true if any APCs were processed
bool ProcessPendingApcs()
{
    uint32_t threadId = GuestThread::GetCurrentThreadId();

    // Get the next APC from the queue
    ApcEntry apc;
    {
        std::lock_guard<std::mutex> lock(g_apcMutex);
        auto it = g_apcQueues.find(threadId);
        if (it == g_apcQueues.end() || it->second.empty()) {
            return false;  // No pending APCs
        }

        apc = it->second.front();
        it->second.pop();

        KernelTraceHostOpF("HOST.ProcessPendingApcs tid=%08X routine=%08X ctx=%08X remaining=%u",
                          threadId, apc.routine, apc.context, (unsigned)it->second.size());

        // Log to stderr for debugging
        static uint32_t s_apc_process_log_count = 0;
        if (s_apc_process_log_count < 10) {
            fprintf(stderr, "[APC] Processing APC for thread %08X: routine=%08X ctx=%08X (remaining=%u)\n",
                    threadId, apc.routine, apc.context, (unsigned)it->second.size());
            fflush(stderr);
            s_apc_process_log_count++;
        }
    }

    // Call the APC routine
    // The APC routine signature is: void ApcRoutine(uint32_t ApcContext, uint32_t Argument1, uint32_t Argument2)
    if (apc.routine != 0) {
        // Set up PPC context for the call
        PPCContext ctx{};
        if (auto* cur = GetPPCContext()) {
            ctx = *cur;
        } else {
            // Initialize a minimal context if none exists
            ctx.r1.u32 = 0x7FEA0000;  // Stack pointer
        }

        // Set up parameters
        ctx.r3.u32 = apc.context;
        ctx.r4.u32 = apc.arg1;
        ctx.r5.u32 = apc.arg2;

        // Find the function in the function table
        uint8_t* base = g_memory.base;

        // Calculate the function pointer from the function table
        // The function table is stored after the image data at base + PPC_IMAGE_SIZE
        // Each entry is a pointer to a function (PPCFunc*)
        const uint32_t offset_from_code_base = apc.routine - PPC_CODE_BASE;
        PPCFunc** func_table = reinterpret_cast<PPCFunc**>(base + PPC_IMAGE_SIZE);
        PPCFunc* func_ptr = func_table[offset_from_code_base];

        if (func_ptr && *func_ptr) {
            KernelTraceHostOpF("HOST.ProcessPendingApcs.call routine=%08X ctx=%08X", apc.routine, apc.context);

            // Call the APC routine
            SetPPCContext(ctx);
            (*func_ptr)(ctx, base);

            KernelTraceHostOpF("HOST.ProcessPendingApcs.return routine=%08X", apc.routine);
        } else {
            KernelTraceHostOpF("HOST.ProcessPendingApcs.NULL_FUNC routine=%08X", apc.routine);
            fprintf(stderr, "[APC] ERROR: APC routine %08X not found in function table!\n", apc.routine);
            fflush(stderr);
        }
    }

    return true;  // APC was processed
}

uint32_t NtSignalAndWaitForSingleObjectEx(uint32_t SignalHandle, uint32_t WaitHandle, uint32_t Alertable, be<int64_t>* Timeout)
{
    // Signal the first object
    if (IsKernelObject(SignalHandle))
    {
        auto* signalObj = GetKernelObject<KernelObject>(SignalHandle);
        if (auto* event = dynamic_cast<Event*>(signalObj))
        {
            event->Set();
        }
        else if (auto* semaphore = dynamic_cast<Semaphore*>(signalObj))
        {
            uint32_t prev;
            semaphore->Release(1, &prev);
        }
        else if (auto* mutant = dynamic_cast<Mutant*>(signalObj))
        {
            mutant->Release();
        }
    }

    // Wait for the second object
    if (IsKernelObject(WaitHandle))
    {
        auto* waitObj = GetKernelObject<KernelObject>(WaitHandle);
        if (waitObj)
        {
            uint32_t timeout_ms = INFINITE;
            if (Timeout)
            {
                int64_t timeout_100ns = Timeout->get();
                if (timeout_100ns < 0)
                {
                    timeout_ms = static_cast<uint32_t>((-timeout_100ns) / 10000);
                }
                else if (timeout_100ns == 0)
                {
                    timeout_ms = 0;
                }
            }

            return waitObj->Wait(timeout_ms);
        }
    }

    return STATUS_SUCCESS;
}

uint32_t NtYieldExecution()
{
    // Yield the current thread's time slice
    std::this_thread::yield();
    return STATUS_SUCCESS;
}

//=============================================================================
// Additional kernel functions
//=============================================================================

// Ke* functions
PPC_FUNC(KePulseEvent)
{
    uint32_t handle = ctx.r3.u32;

    // Try to get the event object
    if (!IsKernelObject(handle))
    {
        ctx.r3.u32 = STATUS_INVALID_HANDLE;
        return;
    }

    auto* event = reinterpret_cast<Event*>(g_memory.Translate(handle));
    if (!event)
    {
        ctx.r3.u32 = STATUS_INVALID_HANDLE;
        return;
    }

    // Pulse: briefly signal then reset
    event->Set();
    event->Reset();
    ctx.r3.u32 = STATUS_SUCCESS;
}

PPC_FUNC(KeSetDisableBoostThread)
{
    // Thread boost control - stub (not critical for rendering)
    ctx.r3.u32 = STATUS_SUCCESS;
}

PPC_FUNC(KeTryToAcquireSpinLockAtRaisedIrql)
{
    // Spinlock - stub (return success, assume acquired)
    ctx.r3.u32 = 1; // TRUE
}

// Ob* functions
PPC_FUNC(ObLookupThreadByThreadId)
{
    // Stub: return success
    ctx.r3.u32 = STATUS_SUCCESS;
}

PPC_FUNC(ObOpenObjectByName)
{
    // Stub: fail gracefully
    ctx.r3.u32 = STATUS_OBJECT_NAME_NOT_FOUND;
}

PPC_FUNC(ObOpenObjectByPointer)
{
    // Stub: fail gracefully
    ctx.r3.u32 = STATUS_INVALID_PARAMETER;
}

// Mm* functions
PPC_FUNC(MmAllocatePhysicalMemory)
{
    // Stub: return a safe guest address
    ctx.r3.u32 = 0x90000000;
}

PPC_FUNC(MmSetAddressProtect)
{
    // Memory protection - stub (not critical)
    ctx.r3.u32 = STATUS_SUCCESS;
}

// Rtl* functions
uint32_t RtlCompareMemory(uint32_t src1, uint32_t src2, uint32_t length)
{
    const uint8_t* p1 = static_cast<const uint8_t*>(g_memory.Translate(src1));
    const uint8_t* p2 = static_cast<const uint8_t*>(g_memory.Translate(src2));

    if (!p1 || !p2)
    {
        return 0;
    }

    uint32_t matchCount = 0;
    for (uint32_t i = 0; i < length; i++)
    {
        if (p1[i] != p2[i])
            break;
        matchCount++;
    }

    return matchCount;
}

// Vd* functions
PPC_FUNC(VdGetGraphicsAsicID)
{
    // Return a fake ASIC ID (Xenos GPU)
    ctx.r3.u32 = 0x5820; // Xbox 360 GPU ID
}

// ===== helpers =====
static inline bool EarlyBootGate(const char* env_name, const char* trace_tag, std::chrono::steady_clock::time_point t0) {
    static const bool on = [] (const char* key) {
        if (const char* v = std::getenv(key)) return !(v[0] == '0' && v[1] == '\0');
        return false;
    }(env_name);
    if (!on) return false;
    if (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30)) {
        KernelTraceHostOp(trace_tag);
        return true;
    }
    return false;
}


// Shared вЂњstart timeвЂќ for early-boot gates
static const auto g_waits_t0 = std::chrono::steady_clock::now();


// ===== core impl (Objects = xpointer array) =====
static uint32_t KeWaitForMultipleObjects_Impl(
    uint32_t Count,
    xpointer<XDISPATCHER_HEADER>* Objects,
    uint32_t WaitType,          // 0=any, !=0=all
    uint32_t /*WaitReason*/,
    uint32_t /*WaitMode*/,
    uint32_t Alertable,
    be<int64_t>* Timeout,
    be<uint32_t>* /*WaitBlockArray*/)
{
    // Record last-waited dispatcher EA for ISR nudge (prefer the last in the array)
    if (Count) {
        for (int i = int(Count) - 1; i >= 0; --i) {
            if (Objects[i]) {
                if (uint32_t ea = g_memory.MapVirtual(Objects[i].get())) {
                    g_lastWaitEventEA.store(ea, std::memory_order_release);
                    g_lastWaitEventType.store(Objects[i]->Type, std::memory_order_release);
                    break;
                }
            }
        }
    }
    if (const char* tlw = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
        if (!(tlw[0]=='0' && tlw[1]=='\0')) {
            KernelTraceHostOpF("HOST.Wait.last.record ea=%08X type=%u", g_lastWaitEventEA.load(std::memory_order_relaxed), (unsigned)g_lastWaitEventType.load(std::memory_order_relaxed));
        }
    }


    // Early-boot/list-shims fast path (same behavior no matter who calls us)
    if (EarlyBootGate("MW05_FAST_BOOT",   "HOST.FastWait.KeWaitForMultipleObjects",   g_waits_t0) ||
        EarlyBootGate("MW05_LIST_SHIMS",  "HOST.MW05_LIST_SHIMS.KeWaitForMultipleObjects", g_waits_t0)) {
        // Pretend вЂњwait anyвЂќ hit index 0; вЂњwait allвЂќ -> success
        return (WaitType == 0) ? (STATUS_WAIT_0 + 0) : STATUS_SUCCESS;
    }

    // Optional: force-ack any event objects before blocking to break stalls
    if (Mw05ForceAckWaitEnabled()) {
        for (uint32_t i = 0; i < Count; ++i) {
            if (Objects[i]) {
                if (uint32_t ea = g_memory.MapVirtual(Objects[i].get())) {
                    Mw05ForceAckFromEventEA(ea);
                }
            }
        }
    }

    const uint32_t timeout_ms = GuestTimeoutToMilliseconds(Timeout);
    const bool wait_all = (WaitType != 0);

    // ---- Fast path: if everything are Events, use the generation wait ----
    {
        bool all_events = true;
        thread_local std::vector<Event*> s_events;
        s_events.resize(Count);

        for (uint32_t i = 0; i < Count; ++i) {
            // Deref xpointer вЂ” if invalid EA, your operator* should fail/assert similarly
            XDISPATCHER_HEADER& hdr = *Objects[i];
            Event* ev = nullptr;
            if (hdr.Type == 0 || hdr.Type == 1)
                ev = QueryKernelObject<Event>(hdr);
            if (!ev) { all_events = false; break; }
            s_events[i] = ev;
        }

        if (all_events) {
            const auto start = std::chrono::steady_clock::now();
            auto expired = [&]{
                if (timeout_ms == INFINITE) return false;
                uint32_t ms = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - start).count();
                return ms >= timeout_ms;
            };

            for (;;) {
                uint32_t ready = 0, signaled = UINT32_MAX;
                for (uint32_t i = 0; i < Count; ++i) {
                    if (s_events[i]->Wait(0) == STATUS_SUCCESS) {
                        ++ready; if (!wait_all) { signaled = i; break; }
                    }
                }
                if (wait_all) { if (ready == Count) return STATUS_SUCCESS; }
                else          { if (signaled != UINT32_MAX) return STATUS_WAIT_0 + (signaled & 0xFF); }

                if (Alertable) { /* TODO: APC handling if you wire it up */ }
                if (expired()) return STATUS_TIMEOUT;

                // If your KeSetEvent/ResetEvent signal a gen var, the wait below will block nicely.
                // Otherwise, temporarily replace with sleep_for(1ms).
                uint32_t gen = g_keSetEventGeneration.load(std::memory_order_acquire);
                g_keSetEventGeneration.wait(gen, std::memory_order_relaxed);
            }
        }
    }

    // ---- Generic path: build KernelObject* table and poll with light backoff ----
    std::vector<KernelObject*> objs;
    objs.reserve(Count);

    for (uint32_t i = 0; i < Count; ++i) {
        XDISPATCHER_HEADER& hdr = *Objects[i];   // deref xpointer
        KernelObject* ko = nullptr;
        switch (hdr.Type) {
            case 0: // NotificationEvent
            case 1: // SynchronizationEvent
                ko = static_cast<KernelObject*>(QueryKernelObject<Event>(hdr));
                break;
            case 5: // Semaphore
                ko = static_cast<KernelObject*>(QueryKernelObject<Semaphore>(hdr));
                break;
            default:
                return STATUS_INVALID_HANDLE;
        }
        if (!ko) return STATUS_INVALID_HANDLE;
        objs.push_back(ko);
    }

    const auto start = std::chrono::steady_clock::now();
    auto expired = [&]{
        if (timeout_ms == INFINITE) return false;
        uint32_t ms = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - start).count();
        return ms >= timeout_ms;
    };

    for (;;) {
        uint32_t ready = 0, signaled = UINT32_MAX;

        for (uint32_t i = 0; i < Count; ++i) {
            if (objs[i]->Wait(0) == STATUS_SUCCESS) {
                ++ready; if (!wait_all) { signaled = i; break; }
            }
        }
        if (wait_all) { if (ready == Count) return STATUS_SUCCESS; }
        else          { if (signaled != UINT32_MAX) return STATUS_WAIT_0 + (signaled & 0xFF); }

        if (Alertable) { /* APC if needed */ }
        if (expired()) return STATUS_TIMEOUT;

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}


// ===== public exports =====

// Kernel surface: already has xpointer[] вЂ” forward to impl.
uint32_t KeWaitForMultipleObjects(
    uint32_t Count,
    xpointer<XDISPATCHER_HEADER>* Objects,
    uint32_t WaitType,
    uint32_t WaitReason,
    uint32_t WaitMode,
    uint32_t Alertable,
    be<int64_t>* Timeout,
    be<uint32_t>* WaitBlockArray)
{
    KernelTraceHostOp("HOST.MW05_LIST_SHIMS.KeWaitForMultipleObjects.enter");
    return KeWaitForMultipleObjects_Impl(Count, Objects, WaitType, WaitReason, WaitMode,
                                         Alertable, Timeout, WaitBlockArray);
}

// NTDLL surface: handles/dispatcher EAs -> build xpointer[] then forward.
// --- NtWaitForMultipleObjectsEx: handles or dispatcher EAs ---
// No xpointer construction, no DispatcherEA(), no duplicate KeWaitForMultipleObjects.
// Optional: if you already expose this elsewhere, reuse it.
static inline void Mw05NudgeEventWaiters() {
    g_keSetEventGeneration.fetch_add(1, std::memory_order_acq_rel);
    g_keSetEventGeneration.notify_all();
}

extern "C" uint32_t NtWaitForMultipleObjectsEx(
    uint32_t Count,
    uint32_t* HandlesOrDispatchers,   // guest EAs or kernel handles
    uint32_t WaitType,                // 0 = wait-any, !=0 = wait-all
    uint32_t WaitMode,
    uint32_t Alertable,
    be<int64_t>* Timeout)
{
    KernelTraceHostOp("HOST.Wait.enter.NtWaitForMultipleObjectsEx");

    // Guards
    if (!HandlesOrDispatchers) return STATUS_INVALID_PARAMETER;
    if (Count == 0 || Count > 64) return STATUS_INVALID_PARAMETER; // sane cap

    const bool fastBoot  = Mw05FastBootEnabled();
    const bool listShims = Mw05ListShimsEnabled();
    static const auto t0 = std::chrono::steady_clock::now();
    const auto elapsed   = std::chrono::steady_clock::now() - t0;

    // LIST_SHIMS: trace only (no bypass)
    if (listShims && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.MW05_LIST_SHIMS.NtWaitForMultipleObjectsEx");
    }

    // Early-boot short-circuit ONLY for fast-boot
    if (fastBoot && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.FastWait.NtWaitForMultipleObjectsEx");
        // Heuristically mark dispatcher headers signaled
        for (uint32_t i = 0; i < Count; ++i) {
            const uint32_t v = HandlesOrDispatchers[i];
            if (GuestOffsetInRange(v, sizeof(XDISPATCHER_HEADER))) {
                auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(v));
                if (hdr) hdr->SignalState = be<int32_t>(1);
            }
        }
        Mw05NudgeEventWaiters();
        // Pretend index 0 fired for wait-any; success for wait-all
        return (WaitType == 0) ? (STATUS_WAIT_0 + 0) : STATUS_SUCCESS;
    }

    const uint32_t timeout_ms = GuestTimeoutToMilliseconds(Timeout);
    const bool wait_all = (WaitType != 0);

    // Build a vector of KernelObject* from mixed inputs and record last-wait info
    std::vector<KernelObject*> objs;
    objs.reserve(Count);

    auto record_last_ea = [](uint32_t ea, uint32_t type){
        if (!ea || !GuestOffsetInRange(ea, sizeof(XDISPATCHER_HEADER))) return;
        g_lastWaitEventEA.store(ea, std::memory_order_release);
        g_lastWaitEventType.store(type, std::memory_order_release);
        if (const char* tlw = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
            if (!(tlw[0]=='0' && tlw[1]=='\0'))
                KernelTraceHostOpF("HOST.Wait.last.record ea=%08X type=%u", ea, (unsigned)type);
        }
    };

    for (uint32_t i = 0; i < Count; ++i) {
        const uint32_t v = HandlesOrDispatchers[i];

        if (IsKernelObject(v)) {
            // Record last-wait kernel handle for ISR fallback (prefer later entries)
            g_lastWaitKernelHandle.store(v, std::memory_order_release);
            if (const char* tlw_h = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
                if (!(tlw_h[0]=='0' && tlw_h[1]=='\0'))
                    KernelTraceHostOpF("HOST.Wait.last.handle NtWaitForMultipleObjectsEx handle=%08X", v);
            }

            KernelObject* ko = GetKernelObject(v);
            if (!IsKernelObjectAlive(ko)) return STATUS_INVALID_HANDLE;

            // If this kernel object mirrors a guest dispatcher header, record its EA/type
            if (auto* ev = dynamic_cast<Event*>(ko)) {
                record_last_ea(ev->guestHeaderEA, ev->manualReset ? 0u : 1u);
            } else if (auto* sem = dynamic_cast<Semaphore*>(ko)) {
                record_last_ea(sem->guestHeaderEA, 5u);
            }

            objs.push_back(ko);
            continue;
        }

        // Treat non-handle as guest dispatcher pointer (EA)
        if (!GuestOffsetInRange(v, sizeof(XDISPATCHER_HEADER)))
            return STATUS_INVALID_HANDLE;

        auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(v));
        if (!hdr) return STATUS_INVALID_HANDLE;

        KernelObject* ko = nullptr;
        switch (hdr->Type) {
            case 0: // NotificationEvent
            case 1: // SynchronizationEvent
                ko = static_cast<KernelObject*>(QueryKernelObject<Event>(*hdr));
                break;
            case 5: // Semaphore
                ko = static_cast<KernelObject*>(QueryKernelObject<Semaphore>(*hdr));
                break;
            default:
                return STATUS_INVALID_HANDLE;
        }

        // Record this dispatcher EA/type (prefer later entries)
        record_last_ea(v, hdr->Type);
        objs.push_back(ko);
    }

    // Portable polling loop
    const auto start = std::chrono::steady_clock::now();
    auto expired = [&]{
        if (timeout_ms == INFINITE) return false;
        const uint32_t ms = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - start).count();
        return ms >= timeout_ms;
    };

    for (;;) {
        uint32_t ready = 0, signaled = UINT32_MAX;

        for (uint32_t i = 0; i < Count; ++i) {
            if (objs[i]->Wait(0) == STATUS_SUCCESS) {
                ++ready;
                if (!wait_all) { signaled = i; break; }
            }
        }

        if (wait_all) {
            if (ready == Count) return STATUS_SUCCESS;
        } else {
            if (signaled != UINT32_MAX) return STATUS_WAIT_0 + (signaled & 0xFF);
        }

        if (Alertable) {
            // TODO: APC support
        }
        if (expired()) return STATUS_TIMEOUT;

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}


void RtlCompareStringN()
{
    LOG_UTILITY("!!! STUB !!!");
}

void _snprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
}

void StfsControlDevice()
{
    LOG_UTILITY("!!! STUB !!!");
}

void StfsCreateDevice()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NtFlushBuffersFile()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlTimeToTimeFields()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlFreeAnsiString()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlUnicodeStringToAnsiString()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlInitUnicodeString()
{
    LOG_UTILITY("!!! STUB !!!");
}

void ExTerminateThread()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t ExCreateThread(be<uint32_t>* handle, uint32_t stackSize, be<uint32_t>* threadId, uint32_t xApiThreadStartup, uint32_t startAddress, uint32_t startContext, uint32_t creationFlags)
{
    LOGF_UTILITY("0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}",
        (intptr_t)handle, stackSize, (intptr_t)threadId, xApiThreadStartup, startAddress, startContext, creationFlags);

    // PERFORMANCE: Thread debug logging (disabled by default - causes FPS drop)
    static const bool s_debug_thread = [](){
        if (const char* v = std::getenv("MW05_DEBUG_THREAD"))
            return !(v[0]=='0' && v[1]=='\0');
        return false; // DISABLED by default for performance
    }();

    if (s_debug_thread) {
        KernelTraceHostOpF("HOST.ExCreateThread entry=%08X ctx=%08X flags=%08X", startAddress, startContext, creationFlags);
    }

    // MW05 FIX: Log first 10 thread creations only (to identify key threads without spam)
    static int s_thread_count = 0;
    const bool is_suspended = (creationFlags & 0x1) != 0;
    if (s_debug_thread || s_thread_count < 10) {
        fprintf(stderr, "[MW05_FIX] Thread #%d created: entry=%08X ctx=%08X flags=%08X %s\n",
            s_thread_count + 1, startAddress, startContext, creationFlags,
            is_suspended ? "SUSPENDED" : "RUNNING");
        fflush(stderr);
    }
    s_thread_count++;

    // Log context for debugging (but don't validate - context can be a simple parameter, not a structure!)
    if (startContext != 0 && startContext > 0x1000) {
        void* ctx_ptr = g_memory.Translate(startContext);
        if (ctx_ptr) {
            struct ThreadStartBlock {
                be<uint32_t> state;
                be<uint32_t> entry;
                be<uint32_t> context;
                be<uint32_t> event;
            };
            ThreadStartBlock* block = static_cast<ThreadStartBlock*>(ctx_ptr);
            fprintf(stderr, "[CONTEXT-DEBUG] ctx=0x%08X state=0x%08X entry=0x%08X context=0x%08X event=0x%08X\n",
                startContext, block->state.get(), block->entry.get(), block->context.get(), block->event.get());
            fflush(stderr);
        }
    } else if (startContext != 0) {
        fprintf(stderr, "[CONTEXT-DEBUG] ctx=0x%08X (simple parameter, not a structure)\n", startContext);
        fflush(stderr);
    }

    // CRITICAL FIX: Initialize worker thread context if it's uninitialized
    // The game sometimes creates threads with contexts that are all zeros
    // This causes crashes when the thread tries to call the callback function at offset +84
    // Check ANY thread context (not just worker threads) because startAddress can be corrupted
    fprintf(stderr, "[WORKER-THREAD-FIX] Checking context: ctx=0x%08X entry=0x%08X\n", startContext, startAddress);
    fflush(stderr);

    if (startContext != 0 && startContext > 0x1000 && startContext < 0x08000000) {  // User heap range
        fprintf(stderr, "[WORKER-THREAD-FIX] Context in user heap range, translating...\n");
        fflush(stderr);

        void* ctx_ptr = g_memory.Translate(startContext);
        if (ctx_ptr) {
            fprintf(stderr, "[WORKER-THREAD-FIX] Context translated to host=%p\n", ctx_ptr);
            fflush(stderr);
            // Check if context is uninitialized (all zeros in first 12 bytes AND callback pointers at +84/+88 are NULL)
            be<uint32_t>* ctx_u32 = reinterpret_cast<be<uint32_t>*>(ctx_ptr);
            uint32_t field_00 = ctx_u32[0].get();       // +0x00
            uint32_t field_04 = ctx_u32[1].get();       // +0x04
            uint32_t field_08 = ctx_u32[2].get();       // +0x08
            uint32_t callback_func = ctx_u32[84/4].get();  // +0x54 (84) - callback function pointer
            uint32_t callback_param = ctx_u32[88/4].get(); // +0x58 (88) - callback parameter

            // NATURAL PATH: Let the game initialize callback pointers
            // The game should pass initialized callback pointers when creating threads
            // If they're NULL, it means the game hasn't initialized them yet (not an error)
            if (startAddress == 0x828508A8) {
                // Only log for worker threads to avoid spam
                fprintf(stderr, "[WORKER-THREAD-NATURAL] Worker thread context: +0x54=0x%08X, +0x58=0x%08X\n",
                        callback_func, callback_param);
                fflush(stderr);
            }
        }
    }

    // TRACE: For Thread #2, dump the context structure
    if (startAddress == 0x82812ED0) {
        fprintf(stderr, "[THREAD2-TRACE] Thread #2 being created with ctx=%08X\n", startContext);

        // CRITICAL: Verify the context address matches expected static global
        const uint32_t EXPECTED_STATIC_CTX = 0x828F1F98;  // qword_828F1F98 from .data section
        const uint32_t OLD_BUGGY_CTX = 0x00120E10;        // Old incorrect address from traces

        fprintf(stderr, "[CONTEXT-VERIFY] Context address analysis:\n");
        fprintf(stderr, "  Actual:   0x%08X\n", startContext);
        fprintf(stderr, "  Expected: 0x%08X (static global qword_828F1F98)\n", EXPECTED_STATIC_CTX);

        if (startContext == EXPECTED_STATIC_CTX) {
            fprintf(stderr, "  ✅ CORRECT: Using static global from .data section\n");
        } else if (startContext == OLD_BUGGY_CTX) {
            fprintf(stderr, "  ❌ ERROR: Using old buggy address 0x00120E10!\n");
        } else if ((startContext >= 0x70000000) && (startContext < 0x80000000)) {
            fprintf(stderr, "  ⚠️ WARNING: Using heap address (Xenia-style, not expected for recompilation)\n");
        } else if ((startContext >= 0x82000000) && (startContext < 0x83000000)) {
            fprintf(stderr, "  ⚠️ WARNING: In XEX range but not at expected address\n");
        } else {
            fprintf(stderr, "  ⚠️ WARNING: Unknown memory region\n");
        }

        if (startContext != 0) {
            void* ctx_host = g_memory.Translate(startContext);
            if (ctx_host) {
                uint32_t* ctx_ptr = (uint32_t*)ctx_host;
                fprintf(stderr, "[THREAD2-TRACE] Context at %08X:\n", startContext);
                fprintf(stderr, "  +0x00: 0x%08X\n", __builtin_bswap32(ctx_ptr[0]));
                fprintf(stderr, "  +0x04: 0x%08X\n", __builtin_bswap32(ctx_ptr[1]));
                fprintf(stderr, "  +0x08: 0x%08X\n", __builtin_bswap32(ctx_ptr[2]));
                fprintf(stderr, "  +0x0C: 0x%08X\n", __builtin_bswap32(ctx_ptr[3]));

                // Save the valid function pointer for later verification
                static uint32_t s_saved_func_ptr = 0;
                static uint32_t s_context_addr = 0;
                static void* s_context_host_ptr = nullptr;
                s_saved_func_ptr = __builtin_bswap32(ctx_ptr[1]);
                s_context_addr = startContext;
                s_context_host_ptr = ctx_host;
                fprintf(stderr, "[THREAD2-TRACE] Saved function pointer: 0x%08X at guest=%08X host=%p\n",
                        s_saved_func_ptr, s_context_addr, s_context_host_ptr);

                // REMOVED: Corruption monitor was causing false positives
                // The thread context is temporary and gets reused/freed after thread creation
                // This is EXPECTED behavior, not corruption
            } else {
                fprintf(stderr, "[THREAD2-TRACE] Context address %08X is NOT MAPPED!\n", startContext);
            }
        }
        fflush(stderr);
    }

    uint32_t hostThreadId;

    *handle = GetKernelHandle(GuestThread::Start({ startAddress, startContext, creationFlags }, &hostThreadId));

    if (threadId != nullptr)
        *threadId = hostThreadId;

    if (s_debug_thread || s_thread_count <= 10) {
        fprintf(stderr, "[MW05_FIX] Thread #%d handle=%08X hostTid=%08X %s\n",
            s_thread_count, (uint32_t)*handle, hostThreadId,
            is_suspended ? "WAITING_FOR_RESUME" : "STARTED");
        fflush(stderr);
    }

    if (s_debug_thread) {
        KernelTraceHostOpF("HOST.ExCreateThread DONE entry=%08X hostTid=%08X", startAddress, hostThreadId);
    }

    return 0;
}

void IoInvalidDeviceRequest()
{
    LOG_UTILITY("!!! STUB !!!");
}

void ObReferenceObject()
{
    LOG_UTILITY("!!! STUB !!!");
}

void IoCreateDevice()
{
    LOG_UTILITY("!!! STUB !!!");
}

void IoDeleteDevice()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlTimeFieldsToTime()
{
    LOG_UTILITY("!!! STUB !!!");
}

void IoCompleteRequest()
{
    LOG_UTILITY("!!! STUB !!!");
}

void RtlUpcaseUnicodeChar()
{
    LOG_UTILITY("!!! STUB !!!");
}

void ObIsTitleObject()
{
    LOG_UTILITY("!!! STUB !!!");
}

void IoCheckShareAccess()
{
    LOG_UTILITY("!!! STUB !!!");
}

void IoSetShareAccess()
{
    LOG_UTILITY("!!! STUB !!!");
}

void IoRemoveShareAccess()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_XNetStartup()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NetDll_XNetGetTitleXnAddr()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t KeRaiseIrqlToDpcLevel()
{
    return 0;
}

void KfLowerIrql() { }

uint32_t KeReleaseSemaphore(XKSEMAPHORE* semaphore, uint32_t increment, uint32_t adjustment, uint32_t wait)
{
    auto* object = QueryKernelObject<Semaphore>(semaphore->Header);
    object->Release(adjustment, nullptr);
    return STATUS_SUCCESS;
}

void XAudioGetVoiceCategoryVolume()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t XAudioGetVoiceCategoryVolumeChangeMask(uint32_t Driver, be<uint32_t>* Mask)
{
    *Mask = 0;
    return 0;
}

uint32_t KeResumeThread(GuestThreadHandle* object)
{
    assert(object != GetKernelObject(CURRENT_THREAD_HANDLE));

    // PERFORMANCE: Thread debug logging (disabled by default - causes FPS drop)
    static const bool s_debug_thread = [](){
        if (const char* v = std::getenv("MW05_DEBUG_THREAD"))
            return !(v[0]=='0' && v[1]=='\0');
        return false; // DISABLED by default for performance
    }();

    // Log first 10 thread resumes only
    static int s_resume_count = 0;
    if (s_debug_thread || s_resume_count < 10) {
        fprintf(stderr, "[MW05_FIX] KeResumeThread called: handle=%p tid=%08X\n",
            (void*)object, object ? object->GetThreadId() : 0);
        fflush(stderr);
    }
    s_resume_count++;

    if (s_debug_thread) {
        KernelTraceHostOpF("HOST.KeResumeThread tid=%08X", object ? object->GetThreadId() : 0);
    }

    object->suspended = false;
    object->suspended.notify_all();

    if (s_debug_thread || s_resume_count <= 10) {
        fprintf(stderr, "[MW05_FIX] KeResumeThread: thread resumed, tid=%08X\n",
            object->GetThreadId());
        fflush(stderr);
    }

    return 0;
}

void KeInitializeSemaphore(XKSEMAPHORE* semaphore, uint32_t count, uint32_t limit)
{
    semaphore->Header.Type = 5;
    semaphore->Header.SignalState = count;
    semaphore->Limit = limit;

    auto* object = QueryKernelObject<Semaphore>(semaphore->Header);
}

void XMAReleaseContext()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XMACreateContext(PPCContext& ctx, uint8_t* /*base*/)
{
    // XMACreateContext returns 0 on success, negative on failure
    // The game checks: cmpwi cr6,r3,0 then bge cr6 (branch if r3 >= 0)
    // Return success to allow audio initialization to proceed
    ctx.r3.s32 = 0;  // Success

    static int call_count = 0;
    if (call_count++ < 3) {
        fprintf(stderr, "[XMACreateContext] STUB - returning success (r3=0)\n");
        fflush(stderr);
    }
    LOG_UTILITY("!!! STUB !!! - returning success");
}

// uint32_t XAudioRegisterRenderDriverClient(be<uint32_t>* callback, be<uint32_t>* driver)
// {
//     //printf("XAudioRegisterRenderDriverClient(): %x %x\n");
//
//     *driver = apu::RegisterClient(callback[0], callback[1]);
//     return 0;
// }

// void XAudioUnregisterRenderDriverClient()
// {
//     printf("!!! STUB !!! XAudioUnregisterRenderDriverClient\n");
// }

// uint32_t XAudioSubmitRenderDriverFrame(uint32_t driver, void* samples)
// {
//     // printf("!!! STUB !!! XAudioSubmitRenderDriverFrame\n");
//     apu::SubmitFrames(samples);
//
//     return 0;
// }

GUEST_FUNCTION_HOOK(__imp__XGetVideoMode, VdQueryVideoMode); // XGetVideoMode
GUEST_FUNCTION_HOOK(__imp__XNotifyGetNext, XNotifyGetNext);
GUEST_FUNCTION_HOOK(__imp__XGetGameRegion, XGetGameRegion);
GUEST_FUNCTION_HOOK(__imp__XMsgStartIORequest, XMsgStartIORequest);
GUEST_FUNCTION_HOOK(__imp__XamUserGetSigninState, XamUserGetSigninState);
GUEST_FUNCTION_HOOK(__imp__XamGetSystemVersion, XamGetSystemVersion);
GUEST_FUNCTION_HOOK(__imp__XamContentCreateEx, XamContentCreateEx);
GUEST_FUNCTION_HOOK(__imp__XamContentDelete, XamContentDelete);
GUEST_FUNCTION_HOOK(__imp__XamContentClose, XamContentClose);
GUEST_FUNCTION_HOOK(__imp__XamContentGetCreator, XamContentGetCreator);
GUEST_FUNCTION_HOOK(__imp__XamContentCreateEnumerator, XamContentCreateEnumerator);
GUEST_FUNCTION_HOOK(__imp__XamContentGetDeviceState, XamContentGetDeviceState);
GUEST_FUNCTION_HOOK(__imp__XamContentGetDeviceData, XamContentGetDeviceData);
GUEST_FUNCTION_HOOK(__imp__XamEnumerate, XamEnumerate);
GUEST_FUNCTION_HOOK(__imp__XamNotifyCreateListener, XamNotifyCreateListener);
GUEST_FUNCTION_HOOK(__imp__XamUserGetSigninInfo, XamUserGetSigninInfo);
GUEST_FUNCTION_HOOK(__imp__XamShowSigninUI, XamShowSigninUI);
GUEST_FUNCTION_HOOK(__imp__XamShowDeviceSelectorUI, XamShowDeviceSelectorUI);
GUEST_FUNCTION_HOOK(__imp__XamShowMessageBoxUI, XamShowMessageBoxUI);
GUEST_FUNCTION_HOOK(__imp__XamShowDirtyDiscErrorUI, XamShowDirtyDiscErrorUI);
GUEST_FUNCTION_HOOK(__imp__XamEnableInactivityProcessing, XamEnableInactivityProcessing);
GUEST_FUNCTION_HOOK(__imp__XamResetInactivity, XamResetInactivity);
GUEST_FUNCTION_HOOK(__imp__XamShowMessageBoxUIEx, XamShowMessageBoxUIEx);
GUEST_FUNCTION_HOOK(__imp__XGetLanguage, XGetLanguage);

// Minimal stubs for XAM imports referenced by the recompiled mapping but not yet implemented.
GUEST_FUNCTION_HOOK(__imp__XamLoaderGetLaunchDataSize, XamLoaderGetLaunchDataSize);
GUEST_FUNCTION_HOOK(__imp__XamLoaderGetLaunchData,     XamLoaderGetLaunchData);
GUEST_FUNCTION_HOOK(__imp__XamLoaderSetLaunchData,     XamLoaderSetLaunchData);
GUEST_FUNCTION_STUB(__imp__XamUserGetName);
GUEST_FUNCTION_STUB(__imp__XamUserAreUsersFriends);
GUEST_FUNCTION_STUB(__imp__XamUserCheckPrivilege);
GUEST_FUNCTION_STUB(__imp__XamUserCreateStatsEnumerator);
// XamReadTileToTexture(handle, key, offset, size, texturePtr, miplevel, ...)
// MW05 may call this to populate textures from XContent tiles. For now, no-op
// and report success so callers can proceed. Add logging to help future wiring.
PPC_FUNC(__imp__XamReadTileToTexture)
{
    (void)base;
    // Minimal success return
    ctx.r3.u32 = 0; // S_OK
}
GUEST_FUNCTION_STUB(__imp__XamParseGamerTileKey);
GUEST_FUNCTION_STUB(__imp__XamWriteGamerTile);
GUEST_FUNCTION_STUB(__imp__XamUserCreatePlayerEnumerator);
GUEST_FUNCTION_STUB(__imp__XamUserCreateAchievementEnumerator);
GUEST_FUNCTION_STUB(__imp__XamUserGetXUID);
GUEST_FUNCTION_STUB(__imp__XamShowSigninUIp);
GUEST_FUNCTION_STUB(__imp__XamShowFriendsUI);
GUEST_FUNCTION_STUB(__imp__XamShowPlayersUI);
GUEST_FUNCTION_STUB(__imp__XamShowMessagesUI);
GUEST_FUNCTION_STUB(__imp__XamShowKeyboardUI);
GUEST_FUNCTION_STUB(__imp__XamShowQuickChatUI);
GUEST_FUNCTION_STUB(__imp__XamShowVoiceMailUI);
GUEST_FUNCTION_STUB(__imp__XamShowGamerCardUIForXUID);
GUEST_FUNCTION_STUB(__imp__XamShowAchievementsUI);
GUEST_FUNCTION_STUB(__imp__XamShowPlayerReviewUI);
GUEST_FUNCTION_STUB(__imp__XamShowMarketplaceUI);
GUEST_FUNCTION_STUB(__imp__XamShowMessageComposeUI);
GUEST_FUNCTION_STUB(__imp__XamShowGameInviteUI);
GUEST_FUNCTION_STUB(__imp__XamShowFriendRequestUI);

// MW05 DEBUG: Wrappers to trace sub_821BB4D0 sub-function calls
static std::atomic<int> s_debug_call_depth{0};


// Forward decl: MW05 allocator functions (for debugging)
// CRITICAL FIX (2025-11-01): sub_8215CB08 is now recompiled - no need for PPC_FUNC_IMPL or debug wrapper
// PPC_FUNC_IMPL(__imp__sub_8215CB08);  // DISABLED - function is recompiled
// REMOVED: These are now in MW05.toml and recompiled
// PPC_FUNC_IMPL(__imp__sub_8215C790);
// PPC_FUNC_IMPL(__imp__sub_8215C838);
// PPC_FUNC_IMPL(__imp__sub_821BB4D0);

// Forward decl: MW05 graphics initialization functions (sub_825A8698 only - others are in mw05_trace_threads.cpp and mw05_draw_diagnostic.cpp)
PPC_FUNC_IMPL(__imp__sub_825A8698);

// DISABLED (2025-11-01): sub_8215CB08_debug causes infinite recursion - function is now recompiled
/*
void sub_8215CB08_debug(PPCContext& ctx, uint8_t* base) {
    int depth = s_debug_call_depth.fetch_add(1);
    uint32_t size = ctx.r3.u32;
    uint32_t flags = ctx.r4.u32;

    static std::atomic<uint64_t> s_largeAllocCount{0};
    static std::atomic<uint64_t> s_buggyAllocCount{0};

    // CRITICAL FIX: Bypass recompiler bug for specific allocation sizes
    // The recompiled sub_8215CB08 crashes with access violation when allocating 1538 bytes (0x602)
    // This is a recompiler bug, not a game bug. Bypass the problematic allocation sizes.
    const uint32_t BUGGY_ALLOC_SIZE = 0x602;  // 1538 bytes - causes crash in recompiled code

    if (size == BUGGY_ALLOC_SIZE) {
        uint64_t count = s_buggyAllocCount.fetch_add(1);
        fprintf(stderr, "[MW05_BUGGY_ALLOC] #%llu: Bypassing recompiler bug for %u bytes allocation\n",
                count, size);
        fflush(stderr);

        // Allocate directly from our user heap
        void* host_ptr = g_userHeap.Alloc(size);

        if (host_ptr == nullptr) {
            fprintf(stderr, "[MW05_BUGGY_ALLOC] ERROR: Failed to allocate %u bytes from heap!\n", size);
            fflush(stderr);
            ctx.r3.u32 = 0;
        } else {
            uint32_t guest_addr = g_memory.MapVirtual(host_ptr);
            fprintf(stderr, "[MW05_BUGGY_ALLOC] SUCCESS: Allocated %u bytes at 0x%08X (host=%p)\n",
                    size, guest_addr, host_ptr);
            fflush(stderr);
            ctx.r3.u32 = guest_addr;
        }
        s_debug_call_depth.fetch_sub(1);
        return;
    }

    // REMOVED BYPASS: Let the game use its own pool allocator for ALL allocations
    // The bypass was masking the real issue - we need to fix the allocator, not bypass it

    fprintf(stderr, "[MW05_DEBUG] [depth=%d] ENTER sub_8215CB08 r3=%08X (size=%u bytes = %u KB) r4=%08X\n",
            depth, size, size, size/1024, flags);
    fflush(stderr);

    // CRITICAL FIX: Call the ORIGINAL game allocator instead of bypassing it!
    // The game's allocator (sub_8215CB08) performs important initialization on first call
    // by calling sub_8215FDC0, which sets up internal data structures.
    // Bypassing this causes crashes due to uninitialized static globals.
    __imp__sub_8215CB08(ctx, base);

    uint32_t result = ctx.r3.u32;
    fprintf(stderr, "[MW05_DEBUG] [depth=%d] EXIT sub_8215CB08 - allocated %u bytes at %08X\n",
            depth, size, result);
    fflush(stderr);

    // CRITICAL FIX: If game's pool allocator returns NULL, retry with direct heap allocation
    // After large physical allocations (4 × 345 MB), the pool may be full/fragmented
    // This prevents heap errors from trying to free NULL pointers
    if (result == 0 && size > 0) {
        static std::atomic<uint64_t> s_retryCount{0};
        uint64_t count = s_retryCount.fetch_add(1);
        fprintf(stderr, "[MW05_POOL_FULL] #%llu: Pool allocator returned NULL for %u bytes, retrying with direct heap...\n",
                count, size);
        fflush(stderr);

        // Allocate directly from our user heap
        void* host_ptr = g_userHeap.Alloc(size);

        if (host_ptr == nullptr) {
            fprintf(stderr, "[MW05_POOL_FULL] ERROR: Direct heap allocation also failed for %u bytes!\n", size);
            fflush(stderr);
            // Leave result as 0 - let game handle the failure
        } else {
            uint32_t guest_addr = g_memory.MapVirtual(host_ptr);
            fprintf(stderr, "[MW05_POOL_FULL] SUCCESS: Allocated %u bytes at 0x%08X (host=%p)\n",
                    size, guest_addr, host_ptr);
            fflush(stderr);
            ctx.r3.u32 = guest_addr;
            result = guest_addr;  // Update result for logging below
        }
    }

    // DEBUG: Check if the allocated address is valid
    if (result != 0) {
        void* host_ptr = g_memory.Translate(result);
        if (!host_ptr) {
            fprintf(stderr, "[MW05_DEBUG] ERROR: Allocated address 0x%08X cannot be translated to host!\n", result);
            fflush(stderr);
        } else {
            fprintf(stderr, "[MW05_DEBUG] Allocated address 0x%08X translates to host %p\n", result, host_ptr);
            fflush(stderr);
        }
    }

    s_debug_call_depth.fetch_sub(1);
}
*/  // End of disabled sub_8215CB08_debug function

// REMOVED: These functions are now recompiled (added to MW05.toml)
// sub_8215C790_debug, sub_8215C838_debug, sub_821BB4D0_debug

// Debug wrapper for sub_825A8698 (CreateDevice)
// CRITICAL: This function hangs and never returns! We need to find which sub-function is hanging.
// According to IDA decompilation, it calls:
// - sub_825A8648() - initialization
// - sub_825A85E0(a1) - returns bool
// - sub_82598230(a1, a2 + 72) - CreateDevice core
// - sub_825AAE58(a1) - create render thread
// - sub_825ACE98(a1), sub_825A8200(a1, a2), sub_825A8080(a1), etc.
//
// STRATEGY: Let the function run but add detailed logging to identify the hanging sub-function.
void sub_825A8698_debug(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[MW05_DEBUG] ========== ENTER sub_825A8698 (CreateDevice) r3=%08X r4=%08X ==========\n",
            ctx.r3.u32, ctx.r4.u32);
    fflush(stderr);

    // TEMPORARY: Disable the skip to identify which sub-function hangs
    static const bool s_skip_buggy_code = [](){
        if (const char* v = std::getenv("MW05_SKIP_825A8698_BUG"))
            return !(v[0]=='0' && v[1]=='\0');
        return false; // DISABLED - we want to see where it hangs
    }();

    if (s_skip_buggy_code) {
        fprintf(stderr, "[MW05_DEBUG] SKIPPING sub_825A8698 (CreateDevice) - buggy recompiled code hangs!\n");
        fflush(stderr);
        ctx.r3.u32 = 1; // Return success
        fprintf(stderr, "[MW05_DEBUG] ========== EXIT  sub_825A8698 (CreateDevice) r3=%08X (SKIPPED) ==========\n", ctx.r3.u32);
        fflush(stderr);
        return;
    }

    fprintf(stderr, "[MW05_DEBUG] Calling __imp__sub_825A8698 (recompiled CreateDevice)...\n");
    fflush(stderr);

    __imp__sub_825A8698(ctx, base);

    fprintf(stderr, "[MW05_DEBUG] ========== EXIT  sub_825A8698 (CreateDevice) r3=%08X ==========\n", ctx.r3.u32);
    fflush(stderr);
}

// Forward declarations for main loop functions
extern "C" void __imp__sub_82441E80(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_82441CF0(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_8262DE60(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_8262D9D0(PPCContext& ctx, uint8_t* base);

// Debug wrapper for sub_82441E80 (function that should call main loop)
// Forward declaration of sub_82441CF0_debug (main loop)
void sub_82441CF0_debug(PPCContext& ctx, uint8_t* base);

// CRITICAL: Both sub_82441E80 and sub_82441CF0 have recompiler bugs!
// WORKAROUND: Implement the main loop logic manually.
void sub_82441E80_debug(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[MW05_DEBUG] ========== ENTER sub_82441E80 (should call main loop) ==========\n");
    fflush(stderr);

    // CRITICAL FIX: The recompiled code for both sub_82441E80 and sub_82441CF0 have bugs!
    // sub_82441E80 hangs, and sub_82441CF0 (main loop) exits after 10 iterations.
    //
    // According to IDA decompilation, sub_82441E80 should:
    // 1. Call sub_8215CB08(4, 0, 0, 0) to allocate memory
    // 2. Call sub_8261A5E8() - CREATES WORKER THREADS!
    // 3. Call sub_8262FA08() - Set thread affinity
    // 4. Call sub_826B96B0() - Set thread name
    // 5. Call sub_82441CF0() - main loop
    //
    // We implement this logic manually to bypass the recompiler bugs.
    fprintf(stderr, "[MW05_DEBUG] SKIPPING buggy recompiled code, implementing initialization + main loop manually...\n");
    fflush(stderr);

    // Step 1: Allocate memory structure
    fprintf(stderr, "[MW05_DEBUG] Calling sub_8215CB08(4, 0, 0, 0) to allocate memory...\n");
    fflush(stderr);

    extern void sub_8215CB08(PPCContext& ctx, uint8_t* base);
    ctx.r3.u32 = 4;
    ctx.r4.u32 = 0;
    ctx.r5.u32 = 0;
    ctx.r6.u32 = 0;
    sub_8215CB08(ctx, base);
    uint32_t allocated_ptr = ctx.r3.u32;

    fprintf(stderr, "[MW05_DEBUG] sub_8215CB08() returned ptr=0x%08X\n", allocated_ptr);
    fflush(stderr);

    // Step 2: Create worker threads
    fprintf(stderr, "[MW05_DEBUG] Calling sub_8261A5E8() to create worker threads...\n");
    fflush(stderr);

    // Set up parameters for sub_8261A5E8 (from recompiled code):
    // r3 = pointer to allocated structure (already set from sub_8215CB08)
    // r4 = 0x82440000 + 7768 = 0x82441E58 (some function address)
    // r5 = 0
    // r6 = 0
    // r7 = value from dword_82A2CF48 (global variable)
    const uint32_t dword_82A2CF48_ea = 0x82A2CF48;
    uint32_t* dword_82A2CF48_ptr = (uint32_t*)(base + dword_82A2CF48_ea);
    uint32_t r7_value = be<uint32_t>(*dword_82A2CF48_ptr).get();

    extern void sub_8261A5E8(PPCContext& ctx, uint8_t* base);
    // r3 is already set to allocated_ptr from sub_8215CB08
    ctx.r4.u32 = 0x82441E58;  // Function address
    ctx.r5.u32 = 0;
    ctx.r6.u32 = 0;
    ctx.r7.u32 = r7_value;
    sub_8261A5E8(ctx, base);

    fprintf(stderr, "[MW05_DEBUG] sub_8261A5E8() returned - worker threads should now be created!\n");
    fflush(stderr);

    // Step 3: Set thread affinity (if allocated_ptr is valid)
    if (allocated_ptr != 0) {
        // Read the pointer from allocated structure
        uint32_t* allocated_struct = (uint32_t*)(base + allocated_ptr);
        uint32_t inner_ptr = be<uint32_t>(*allocated_struct).get();

        if (inner_ptr != 0) {
            fprintf(stderr, "[MW05_DEBUG] Calling sub_8262FA08(0x%08X, 2) to set thread affinity...\n", inner_ptr);
            fflush(stderr);

            extern void sub_8262FA08(PPCContext& ctx, uint8_t* base);
            ctx.r3.u32 = inner_ptr;
            ctx.r4.u32 = 2;  // Affinity parameter
            sub_8262FA08(ctx, base);

            fprintf(stderr, "[MW05_DEBUG] sub_8262FA08() returned\n");
            fflush(stderr);

            // Step 4: Set thread name
            fprintf(stderr, "[MW05_DEBUG] Calling sub_826B96B0() to set thread name...\n");
            fflush(stderr);

            // Allocate memory for the "MainThread" string in guest memory
            const char* main_thread_name = "MainThread";
            size_t name_len = strlen(main_thread_name) + 1;  // Include null terminator
            void* name_host = g_userHeap.Alloc(name_len);
            if (name_host) {
                memcpy(name_host, main_thread_name, name_len);
                uint32_t name_guest_addr = g_memory.MapVirtual(name_host);

                extern void sub_826B96B0(PPCContext& ctx, uint8_t* base);
                ctx.r3.u32 = inner_ptr + 36;  // Offset for thread name
                ctx.r4.u32 = name_guest_addr;
                ctx.r5.u32 = 20;  // Max length
                sub_826B96B0(ctx, base);

                fprintf(stderr, "[MW05_DEBUG] sub_826B96B0() returned\n");
                fflush(stderr);
            } else {
                fprintf(stderr, "[MW05_DEBUG] ERROR: Failed to allocate memory for thread name!\n");
                fflush(stderr);
            }
        }
    }

    // Store allocated pointer in global variable (dword_82A2CF44)
    const uint32_t global_ptr_addr = 0x82A2CF44;
    uint32_t* global_ptr = (uint32_t*)(base + global_ptr_addr);
    *global_ptr = allocated_ptr;

    fprintf(stderr, "[MW05_DEBUG] Stored allocated ptr 0x%08X in global dword_82A2CF44\n", allocated_ptr);
    fflush(stderr);

    // Call the REAL main loop function: sub_82441CF0(0)
    fprintf(stderr, "[MW05_DEBUG] Calling sub_82441CF0_debug(0) - THE REAL MAIN LOOP!\n");
    fflush(stderr);

    // Call our manual implementation directly (not through the hook)
    ctx.r3.u32 = 0;
    sub_82441CF0_debug(ctx, base);

    fprintf(stderr, "[MW05_DEBUG] ========== EXIT  sub_82441E80 - should never reach here! ==========\n");
    fflush(stderr);
}

// Manual implementation of sub_82441CF0 (main loop)
// This is the REAL main loop that processes frames
// CRITICAL: Must call sub_8262DE60 on every iteration to process frames
void sub_82441CF0_debug(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[MW05_DEBUG] ========== ENTER sub_82441CF0 (main loop) ==========\n");
    fflush(stderr);

    // Call sub_82619E90() to initialize
    extern void sub_82619E90(PPCContext& ctx, uint8_t* base);
    sub_82619E90(ctx, base);
    uint32_t v0 = ctx.r3.u32;

    fprintf(stderr, "[MW05_DEBUG] sub_82619E90() returned r3=0x%08X\n", v0);
    fflush(stderr);

    // Store in dword_82A2CF48
    const uint32_t dword_82A2CF48_ea = 0x82A2CF48;
    uint32_t* dword_82A2CF48_ptr = (uint32_t*)(base + dword_82A2CF48_ea);
    *dword_82A2CF48_ptr = v0;

    // Main loop flag address
    const uint32_t main_loop_flag_ea = 0x82A2CF40;
    volatile uint32_t* main_loop_flag_ptr = (volatile uint32_t*)(base + main_loop_flag_ea);

    // External functions
    extern void sub_8262D9D0(PPCContext& ctx, uint8_t* base);
    extern void sub_8262EC60(PPCContext& ctx, uint8_t* base);
    extern void sub_823C8420(PPCContext& ctx, uint8_t* base);
    extern void sub_8262DE60(PPCContext& ctx, uint8_t* base);

    uint64_t iteration = 0;
    fprintf(stderr, "[MW05_DEBUG] Entering main loop...\n");
    fprintf(stderr, "[MW05_DEBUG] main_loop_flag_ptr = %p\n", main_loop_flag_ptr);
    fflush(stderr);
    fprintf(stderr, "[MW05_DEBUG] Reading initial flag value...\n");
    fflush(stderr);
    uint32_t initial_flag = *main_loop_flag_ptr;
    fprintf(stderr, "[MW05_DEBUG] Initial flag value = 0x%08X\n", initial_flag);
    fflush(stderr);

    while (true) {
        // Wait for flag to be set (call sub_8262D9D0 while waiting)
        uint32_t wait_count = 0;
        while (*main_loop_flag_ptr == 0) {
            if (wait_count < 5) {
                fprintf(stderr, "[MW05_DEBUG] Waiting for flag (iteration %llu, wait %u): flag = 0x%08X\n", iteration, wait_count, *main_loop_flag_ptr);
                fflush(stderr);
            }
            ctx.r3.u32 = 0;
            sub_8262D9D0(ctx, base);
            v0 = ctx.r3.u32;
            wait_count++;
        }

        // Flag is set, process frame
        fprintf(stderr, "[MW05_DEBUG] BEFORE iteration check (iteration=%llu)\n", iteration);
        fflush(stderr);
        if (iteration < 5) {
            fprintf(stderr, "[MW05_DEBUG] Main loop iteration %llu: flag was set!\n", iteration);
            fflush(stderr);
        }

        // Call sub_8262EC60 (timing function)
        if (iteration < 5) {
            fprintf(stderr, "[MW05_DEBUG] Calling sub_8262EC60 (timing)...\n");
            fflush(stderr);
        }
        sub_8262EC60(ctx, base);
        if (iteration < 5) {
            fprintf(stderr, "[MW05_DEBUG] sub_8262EC60 returned\n");
            fflush(stderr);
        }

        // Process work queue (sub_823C8420) - THIS IS CRITICAL FOR RENDERING!
        // This function processes work items from the queue and dispatches them to worker threads
        if (iteration < 5) {
            fprintf(stderr, "[MW05_DEBUG] Calling sub_823C8420 (work queue processing)...\n");
            fflush(stderr);
        }
        ctx.r3.u32 = 0;  // First parameter (unknown)
        ctx.r4.u32 = 1;  // Second parameter (number of items to process)
        sub_823C8420(ctx, base);
        if (iteration < 5) {
            fprintf(stderr, "[MW05_DEBUG] sub_823C8420 returned\n");
            fflush(stderr);
        }

        // Call sub_8262DE60 (frame update) - THIS IS CRITICAL!
        if (iteration < 5) {
            fprintf(stderr, "[MW05_DEBUG] Calling sub_8262DE60 (frame update)...\n");
            fflush(stderr);
        }
        sub_8262DE60(ctx, base);
        if (iteration < 5) {
            fprintf(stderr, "[MW05_DEBUG] sub_8262DE60 returned\n");
            fflush(stderr);
        }

        // Reset flag
        *main_loop_flag_ptr = 0;

        iteration++;
    }

    fprintf(stderr, "[MW05_DEBUG] ========== EXIT  sub_82441CF0 - should never reach here! ==========\n");
    fflush(stderr);
}

// Manual implementation of sub_82849DE8 (notification system initialization)
// This function creates the notification polling thread and sets the flag that allows it to start
// CRITICAL: The flag at offset +96 must be set with proper memory barriers to ensure visibility
void sub_82849DE8_debug(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[MW05_DEBUG] ========== ENTER sub_82849DE8 (notification system init) ==========\n");
    fflush(stderr);

    // Call the original recompiled function
    extern void sub_82849DE8(PPCContext& ctx, uint8_t* base);
    sub_82849DE8(ctx, base);

    uint32_t result = ctx.r3.u32;
    fprintf(stderr, "[MW05_DEBUG] sub_82849DE8() returned r3=0x%08X\n", result);
    fflush(stderr);

    if (result != 0) {
        // The function should have set the flag at offset +96 to 1
        // But due to memory visibility issues, the notification thread might not see it
        // Force the flag to be set with proper memory barriers
        const uint32_t flag_offset = 96;
        const uint32_t flag_ea = result + flag_offset;
        volatile uint32_t* flag_ptr = (volatile uint32_t*)(base + flag_ea);

        fprintf(stderr, "[MW05_FIX] Forcing notification thread flag at 0x%08X to 1 (with memory barrier)\n", flag_ea);
        fflush(stderr);

        // Set flag to 1 (big-endian)
        *flag_ptr = _byteswap_ulong(1);

        // Memory barrier to ensure visibility
        std::atomic_thread_fence(std::memory_order_seq_cst);

        fprintf(stderr, "[MW05_FIX] Flag set! Notification thread should now start polling.\n");
        fflush(stderr);
    }

    fprintf(stderr, "[MW05_DEBUG] ========== EXIT  sub_82849DE8 ==========\n");
    fflush(stderr);
}

// NOTE: PPC_FUNC_IMPL not needed - function already exists in recompiled code

// Hook the debug wrappers
// CRITICAL FIX (2025-11-01): REMOVED sub_8215CB08 hook - causes infinite recursion!
// The debug wrapper calls __imp__sub_8215CB08, which gets redirected back to the debug wrapper
// This creates infinite recursion and stack overflow, preventing the main loop from running
// GUEST_FUNCTION_HOOK(sub_8215CB08, sub_8215CB08_debug);  // DISABLED - infinite recursion bug
// MINIMAL OVERRIDES: Only override what's actually broken in the recompiled code
// 1. sub_82441E80: REMOVED - Let game run naturally, worker threads now fixed
// GUEST_FUNCTION_HOOK(sub_82441E80, sub_82441E80_debug);  // DISABLED - manual implementation hangs
// 2. sub_825A8698: Buggy CreateDevice function that causes crashes
GUEST_FUNCTION_HOOK(sub_825A8698, sub_825A8698_debug);
// 3. sub_8215C790, sub_8215C838, sub_821BB4D0: NOW RECOMPILED (added to MW05.toml)
//    No longer need wrappers - using recompiled versions

GUEST_FUNCTION_HOOK(__imp__XGetAVPack, XGetAVPack);
GUEST_FUNCTION_HOOK(__imp__XamLoaderTerminateTitle, XamLoaderTerminateTitle);
GUEST_FUNCTION_HOOK(__imp__XamGetExecutionId, XamGetExecutionId);
GUEST_FUNCTION_HOOK(__imp__XamLoaderLaunchTitle, XamLoaderLaunchTitle);
GUEST_FUNCTION_HOOK(__imp__RtlInitAnsiString, RtlInitAnsiString);
GUEST_FUNCTION_HOOK(__imp__NtSetInformationFile, NtSetInformationFile);
GUEST_FUNCTION_HOOK(__imp__FscSetCacheElementCount, FscSetCacheElementCount);
GUEST_FUNCTION_HOOK(__imp__NtWaitForSingleObjectEx, NtWaitForSingleObjectEx);
GUEST_FUNCTION_HOOK(__imp__ExGetXConfigSetting, ExGetXConfigSetting);
GUEST_FUNCTION_HOOK(__imp__NtQueryVirtualMemory, NtQueryVirtualMemory);
uint32_t NtProtectVirtualMemory(
    uint32_t /*ProcessHandle*/,
    be<uint32_t>* BaseAddress,
    be<uint32_t>* RegionSize,
    uint32_t NewProtect,
    be<uint32_t>* OldProtect)
{
    // Validate guest pointers
    auto valid_ptr = [](const void* p, size_t bytes) -> bool {
        if (!p) return false;
        const uint8_t* u = reinterpret_cast<const uint8_t*>(p);
        const uint8_t* b = g_memory.base;
        if (u < b + 4096) return false;
        size_t off = static_cast<size_t>(u - b);
        return off + bytes <= PPC_MEMORY_SIZE;
    };

    if (!valid_ptr(BaseAddress, sizeof(*BaseAddress)) || !valid_ptr(RegionSize, sizeof(*RegionSize)))
        return 0xC000000DL; // STATUS_INVALID_PARAMETER

    if (OldProtect && valid_ptr(OldProtect, sizeof(*OldProtect)))
        *OldProtect = PAGE_READWRITE; // report prior as RW for simplicity

    // We don’t enforce protection in host; treat as success.
    (void)NewProtect;
    return 0; // STATUS_SUCCESS
}

GUEST_FUNCTION_HOOK(__imp__NtProtectVirtualMemory, NtProtectVirtualMemory);
GUEST_FUNCTION_HOOK(__imp__MmQueryStatistics, MmQueryStatistics);
GUEST_FUNCTION_HOOK(__imp__NtCreateEvent, NtCreateEvent);
GUEST_FUNCTION_HOOK(__imp__XexCheckExecutablePrivilege, XexCheckExecutablePrivilege);
GUEST_FUNCTION_HOOK(__imp__DbgPrint, DbgPrint);
GUEST_FUNCTION_HOOK(__imp____C_specific_handler, __C_specific_handler_x);
GUEST_FUNCTION_HOOK(__imp__RtlNtStatusToDosError, RtlNtStatusToDosError);
GUEST_FUNCTION_HOOK(__imp__XexGetProcedureAddress, XexGetProcedureAddress);
GUEST_FUNCTION_HOOK(__imp__VdRegisterGraphicsNotificationRoutine, VdRegisterGraphicsNotificationRoutine);
GUEST_FUNCTION_HOOK(__imp__VdUnregisterGraphicsNotificationRoutine, VdUnregisterGraphicsNotificationRoutine);

GUEST_FUNCTION_HOOK(__imp__XexGetModuleSection, XexGetModuleSection);
GUEST_FUNCTION_HOOK(__imp__RtlUnicodeToMultiByteN, RtlUnicodeToMultiByteN);
GUEST_FUNCTION_HOOK(__imp__KeDelayExecutionThread, KeDelayExecutionThread);
GUEST_FUNCTION_HOOK(__imp__NtQueryInformationFile, NtQueryInformationFile);
GUEST_FUNCTION_HOOK(__imp__NtQueryVolumeInformationFile, NtQueryVolumeInformationFile);
GUEST_FUNCTION_HOOK(__imp__NtQueryDirectoryFile, NtQueryDirectoryFile);
GUEST_FUNCTION_HOOK(__imp__NtDuplicateObject, NtDuplicateObject);
GUEST_FUNCTION_HOOK(__imp__NtAllocateVirtualMemory, NtAllocateVirtualMemory);
GUEST_FUNCTION_HOOK(__imp__NtFreeVirtualMemory, NtFreeVirtualMemory);
GUEST_FUNCTION_HOOK(__imp__ObDereferenceObject, ObDereferenceObject);
GUEST_FUNCTION_HOOK(__imp__KeSetBasePriorityThread, KeSetBasePriorityThread);
GUEST_FUNCTION_HOOK(__imp__ObReferenceObjectByHandle, ObReferenceObjectByHandle);
GUEST_FUNCTION_HOOK(__imp__KeQueryBasePriorityThread, KeQueryBasePriorityThread);
GUEST_FUNCTION_HOOK(__imp__NtSuspendThread, NtSuspendThread);
GUEST_FUNCTION_HOOK(__imp__KeSetAffinityThread, KeSetAffinityThread);
GUEST_FUNCTION_HOOK(__imp__RtlLeaveCriticalSection, RtlLeaveCriticalSection);
GUEST_FUNCTION_HOOK(__imp__RtlEnterCriticalSection, RtlEnterCriticalSection);
GUEST_FUNCTION_HOOK(__imp__RtlImageXexHeaderField, RtlImageXexHeaderField);
GUEST_FUNCTION_HOOK(__imp__HalReturnToFirmware, HalReturnToFirmware);
GUEST_FUNCTION_HOOK(__imp__RtlFillMemoryUlong, RtlFillMemoryUlong);
GUEST_FUNCTION_HOOK(__imp__KeBugCheckEx, KeBugCheckEx);
GUEST_FUNCTION_HOOK(__imp__KeGetCurrentProcessType, KeGetCurrentProcessType);
GUEST_FUNCTION_HOOK(__imp__RtlCompareMemoryUlong, RtlCompareMemoryUlong);
GUEST_FUNCTION_HOOK(__imp__RtlInitializeCriticalSection, RtlInitializeCriticalSection);
GUEST_FUNCTION_HOOK(__imp__RtlRaiseException, RtlRaiseException_x);
GUEST_FUNCTION_HOOK(__imp__KfReleaseSpinLock, KfReleaseSpinLock);
GUEST_FUNCTION_HOOK(__imp__KfAcquireSpinLock, KfAcquireSpinLock);
GUEST_FUNCTION_HOOK(__imp__KeQueryPerformanceFrequency, KeQueryPerformanceFrequency);
GUEST_FUNCTION_HOOK(__imp__MmFreePhysicalMemory, MmFreePhysicalMemory);
GUEST_FUNCTION_HOOK(__imp__VdPersistDisplay, VdPersistDisplay);
GUEST_FUNCTION_HOOK(__imp__VdSwap, VdSwap);
GUEST_FUNCTION_HOOK(__imp__VdGetSystemCommandBuffer, VdGetSystemCommandBuffer);
GUEST_FUNCTION_HOOK(__imp__KeReleaseSpinLockFromRaisedIrql, KeReleaseSpinLockFromRaisedIrql);
GUEST_FUNCTION_HOOK(__imp__KeAcquireSpinLockAtRaisedIrql, KeAcquireSpinLockAtRaisedIrql);
GUEST_FUNCTION_HOOK(__imp__KiApcNormalRoutineNop, KiApcNormalRoutineNop);
GUEST_FUNCTION_HOOK(__imp__VdEnableRingBufferRPtrWriteBack, VdEnableRingBufferRPtrWriteBack);
GUEST_FUNCTION_HOOK(__imp__VdInitializeRingBuffer, VdInitializeRingBuffer);
GUEST_FUNCTION_HOOK(__imp__MmGetPhysicalAddress, MmGetPhysicalAddress);
GUEST_FUNCTION_HOOK(__imp__VdSetSystemCommandBufferGpuIdentifierAddress, VdSetSystemCommandBufferGpuIdentifierAddress);
GUEST_FUNCTION_HOOK(__imp__ExRegisterTitleTerminateNotification, ExRegisterTitleTerminateNotification);
GUEST_FUNCTION_HOOK(__imp__VdShutdownEngines, VdShutdownEngines);
GUEST_FUNCTION_HOOK(__imp__VdQueryVideoMode, VdQueryVideoMode);
GUEST_FUNCTION_HOOK(__imp__VdGetCurrentDisplayInformation, VdGetCurrentDisplayInformation);
GUEST_FUNCTION_HOOK(__imp__VdSetDisplayMode, VdSetDisplayMode);
GUEST_FUNCTION_HOOK(__imp__VdSetGraphicsInterruptCallback, VdSetGraphicsInterruptCallback);
GUEST_FUNCTION_HOOK(__imp__VdInitializeEngines, VdInitializeEngines);
GUEST_FUNCTION_HOOK(__imp__VdIsHSIOTrainingSucceeded, VdIsHSIOTrainingSucceeded);
GUEST_FUNCTION_HOOK(__imp__VdGetCurrentDisplayGamma, VdGetCurrentDisplayGamma);
GUEST_FUNCTION_HOOK(__imp__VdQueryVideoFlags, VdQueryVideoFlags);
GUEST_FUNCTION_HOOK(__imp__VdCallGraphicsNotificationRoutines, VdCallGraphicsNotificationRoutines);
GUEST_FUNCTION_HOOK(__imp__VdInitializeScalerCommandBuffer, VdInitializeScalerCommandBuffer);
GUEST_FUNCTION_HOOK(__imp__KeLeaveCriticalRegion, KeLeaveCriticalRegion);
GUEST_FUNCTION_HOOK(__imp__VdRetrainEDRAM, VdRetrainEDRAM);
GUEST_FUNCTION_HOOK(__imp__VdRetrainEDRAMWorker, VdRetrainEDRAMWorker);
GUEST_FUNCTION_HOOK(__imp__KeEnterCriticalRegion, KeEnterCriticalRegion);
GUEST_FUNCTION_HOOK(__imp__MmAllocatePhysicalMemoryEx, MmAllocatePhysicalMemoryEx);
GUEST_FUNCTION_HOOK(__imp__ObDeleteSymbolicLink, ObDeleteSymbolicLink);
GUEST_FUNCTION_HOOK(__imp__ObCreateSymbolicLink, ObCreateSymbolicLink);
GUEST_FUNCTION_HOOK(__imp__MmQueryAddressProtect, MmQueryAddressProtect);
GUEST_FUNCTION_HOOK(__imp__VdEnableDisableClockGating, VdEnableDisableClockGating);
GUEST_FUNCTION_HOOK(__imp__KeBugCheck, KeBugCheck);
GUEST_FUNCTION_HOOK(__imp__KeLockL2, KeLockL2);
GUEST_FUNCTION_HOOK(__imp__KeUnlockL2, KeUnlockL2);
GUEST_FUNCTION_HOOK(__imp__KeSetEvent, KeSetEvent);
GUEST_FUNCTION_HOOK(__imp__KeResetEvent, KeResetEvent);
GUEST_FUNCTION_HOOK(__imp__KeWaitForSingleObject, KeWaitForSingleObject);
GUEST_FUNCTION_HOOK(__imp__KeTlsGetValue, KeTlsGetValue);
GUEST_FUNCTION_HOOK(__imp__KeTlsSetValue, KeTlsSetValue);
GUEST_FUNCTION_HOOK(__imp__KeTlsAlloc, KeTlsAlloc);
GUEST_FUNCTION_HOOK(__imp__KeTlsFree, KeTlsFree);
GUEST_FUNCTION_HOOK(__imp__XMsgInProcessCall, XMsgInProcessCall);
GUEST_FUNCTION_HOOK(__imp__XamUserReadProfileSettings, XamUserReadProfileSettings);
GUEST_FUNCTION_HOOK(__imp__NetDll_WSAStartup, NetDll_WSAStartup);
GUEST_FUNCTION_HOOK(__imp__NetDll_WSACleanup, NetDll_WSACleanup);
GUEST_FUNCTION_HOOK(__imp__NetDll_socket, NetDll_socket);
GUEST_FUNCTION_HOOK(__imp__NetDll_closesocket, NetDll_closesocket);
GUEST_FUNCTION_HOOK(__imp__NetDll_setsockopt, NetDll_setsockopt);
GUEST_FUNCTION_HOOK(__imp__NetDll_bind, NetDll_bind);
GUEST_FUNCTION_HOOK(__imp__NetDll_connect, NetDll_connect);
GUEST_FUNCTION_HOOK(__imp__NetDll_listen, NetDll_listen);
GUEST_FUNCTION_HOOK(__imp__NetDll_accept, NetDll_accept);
GUEST_FUNCTION_HOOK(__imp__NetDll_select, NetDll_select);
GUEST_FUNCTION_HOOK(__imp__NetDll_recv, NetDll_recv);
GUEST_FUNCTION_HOOK(__imp__NetDll_send, NetDll_send);
GUEST_FUNCTION_HOOK(__imp__NetDll_inet_addr, NetDll_inet_addr);
GUEST_FUNCTION_HOOK(__imp__NetDll___WSAFDIsSet, NetDll___WSAFDIsSet);
GUEST_FUNCTION_HOOK(__imp__XMsgStartIORequestEx, XMsgStartIORequestEx);
GUEST_FUNCTION_HOOK(__imp__XamInputGetCapabilities, XamInputGetCapabilities);
GUEST_FUNCTION_HOOK(__imp__XamInputGetState, XamInputGetState);
GUEST_FUNCTION_HOOK(__imp__XamInputSetState, XamInputSetState);
GUEST_FUNCTION_HOOK(__imp__XexGetModuleHandle, XexGetModuleHandle);
GUEST_FUNCTION_HOOK(__imp__RtlTryEnterCriticalSection, RtlTryEnterCriticalSection);
GUEST_FUNCTION_HOOK(__imp__RtlInitializeCriticalSectionAndSpinCount, RtlInitializeCriticalSectionAndSpinCount);
GUEST_FUNCTION_HOOK(__imp__XeCryptBnQwBeSigVerify, XeCryptBnQwBeSigVerify);
GUEST_FUNCTION_HOOK(__imp__XeKeysGetKey, XeKeysGetKey);
GUEST_FUNCTION_HOOK(__imp__XeCryptRotSumSha, XeCryptRotSumSha);
GUEST_FUNCTION_HOOK(__imp__XeCryptSha, XeCryptSha);
GUEST_FUNCTION_HOOK(__imp__KeEnableFpuExceptions, KeEnableFpuExceptions);
GUEST_FUNCTION_HOOK(__imp__RtlUnwind, RtlUnwind_x);
GUEST_FUNCTION_HOOK(__imp__RtlCaptureContext, RtlCaptureContext_x);
GUEST_FUNCTION_HOOK(__imp__NtQueryFullAttributesFile, NtQueryFullAttributesFile);
GUEST_FUNCTION_HOOK(__imp__RtlMultiByteToUnicodeN, RtlMultiByteToUnicodeN);
GUEST_FUNCTION_HOOK(__imp__DbgBreakPoint, DbgBreakPoint);
GUEST_FUNCTION_HOOK(__imp__MmQueryAllocationSize, MmQueryAllocationSize);
GUEST_FUNCTION_HOOK(__imp__NtClearEvent, NtClearEvent);
GUEST_FUNCTION_HOOK(__imp__NtResumeThread, NtResumeThread);
GUEST_FUNCTION_HOOK(__imp__NtSetEvent, NtSetEvent);
GUEST_FUNCTION_HOOK(__imp__NtCreateSemaphore, NtCreateSemaphore);
GUEST_FUNCTION_HOOK(__imp__NtReleaseSemaphore, NtReleaseSemaphore);
GUEST_FUNCTION_HOOK(__imp__NtWaitForMultipleObjectsEx, NtWaitForMultipleObjectsEx);
GUEST_FUNCTION_HOOK(__imp__RtlCompareStringN, RtlCompareStringN);
GUEST_FUNCTION_HOOK(__imp__StfsControlDevice, StfsControlDevice);
GUEST_FUNCTION_HOOK(__imp__StfsCreateDevice, StfsCreateDevice);
GUEST_FUNCTION_HOOK(__imp__NtFlushBuffersFile, NtFlushBuffersFile);
GUEST_FUNCTION_HOOK(__imp__KeQuerySystemTime, KeQuerySystemTime);
GUEST_FUNCTION_HOOK(__imp__RtlTimeToTimeFields, RtlTimeToTimeFields);
GUEST_FUNCTION_HOOK(__imp__RtlFreeAnsiString, RtlFreeAnsiString);
GUEST_FUNCTION_HOOK(__imp__RtlUnicodeStringToAnsiString, RtlUnicodeStringToAnsiString);
GUEST_FUNCTION_HOOK(__imp__RtlInitUnicodeString, RtlInitUnicodeString);
GUEST_FUNCTION_HOOK(__imp__ExTerminateThread, ExTerminateThread);
GUEST_FUNCTION_HOOK(__imp__ExCreateThread, ExCreateThread);
GUEST_FUNCTION_HOOK(__imp__IoInvalidDeviceRequest, IoInvalidDeviceRequest);
GUEST_FUNCTION_HOOK(__imp__ObReferenceObject, ObReferenceObject);
GUEST_FUNCTION_HOOK(__imp__IoCreateDevice, IoCreateDevice);
GUEST_FUNCTION_HOOK(__imp__IoDeleteDevice, IoDeleteDevice);
GUEST_FUNCTION_HOOK(__imp__RtlTimeFieldsToTime, RtlTimeFieldsToTime);
GUEST_FUNCTION_HOOK(__imp__IoCompleteRequest, IoCompleteRequest);
GUEST_FUNCTION_HOOK(__imp__RtlUpcaseUnicodeChar, RtlUpcaseUnicodeChar);
GUEST_FUNCTION_HOOK(__imp__ObIsTitleObject, ObIsTitleObject);
GUEST_FUNCTION_HOOK(__imp__IoCheckShareAccess, IoCheckShareAccess);
GUEST_FUNCTION_HOOK(__imp__IoSetShareAccess, IoSetShareAccess);
GUEST_FUNCTION_HOOK(__imp__IoRemoveShareAccess, IoRemoveShareAccess);
GUEST_FUNCTION_HOOK(__imp__NetDll_XNetStartup, NetDll_XNetStartup);
GUEST_FUNCTION_HOOK(__imp__NetDll_XNetGetTitleXnAddr, NetDll_XNetGetTitleXnAddr);
GUEST_FUNCTION_HOOK(__imp__KeWaitForMultipleObjects, KeWaitForMultipleObjects);
GUEST_FUNCTION_HOOK(__imp__KeRaiseIrqlToDpcLevel, KeRaiseIrqlToDpcLevel);
GUEST_FUNCTION_HOOK(__imp__KfLowerIrql, KfLowerIrql);
GUEST_FUNCTION_HOOK(__imp__KeReleaseSemaphore, KeReleaseSemaphore);
GUEST_FUNCTION_HOOK(__imp__XAudioGetVoiceCategoryVolume, XAudioGetVoiceCategoryVolume);
GUEST_FUNCTION_HOOK(__imp__XAudioGetVoiceCategoryVolumeChangeMask, XAudioGetVoiceCategoryVolumeChangeMask);
GUEST_FUNCTION_HOOK(__imp__KeResumeThread, KeResumeThread);
GUEST_FUNCTION_HOOK(__imp__KeInitializeSemaphore, KeInitializeSemaphore);
GUEST_FUNCTION_HOOK(__imp__XMAReleaseContext, XMAReleaseContext);
GUEST_FUNCTION_HOOK(__imp__XMACreateContext, XMACreateContext);
GUEST_FUNCTION_HOOK(__imp__XAudioRegisterRenderDriverClient, XAudioRegisterRenderDriverClient);
GUEST_FUNCTION_HOOK(__imp__XAudioUnregisterRenderDriverClient, XAudioUnregisterRenderDriverClient);
GUEST_FUNCTION_HOOK(__imp__XAudioSubmitRenderDriverFrame, XAudioSubmitRenderDriverFrame);

// Additional networking (WSA/XNP) stubs required by PPC mapping but unused in offline mode
GUEST_FUNCTION_STUB(__imp__NetDll_WSASend);
GUEST_FUNCTION_STUB(__imp__NetDll_sendto);
GUEST_FUNCTION_STUB(__imp__NetDll_WSASendTo);
GUEST_FUNCTION_STUB(__imp__NetDll_WSAEventSelect);
GUEST_FUNCTION_STUB(__imp__NetDll_WSAGetLastError);
GUEST_FUNCTION_STUB(__imp__NetDll_WSASetLastError);
GUEST_FUNCTION_STUB(__imp__NetDll_WSACreateEvent);
GUEST_FUNCTION_STUB(__imp__NetDll_WSACloseEvent);
GUEST_FUNCTION_STUB(__imp__NetDll_WSASetEvent);
GUEST_FUNCTION_STUB(__imp__NetDll_WSAResetEvent);
GUEST_FUNCTION_STUB(__imp__NetDll_WSAWaitForMultipleEvents);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLoadConfigParams);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpSaveConfigParams);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpConfigUPnP);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpConfig);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpGetConfigStatus);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLoadMachineAccount);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpSaveMachineAccount);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpCapture);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpEthernetInterceptSetCallbacks);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpEthernetInterceptXmit);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpEthernetInterceptRecv);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonGetStatus);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonGetQFlags);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonSetQFlags);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonSetQEvent);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonClearQEvent);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonGetQVals);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonSetQVals);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpLogonSetPState);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpGetVlanXboxName);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpSetVlanXboxName);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpGetActiveSocketList);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpNoteSystemTime);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpRegisterKeyForCallerType);
GUEST_FUNCTION_STUB(__imp__NetDll_XnpUnregisterKeyForCallerType);
GUEST_FUNCTION_STUB(__imp__XNetLogonGetMachineID);
GUEST_FUNCTION_STUB(__imp__XamUserGetOnlineCountryFromXUID);
GUEST_FUNCTION_STUB(__imp__XamUserGetMembershipTierFromXUID);
GUEST_FUNCTION_STUB(__imp__XamSessionRefObjByHandle);
GUEST_FUNCTION_STUB(__imp__XamSessionCreateHandle);
GUEST_FUNCTION_STUB(__imp__XamContentCreate);
GUEST_FUNCTION_STUB(__imp__XamContentInstall);
GUEST_FUNCTION_STUB(__imp__XamContentFlush);
GUEST_FUNCTION_STUB(__imp__XamContentSetThumbnail);
GUEST_FUNCTION_STUB(__imp__XamContentGetThumbnail);
GUEST_FUNCTION_STUB(__imp__XamContentGetLicenseMask);
GUEST_FUNCTION_STUB(__imp__XamContentCreateDeviceEnumerator);
GUEST_FUNCTION_STUB(__imp__XamContentGetDeviceName);
GUEST_FUNCTION_STUB(__imp__XamContentLaunchImage);
GUEST_FUNCTION_STUB(__imp__XeKeysGetKeyProperties);
GUEST_FUNCTION_STUB(__imp__XeCryptAesKey);
GUEST_FUNCTION_STUB(__imp__XeCryptAesEcb);
GUEST_FUNCTION_STUB(__imp__XeKeysQwNeRsaPrvCrypt);
GUEST_FUNCTION_STUB(__imp__XeCryptBnQw_SwapDwQwLeBe);
GUEST_FUNCTION_STUB(__imp__XeCryptRandom);
GUEST_FUNCTION_STUB(__imp__XeCryptShaFinal);
GUEST_FUNCTION_STUB(__imp__XeCryptShaUpdate);
GUEST_FUNCTION_STUB(__imp__XeCryptShaInit);
GUEST_FUNCTION_STUB(__imp__XeCryptBnQwNeRsaPubCrypt);

// Additional stubs: XeCrypt/XeKeys, XMA, NT timers
GUEST_FUNCTION_STUB(__imp__XeCryptBnQwNeRsaPrvCrypt);
GUEST_FUNCTION_STUB(__imp__XeCryptBnQwNeRsaKeyGen);
GUEST_FUNCTION_STUB(__imp__XeCryptRc4Key);
GUEST_FUNCTION_STUB(__imp__XeCryptRc4Ecb);

GUEST_FUNCTION_STUB(__imp__XMAGetOutputBufferWriteOffset);
GUEST_FUNCTION_STUB(__imp__XMASetInputBuffer1);
GUEST_FUNCTION_STUB(__imp__XMASetOutputBufferReadOffset);
GUEST_FUNCTION_STUB(__imp__XMAInitializeContext);
GUEST_FUNCTION_STUB(__imp__XMASetInputBuffer0);
GUEST_FUNCTION_STUB(__imp__XMADisableContext);
GUEST_FUNCTION_STUB(__imp__XMAEnableContext);
GUEST_FUNCTION_STUB(__imp__XMAIsOutputBufferValid);
GUEST_FUNCTION_STUB(__imp__XMASetInputBuffer0Valid);
GUEST_FUNCTION_STUB(__imp__XMAGetOutputBufferReadOffset);
GUEST_FUNCTION_STUB(__imp__XMAIsInputBuffer1Valid);
GUEST_FUNCTION_STUB(__imp__XMASetOutputBufferValid);
GUEST_FUNCTION_STUB(__imp__XMAIsInputBuffer0Valid);
GUEST_FUNCTION_STUB(__imp__XMASetInputBuffer1Valid);

GUEST_FUNCTION_HOOK(__imp__NtSetTimerEx, NtSetTimerEx);
GUEST_FUNCTION_HOOK(__imp__NtCreateTimer, NtCreateTimer);

// Additional minimal stubs to satisfy link for mappings that are unused at runtime.
GUEST_FUNCTION_STUB(__imp__Refresh);
GUEST_FUNCTION_STUB(__imp__XamInputGetKeystrokeEx);
GUEST_FUNCTION_HOOK(__imp__VdGetGraphicsAsicID, VdGetGraphicsAsicID);
GUEST_FUNCTION_HOOK(__imp__VdQuerySystemCommandBuffer, VdQuerySystemCommandBuffer);
GUEST_FUNCTION_HOOK(__imp__VdSetSystemCommandBuffer, VdSetSystemCommandBuffer);
GUEST_FUNCTION_HOOK(__imp__VdInitializeEDRAM, VdInitializeEDRAM);
GUEST_FUNCTION_HOOK(__imp__MmSetAddressProtect, MmSetAddressProtect);
GUEST_FUNCTION_HOOK(__imp__NtCreateIoCompletion, NtCreateIoCompletion);
GUEST_FUNCTION_HOOK(__imp__NtSetIoCompletion, NtSetIoCompletion);
GUEST_FUNCTION_HOOK(__imp__NtRemoveIoCompletion, NtRemoveIoCompletion);
GUEST_FUNCTION_HOOK(__imp__ObOpenObjectByPointer, ObOpenObjectByPointer);
GUEST_FUNCTION_HOOK(__imp__ObLookupThreadByThreadId, ObLookupThreadByThreadId);
GUEST_FUNCTION_HOOK(__imp__KeSetDisableBoostThread, KeSetDisableBoostThread);
GUEST_FUNCTION_HOOK(__imp__NtQueueApcThread, NtQueueApcThread);
GUEST_FUNCTION_STUB(__imp__RtlCompareMemory);
GUEST_FUNCTION_STUB(__imp__XamCreateEnumeratorHandle);
GUEST_FUNCTION_STUB(__imp__XMsgSystemProcessCall);
GUEST_FUNCTION_STUB(__imp__XamGetPrivateEnumStructureFromHandle);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetCleanup);

// Missing exports reported by linker for PPC mappings
GUEST_FUNCTION_HOOK(__imp__NtCreateMutant, NtCreateMutant);
GUEST_FUNCTION_HOOK(__imp__NtReleaseMutant, NtReleaseMutant);
GUEST_FUNCTION_HOOK(__imp__NtYieldExecution, NtYieldExecution);
GUEST_FUNCTION_STUB(__imp__FscGetCacheElementCount);
GUEST_FUNCTION_STUB(__imp__XamVoiceHeadsetPresent);
GUEST_FUNCTION_STUB(__imp__XamVoiceClose);
GUEST_FUNCTION_STUB(__imp__XMsgCancelIORequest);
GUEST_FUNCTION_STUB(__imp__XamVoiceSubmitPacket);
GUEST_FUNCTION_STUB(__imp__XamVoiceCreate);
GUEST_FUNCTION_STUB(__imp__XAudioQueryDriverPerformance);
GUEST_FUNCTION_HOOK(__imp__KeTryToAcquireSpinLockAtRaisedIrql, KeTryToAcquireSpinLockAtRaisedIrql);
GUEST_FUNCTION_HOOK(__imp__KePulseEvent, KePulseEvent);
GUEST_FUNCTION_HOOK(__imp__MmAllocatePhysicalMemory, MmAllocatePhysicalMemory);
GUEST_FUNCTION_STUB(__imp__XMASetInputBufferReadOffset);
GUEST_FUNCTION_STUB(__imp__XMABlockWhileInUse);
GUEST_FUNCTION_STUB(__imp__XMASetLoopData);
GUEST_FUNCTION_HOOK(__imp__NtCancelTimer, NtCancelTimer);
GUEST_FUNCTION_HOOK(__imp__ObOpenObjectByName, ObOpenObjectByName);
GUEST_FUNCTION_HOOK(__imp__NtPulseEvent, NtPulseEvent);
GUEST_FUNCTION_HOOK(__imp__NtSignalAndWaitForSingleObjectEx, NtSignalAndWaitForSingleObjectEx);
// Networking (XNet) stubs
GUEST_FUNCTION_STUB(__imp__NetDll_XNetRandom);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetCreateKey);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetRegisterKey);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetUnregisterKey);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetXnAddrToInAddr);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetServerToInAddr);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetTsAddrToInAddr);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetInAddrToXnAddr);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetInAddrToServer);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetInAddrToString);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetUnregisterInAddr);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetXnAddrToMachineId);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetConnect);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetGetConnectStatus);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetDnsLookup);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetDnsRelease);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetQosListen);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetQosLookup);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetQosServiceLookup);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetQosRelease);

// Networking/additional import stubs continued
GUEST_FUNCTION_STUB(__imp__NetDll_XNetGetDebugXnAddr);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetGetEthernetLinkStatus);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetGetBroadcastVersionStatus);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetQosGetListenStats);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetGetOpt);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetSetOpt);
GUEST_FUNCTION_STUB(__imp__XNetLogonGetTitleID);
GUEST_FUNCTION_STUB(__imp__XamUserWriteProfileSettings);
GUEST_FUNCTION_STUB(__imp__NetDll_shutdown);
GUEST_FUNCTION_STUB(__imp__NetDll_ioctlsocket);
GUEST_FUNCTION_STUB(__imp__NetDll_getsockopt);
GUEST_FUNCTION_STUB(__imp__NetDll_getsockname);
GUEST_FUNCTION_STUB(__imp__NetDll_getpeername);
GUEST_FUNCTION_STUB(__imp__NetDll_WSAGetOverlappedResult);
GUEST_FUNCTION_STUB(__imp__NetDll_WSACancelOverlappedIO);
GUEST_FUNCTION_STUB(__imp__NetDll_WSARecv);
GUEST_FUNCTION_STUB(__imp__NetDll_recvfrom);
GUEST_FUNCTION_STUB(__imp__NetDll_WSARecvFrom);
