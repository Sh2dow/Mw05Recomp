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
#include "vm_arena.h"
#include <memory>
#include <map>
#include <mutex>
#include "xam.h"
#include "xdm.h"
#include <user/config.h>
#include <ui/game_window.h>
#include <os/logger.h>
#include <gpu/video.h>
#include <gpu/pm4_parser.h>

// Forward decl: original guest MW05 present-wrapper body
extern "C" void __imp__sub_82598A20(PPCContext& ctx, uint8_t* base);

// Trace shim export: last-seen scheduler r3 (captured in mw05_trace_shims.cpp)
extern "C" uint32_t Mw05Trace_LastSchedR3();
extern "C" uint32_t Mw05Trace_SchedR3SeenCount();


// Diagnostic forward decl for MW05 micro-interpreter
extern "C" void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size);


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

extern "C" void Mw05NoteHostPresent(uint64_t ms)
{
    g_lastPresentMs.store(ms, std::memory_order_release);
}


extern "C"
{
	bool Mw05SawRealVdSwap() { return g_sawRealVdSwap.load(std::memory_order_acquire); }

	bool Mw05HasGuestSwapped() { return g_guestHasSwapped.load(std::memory_order_acquire); }

	uint32_t Mw05ConsumeSchedulerBlockEA();
	uint32_t Mw05GetSchedulerHandleEA();
	uint32_t Mw05GetSchedulerTimeoutEA();
	void Mw05ForceVdInitOnce();
	void Mw05LogIsrIfRegisteredOnce();
	void VdInitializeEngines();

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
    // Forward decl: MW05 PM4 builder shim entry (defined in mw05_trace_shims.cpp)
    void MW05Shim_sub_825972B0(PPCContext& ctx, uint8_t* base);



// Forward declarations for VD bridge helpers used across this file
void VdSetGraphicsInterruptCallback(uint32_t callback, uint32_t context);
void VdRegisterGraphicsNotificationRoutine(uint32_t callback, uint32_t context);


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

static void Mw05AutoVideoInitIfNeeded() {
    // One-time optional forced registration via env var
    Mw05MaybeForceRegisterVdEventFromEnv();

    if (!Mw05AutoVideoEnabled()) return;
    bool expected = false;
    if (!g_autoVideoDone.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    // If a ring and write-back already exist, skip.
    if (g_RbLen.load(std::memory_order_relaxed) != 0 &&
        g_RbWriteBackPtr.load(std::memory_order_relaxed) != 0) {
        return;
    }

    // Ensure a system command buffer exists for callers that query it later.
    VdGetSystemCommandBuffer(nullptr, nullptr);

    const uint32_t len_log2 = 16; // 64 KiB ring (closer to MW05 expectations)
    const uint32_t size_bytes = 1u << len_log2;
    void* ring_host = g_userHeap.Alloc(size_bytes, 0x100);
    if (!ring_host) return;
    const uint32_t ring_guest = g_memory.MapVirtual(ring_host);

    void* wb_host = g_userHeap.Alloc(64, 4);
    if (!wb_host) return;
    const uint32_t wb_guest = g_memory.MapVirtual(wb_host);

    KernelTraceHostOpF("HOST.AutoVideo.Init ring=%08X len_log2=%u wb=%08X", ring_guest, len_log2, wb_guest);
    VdInitializeRingBuffer(ring_guest, len_log2);
    VdEnableRingBufferRPtrWriteBack(wb_guest);
    VdSetSystemCommandBufferGpuIdentifierAddress(wb_guest + 8);
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
static std::atomic<uint32_t> g_VdGraphicsCallback{0};
static std::atomic<uint32_t> g_VdGraphicsCallbackCtx{0};

static std::atomic<uint32_t> g_SysCmdBufValue{0};

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
static std::mutex g_VdNotifMutex;
static std::vector<std::pair<uint32_t,uint32_t>> g_VdNotifList;

static inline bool Mw05EnvEnabled(const char* name) {
    if (const char* v = std::getenv(name)) return !(v[0]=='0' && v[1]=='\0');
    return false;
}
static void Mw05MaybeInstallDefaultVdIsr() {
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

static bool Mw05SignalVdInterruptEvent();
static void Mw05DispatchVdInterruptIfPending();

extern "C" {
	uint32_t VdGetGraphicsInterruptCallback() { return g_VdGraphicsCallback.load(); }
	uint32_t VdGetGraphicsInterruptContext() {
	    uint32_t ctx = g_VdGraphicsCallbackCtx.load();
	    // Optional: override ISR context globally with the discovered scheduler pointer.
	    // This centralizes the override instead of patching every callsite.
	    static const bool s_force_ctx_sched = [](){
	        if (const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED")) return !(v[0]=='0' && v[1]=='\0');
	        return false;
	    }();
	    if (!s_force_ctx_sched) return ctx;

	    // Gating to avoid early-boot crashes: wait some vblank ticks and a few stable sightings
	    static const uint32_t s_ctx_delay_ticks = [](){
	        if (const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED_DELAY_TICKS"))
	            return (uint32_t)std::strtoul(v, nullptr, 0);
	        return (uint32_t)120; // default ~2s at 60 Hz
	    }();
	    static const uint32_t s_seen_min = [](){
	        if (const char* v = std::getenv("MW05_VD_ISR_CTX_SEEN_MIN"))
	            return (uint32_t)std::strtoul(v, nullptr, 0);
	        return (uint32_t)2; // need at least 2 stable sightings
	    }();

	    const uint32_t ticks = g_vblankTicks.load(std::memory_order_acquire);
	    if (ticks < s_ctx_delay_ticks) return ctx;

	    uint32_t sched = Mw05Trace_LastSchedR3();
	    bool seeded_env = false;
	    // Allow explicit seeding from env if trace hasn't seen a good pointer yet
	    if (!GuestOffsetInRange(sched, 4)) {
	        if (const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
	            uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
	            if (GuestOffsetInRange(env_r3, 4)) { sched = env_r3; seeded_env = true; }
	        }
	    }

	    if (GuestOffsetInRange(sched, 4)) {
	        const uint32_t seen = Mw05Trace_SchedR3SeenCount();
	        // If seeded from env, allow immediate override; otherwise require stable sightings
	        if (seeded_env || (seen >= s_seen_min)) {
	            static bool s_logged = false;
	            if (!s_logged) {
	                KernelTraceHostOpF("HOST.VdGetGraphicsInterruptContext.override ctx=%08X->%08X ticks=%u seen=%u%s", ctx, sched, (unsigned)ticks, (unsigned)seen, seeded_env?" (env)":"");
	                s_logged = true;
	            }
	            return sched;
	        }
	    }
	    return ctx;
	}
	uint32_t Mw05GetHostDefaultVdIsrMagic() { return kHostDefaultVdIsrMagic; }

	bool KeSetEvent(XKEVENT* pEvent, uint32_t Increment, bool Wait);
	bool KeResetEvent(XKEVENT* pEvent);

	void Mw05RunHostDefaultVdIsrNudge(const char* tag)
	{
        // Controls whether the host default VD ISR requests a Present at the end of each nudge.
        // Default: enabled (preserves current behavior). Set MW05_ISR_AUTO_PRESENT=0 to disable for diagnostics.
        static const bool s_isr_auto_present = [](){
            if (const char* v = std::getenv("MW05_ISR_AUTO_PRESENT"))
                return !(v[0]=='0' && v[1]=='\0');
            return true;
        }();

        static thread_local bool s_inHostIsrNudge = false;
        if (s_inHostIsrNudge) {
            KernelTraceHostOp("HOST.HostDefaultVdIsr.nudge.reentrant");
            return;
        }
        s_inHostIsrNudge = true;

        if (tag) KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge.%s", tag);
        else     KernelTraceHostOp("HOST.HostDefaultVdIsr.nudge");

        // Adjustable ring write-back step
        uint32_t step = 0x40u;
        if (const char* s = std::getenv("MW05_HOST_ISR_RB_STEP")) {
            // Accept hex (0x...) or decimal

        // Controls whether the host default VD ISR requests a Present at the end of each nudge.
        // Default: enabled (preserves current behavior). Set MW05_ISR_AUTO_PRESENT=0 to disable for diagnostics.
        static const bool s_isr_auto_present = [](){
            if (const char* v = std::getenv("MW05_ISR_AUTO_PRESENT"))
                return !(v[0]=='0' && v[1]=='\0');
            return true;
        }();

            char* endp = nullptr;
            unsigned long v = std::strtoul(s, &endp, (s[0]=='0' && (s[1]=='x'||s[1]=='X')) ? 16 : 10);
            if (v > 0 && v < 0x100000) step = static_cast<uint32_t>(v);
        }

        // Bump ring write-back pointer
        if (uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed)) {
            if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb))) {
                uint32_t cur = *rptr;
                uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
                uint32_t mask = len_log2 ? ((1u << len_log2) - 1u) : 0xFFFFu;
                uint32_t next = (cur + step) & mask;
                uint32_t write = next ? next : 0x20u;
                *rptr = write;
                KernelTraceHostOpF("HOST.RB.rptr.bump ea=%08X cur=%08X next=%08X step=%u mask=%08X", wb, cur, write, step, mask);
            }
        }

        // Optional: scan the ring buffer periodically early-on to surface TYPE3 packets (env: MW05_PM4_SCAN_RING=1)
        {
            static uint32_t s_ring_scan_count = 0;
            static const bool s_scan_ring = [](){ if (const char* v = std::getenv("MW05_PM4_SCAN_RING")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
            if (s_scan_ring && s_ring_scan_count < 8) {
                const uint32_t base = g_RbBase.load(std::memory_order_relaxed);
                const uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
                if (base && len_log2) {
                    const uint32_t bytes = 1u << len_log2;
                    KernelTraceHostOpF("HOST.PM4.ScanLinear.RingTick base=%08X bytes=%u tick_scan=%u", base, bytes, s_ring_scan_count);
                    PM4_ScanLinear(base, bytes);
                    ++s_ring_scan_count;
                }
        // Optional: try calling the MW05 PM4 builder shim from ISR a few times early (env: MW05_ISR_TRY_BUILDER=1)
        {
            static uint32_t s_builder_calls = 0;
            static const bool s_try_builder = [](){ if (const char* v = std::getenv("MW05_ISR_TRY_BUILDER")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
            if (s_try_builder && s_builder_calls < 3) {
                uint32_t seed = Mw05Trace_LastSchedR3();
                if (!(seed >= 0x1000u)) seed = 0x00060E30u;
                if (seed >= 0x1000u) {
                    // Ensure guest context on this thread to preserve TOC/r13 etc.
                    EnsureGuestContextForThisThread("HostDefaultVdIsr");
                    PPCContext ctx{};
                    if (auto* cur = GetPPCContext()) ctx = *cur;
                    ctx.r3.u32 = seed;
                    if (ctx.r4.u32 == 0) ctx.r4.u32 = 0x40;
                    uint8_t* base = g_memory.base;
                    KernelTraceHostOpF("HOST.ISR.pm4_forward r3=%08X r4=%08X call=%u", ctx.r3.u32, ctx.r4.u32, s_builder_calls);
                    MW05Shim_sub_825972B0(ctx, base);
                    ++s_builder_calls;
                }
            }
        }

            }
        }

        // Optionally ACK the VD event directly in ISR path
        if (const char* a = std::getenv("MW05_HOST_ISR_ACK_EVENT")) {
            if (!(a[0]=='0' && a[1]=='\0')) {
                const uint32_t eventEA = g_vdInterruptEventEA.load(std::memory_order_acquire);
                if (eventEA) {
                    if (GuestOffsetInRange(eventEA, sizeof(uint64_t))) {
                        if (auto* ps = static_cast<uint8_t*>(g_memory.Translate(eventEA))) {
                            *reinterpret_cast<uint64_t*>(ps) = 0ull;
                            KernelTraceHostOpF("HOST.HostDefaultVdIsr.ack.status.zero ea=%08X", eventEA);
                        }
                    }
                    if (GuestOffsetInRange(eventEA - 8, sizeof(uint64_t))) {
                        if (auto* p2 = static_cast<uint8_t*>(g_memory.Translate(eventEA - 8))) {
                            *reinterpret_cast<uint64_t*>(p2) = 0ull;
                            KernelTraceHostOpF("HOST.HostDefaultVdIsr.ack.ptr.zero ea=%08X", eventEA - 8);
                        }
                    }

                    // Optionally clear scheduler block header that the waiter fences on
                    bool do_sched_clear = false;
                    if (const char* sc = std::getenv("MW05_HOST_ISR_SCHED_CLEAR")) {
                        do_sched_clear = !(sc[0]=='0' && sc[1]=='\0');
                    } else {
                        // Auto-on when force-ack is enabled
                        do_sched_clear = Mw05ForceAckWaitEnabled();
                    }
                    if (do_sched_clear) {
                        // Try to read a big-endian pointer to the block from eventEA-8
                        if (GuestOffsetInRange(eventEA - 8, sizeof(uint64_t))) {
                            const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(eventEA - 8));
                            if (p) {
                                uint64_t be_ptr64 = *reinterpret_cast<const uint64_t*>(p);
                                #if defined(_MSC_VER)
                                be_ptr64 = _byteswap_uint64(be_ptr64);
                                #else
                                be_ptr64 = __builtin_bswap64(be_ptr64);
                                #endif
                                const uint32_t blkEA = static_cast<uint32_t>(be_ptr64);
                                if (blkEA && GuestOffsetInRange(blkEA, 0x20)) {
                                    if (auto* blk = static_cast<uint8_t*>(g_memory.Translate(blkEA))) {
                                        memset(blk, 0, 0x20);
                                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.sched.clear ea=%08X", blkEA);
                                    }
                                }
                            }
                        }
                    }

                    // Optionally signal the VD event from ISR
                    if (const char* se = std::getenv("MW05_HOST_ISR_SIGNAL_VD_EVENT")) {
                        if (!(se[0]=='0' && se[1]=='\0')) {
                            if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(eventEA))) {
                                KeSetEvent(evt, 0, false);
                                KernelTraceHostOpF("HOST.HostDefaultVdIsr.signal ea=%08X", eventEA);
                            }
                        }
                    }
                }
            }
        }


        // Optional: aggressively pulse the suspected scheduler event at EA=0x000E0DD0 (diagnostic)
        // Guarded by MW05_PULSE_E0DD0=1. This is a temporary nudge to test whether that wait gate blocks progress.
        if (const char* pe = std::getenv("MW05_PULSE_E0DD0")) {
            if (!(pe[0]=='0' && pe[1]=='\0')) {
                constexpr uint32_t kPulseEA = 0x000E0DD0u;
                if (GuestOffsetInRange(kPulseEA, sizeof(XDISPATCHER_HEADER))) {
                    if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(kPulseEA))) {
                        KeSetEvent(evt, 0, false);
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.pulse.e0dd0 ea=%08X", kPulseEA);
                    }
                }
            }
        }

        // Optionally signal the last waited-on event (if different from the VD event)
        if (const char* slw = std::getenv("MW05_HOST_ISR_FORCE_SIGNAL_LAST_WAIT")) {
            if (!(slw[0]=='0' && slw[1]=='\0')) {
                const uint32_t lastEA = g_lastWaitEventEA.load(std::memory_order_acquire);
                const uint32_t vdEA   = g_vdInterruptEventEA.load(std::memory_order_acquire);
                if (const char* tl2 = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
                    if (!(tl2[0]=='0' && tl2[1]=='\0')) {
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.last_wait.state last=%08X vd=%08X", lastEA, vdEA);
                    }
                }

                if (lastEA && lastEA != vdEA && GuestOffsetInRange(lastEA, sizeof(XDISPATCHER_HEADER))) {
                    if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(lastEA))) {
                        KeSetEvent(evt, 0, false);
                // Trace last-wait state for diagnostics
                if (const char* tl = std::getenv("MW05_HOST_ISR_TRACE_LAST_WAIT")) {
                    if (!(tl[0]=='0' && tl[1]=='\0')) {
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.last_wait.state last=%08X vd=%08X", lastEA, vdEA);
                    }
                }

                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.signal.last_wait ea=%08X", lastEA);

                    }
                }

	                // If we didn't have a valid last-wait EA, try the last kernel handle waited on (implemented later)
	                if (!(lastEA && GuestOffsetInRange(lastEA, sizeof(XDISPATCHER_HEADER)))) {
	                    Mw05HostIsrSignalLastWaitHandleIfAny();
	                }

            }
        }


        // Optional: one-time nudge after N ISR ticks if still stuck (env-guarded)
        {
            static bool  s_nudgeOnceEnabled = [](){
                if (const char* v = std::getenv("MW05_HOST_ISR_NUDGE_ONCE"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            static uint32_t s_afterTicks = [](){
                if (const char* v = std::getenv("MW05_HOST_ISR_NUDGE_AFTER"))
                    return (uint32_t)std::strtoul(v, nullptr, 10);
                return 240u; // ~4 seconds at 60Hz
            }();
            static uint32_t s_ticks = 0;
            static bool     s_done  = false;
            static bool     s_loggedCfg = false;

            if (!s_loggedCfg) {
                KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge_once.config enabled=%u after=%u", (unsigned)s_nudgeOnceEnabled, s_afterTicks);
                s_loggedCfg = true;
            }

            if (!s_done) ++s_ticks;
            if (s_nudgeOnceEnabled && !s_done && s_ticks >= s_afterTicks) {
                const uint32_t lastEA = g_lastWaitEventEA.load(std::memory_order_acquire);
                const uint32_t vdEA   = g_vdInterruptEventEA.load(std::memory_order_acquire);
                bool did = false;
                if (lastEA && lastEA != vdEA && GuestOffsetInRange(lastEA, sizeof(XDISPATCHER_HEADER))) {
                    if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(lastEA))) {
                        KeSetEvent(evt, 0, false);
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge_once.last_wait ea=%08X ticks=%u", lastEA, s_ticks);
                        did = true;
                    }
                }
                if (!did) {
                    Mw05HostIsrSignalLastWaitHandleIfAny();
                    KernelTraceHostOpF("HOST.HostDefaultVdIsr.nudge_once.handle_or_none handle=%08X ticks=%u",
                                       (unsigned)g_lastWaitKernelHandle.load(std::memory_order_relaxed), s_ticks);
                }
                s_done = true;
            }
        }

        // Optionally tick the system command buffer GPU-identifier value
        if (const char* t = std::getenv("MW05_HOST_ISR_TICK_SYSID")) {
            if (!(t[0]=='0' && t[1]=='\0')) {
                const uint32_t sysIdEA = g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_acquire);
                if (sysIdEA && GuestOffsetInRange(sysIdEA, sizeof(uint32_t))) {
                    if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(sysIdEA))) {
                        uint32_t val = *p + 1u;
                        *p = val;

                        g_SysCmdBufValue.store(val, std::memory_order_release);
                        KernelTraceHostOpF("HOST.HostDefaultVdIsr.sys_id.tick val=%08X", val);
                    }
                } else {
                    // Even if the GPU-id address wasn't set, expose progress via the API value
                    g_SysCmdBufValue.fetch_add(1u, std::memory_order_acq_rel);
                }
        if (!tag || strcmp(tag, "vd_call") != 0) {

        // Optionally drive notifications again within the same tick (safe: reentrancy-guarded)
        static thread_local bool s_inIsrNudge = false;
        if (!s_inIsrNudge) {
            s_inIsrNudge = true;
            VdCallGraphicsNotificationRoutines(0u);


            s_inIsrNudge = false;
        }

        // Optionally synthesize additional notify sources (e.g., 1,2) some titles expect
        if (const char* seq = std::getenv("MW05_HOST_ISR_NOTIFY_SRC_SEQ")) {
            // Format: comma-separated uints, e.g., "0,1,2"
            const char* p = seq;
            while (*p) {
                unsigned v = 0; bool any=false;
                while (*p && *p==' ') ++p;
                while (*p && *p>='0' && *p<='9') { v = v*10 + unsigned(*p - '0'); ++p; any=true; }
                if (any) VdCallGraphicsNotificationRoutines(static_cast<uint32_t>(v));
                while (*p && *p!=',') ++p;
                if (*p==',') ++p;
            }
        } else {
            // Default: also emit a '1' source in addition to the vblank (0)
            VdCallGraphicsNotificationRoutines(0u);
        }
        // If a real ISR is registered (not the host magic), also call it with extra sources
        if (uint32_t cb = VdGetGraphicsInterruptCallback()) {
            if (cb != kHostDefaultVdIsrMagic) {
                const uint32_t ctx = VdGetGraphicsInterruptContext();
                // same sequence logic as above: use env or default to 1
                if (const char* seq2 = std::getenv("MW05_HOST_ISR_NOTIFY_SRC_SEQ")) {
                    const char* p2 = seq2;
                    while (*p2) {
                        unsigned v = 0; bool any=false;
                        while (*p2 && *p2==' ') ++p2;
                        while (*p2 && *p2>='0' && *p2<='9') { v = v*10 + unsigned(*p2 - '0'); ++p2; any=true; }
                        if (any) GuestToHostFunction<void>(cb, static_cast<uint32_t>(v), ctx);
                        while (*p2 && *p2!=',') ++p2;
                        if (*p2==',') ++p2;
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
        if (const char* d = std::getenv("MW05_VD_POLL_DIAG")) {
            if (!(d[0]=='0' && d[1]=='\0')) {
                static int s_diagTick = 0;
                // Log every 8th tick to avoid spamming
                if (((++s_diagTick) & 7) == 0) {
                    auto read_be64 = [](uint32_t ea)->uint64_t {
                        if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                        const void* p = g_memory.Translate(ea);
                        if (!p) return 0;
                        uint64_t v = *reinterpret_cast<const uint64_t*>(p);
                    #if defined(_MSC_VER)
                        v = _byteswap_uint64(v);
                    #else
                        v = __builtin_bswap64(v);
                    #endif
                        return v;
                    };

                    auto read_u32 = [](uint32_t ea)->uint32_t {
                        if (!GuestOffsetInRange(ea, sizeof(uint32_t))) return 0;
                        const void* p = g_memory.Translate(ea);
                        if (!p) return 0;
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
        if (const char* poke58 = std::getenv("MW05_VD_POKE_E58")) {
            // Accept hex or decimal; examples: "0x600" or "1536". If the string starts with '+', OR the value.
            if (poke58 && poke58[0]) {
                const bool or_mode = (poke58[0] == '+');
                const char* val_str = or_mode ? poke58 + 1 : poke58;
                unsigned long v = std::strtoul(val_str, nullptr, 0);
                auto write_be64 = [](uint32_t ea, uint64_t v64){
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return false;
                    auto* p = static_cast<uint8_t*>(g_memory.Translate(ea));
                    if (!p) return false;
                    p[0] = uint8_t(v64 >> 56); p[1] = uint8_t(v64 >> 48);
                    p[2] = uint8_t(v64 >> 40); p[3] = uint8_t(v64 >> 32);
                    p[4] = uint8_t(v64 >> 24); p[5] = uint8_t(v64 >> 16);
                    p[6] = uint8_t(v64 >>  8); p[7] = uint8_t(v64 >>  0);
                    return true;
                };
                const uint32_t ea = 0x00060E58u;
                // Only write if different to minimize churn
                auto read_be64 = [](uint32_t ea)->uint64_t{
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                    const void* p = g_memory.Translate(ea);
                    if (!p) return 0;
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
                if (ov != nv) {
                    if (write_be64(ea, nv)) {
                        KernelTraceHostOpF("HOST.VD.poke%s e58=%016llX (was %016llX)", or_mode?"|":"", (unsigned long long)nv, (unsigned long long)ov);
                    }
                }
            }
        }

        // Optional poke for e68 (OR mode supported with leading '+')
        if (const char* poke68 = std::getenv("MW05_VD_POKE_E68")) {
            if (poke68 && poke68[0]) {
                const bool or_mode = (poke68[0] == '+');
                const char* val_str = or_mode ? poke68 + 1 : poke68;
                unsigned long v = std::strtoul(val_str, nullptr, 0);
                auto write_be64 = [](uint32_t ea, uint64_t v64){
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return false;
                    auto* p = static_cast<uint8_t*>(g_memory.Translate(ea));
                    if (!p) return false;
                    p[0] = uint8_t(v64 >> 56); p[1] = uint8_t(v64 >> 48);
                    p[2] = uint8_t(v64 >> 40); p[3] = uint8_t(v64 >> 32);
                    p[4] = uint8_t(v64 >> 24); p[5] = uint8_t(v64 >> 16);
                    p[6] = uint8_t(v64 >>  8); p[7] = uint8_t(v64 >>  0);
                    return true;
                };
                auto read_be64 = [](uint32_t ea)->uint64_t{
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                    const void* p = g_memory.Translate(ea);
                    if (!p) return 0;
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
                if (ov != nv && write_be64(ea, nv)) {
                    KernelTraceHostOpF("HOST.VD.poke%s e68=%016llX (was %016llX)", or_mode?"|":"", (unsigned long long)nv, (unsigned long long)ov);
                }
            }
        }

        // Optional poke for e70 (OR mode supported with leading '+')
        if (const char* poke70 = std::getenv("MW05_VD_POKE_E70")) {
            if (poke70 && poke70[0]) {
                const bool or_mode = (poke70[0] == '+');
                const char* val_str = or_mode ? poke70 + 1 : poke70;
                unsigned long v = std::strtoul(val_str, nullptr, 0);
                auto write_be64 = [](uint32_t ea, uint64_t v64){
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return false;
                    auto* p = static_cast<uint8_t*>(g_memory.Translate(ea));
                    if (!p) return false;
                    p[0] = uint8_t(v64 >> 56); p[1] = uint8_t(v64 >> 48);
                    p[2] = uint8_t(v64 >> 40); p[3] = uint8_t(v64 >> 32);
                    p[4] = uint8_t(v64 >> 24); p[5] = uint8_t(v64 >> 16);
                    p[6] = uint8_t(v64 >>  8); p[7] = uint8_t(v64 >>  0);
                    return true;
                };
                auto read_be64 = [](uint32_t ea)->uint64_t{
                    if (!GuestOffsetInRange(ea, sizeof(uint64_t))) return 0;
                    const void* p = g_memory.Translate(ea);
                    if (!p) return 0;
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
                if (ov != nv && write_be64(ea, nv)) {
                    KernelTraceHostOpF("HOST.VD.poke%s e70=%016llX (was %016llX)", or_mode?"|":"", (unsigned long long)nv, (unsigned long long)ov);
                }
            }
        }

        s_inHostIsrNudge = false;

        if (s_isr_auto_present) {
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
            assert(false && "Unhandled timeout value.");
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

void VdSwap(uint32_t pWriteCur, uint32_t pParams, uint32_t pRingBase)
{
    KernelTraceHostOp("HOST.VdSwap");
    if (auto* ctx = GetPPCContext()) {
        KernelTraceHostOpF("HOST.VdSwap.caller lr=%08X", (uint32_t)ctx->lr);
    }
    // Terse arg trace to correlate with vdswap.txt disassembly
    KernelTraceHostOpF("HOST.VdSwap.args r3=%08X r4=%08X r5=%08X", pWriteCur, pParams, pRingBase);
    // Mark that the guest performed a swap at least once (real)
    g_guestHasSwapped.store(true, std::memory_order_release);
    g_sawRealVdSwap.store(true, std::memory_order_release);
    // Present the current backbuffer and advance frame state
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[boot] VdSwap()\n"); fflush(stdout);
    }
    Video::Present();

    // Optional: stimulate guest render scheduler by issuing a notify after swap.
    // Titles often rely on graphics notifications to progress their render loop.
    // Opt-in via MW05_VDSWAP_NOTIFY=1 (default: off).
    static const bool s_notify_after_swap = [](){
        if (const char* v = std::getenv("MW05_VDSWAP_NOTIFY"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_notify_after_swap) {
        // Emit a vblank-like source=0 and an auxiliary source=1 (common pattern)
        VdCallGraphicsNotificationRoutines(0u);
        VdCallGraphicsNotificationRoutines(1u);
    }

    // Advance ring-buffer RPtr write-back to the guest's current write position
    // when possible, so polling logic sees precise progress; otherwise, nudge.
    uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);
    if (wb)
    {
        if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb)))
        {
            uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
            const uint32_t size = (len_log2 < 32) ? (1u << len_log2) : 0u;
            const uint32_t base = g_RbBase.load(std::memory_order_relaxed);
            bool set_to_write = false;

            if (size && base && GuestOffsetInRange(pWriteCur, sizeof(uint32_t)))
            {
                if (const uint32_t* pWC = reinterpret_cast<const uint32_t*>(g_memory.Translate(pWriteCur)))
                {
                    const uint32_t write_cur = *pWC;
                    if (write_cur >= base && write_cur < (base + size))
                    {
                        const uint32_t offs = (write_cur - base) & (size - 1u);
                        *rptr = offs ? offs : 0x20u;
                        KernelTraceHostOpF("HOST.VdSwap.rptr.set offs=%04X (wc=%08X base=%08X size=%u)", offs, write_cur, base, size);
                        set_to_write = true;

                        // Optional: force a MW05 micro-IB interpreter pass at the default syscmd payload
                        // to surface headers/logs even if PM4 scans don't trigger. Controlled by MW05_FORCE_MICROIB.
                        {
                            static const bool s_force_micro = [](){
                                if (const char* v = std::getenv("MW05_FORCE_MICROIB")) return !(v[0]=='0' && v[1]=='\0');
                                return false;
                            }();
                            if (s_force_micro) {
                                KernelTraceHostOpF("HOST.PM4.MW05.ForceMicroIB.call ea=%08X size=%u", 0x00140410u, 0x400u);
                                Mw05InterpretMicroIB(0x00140410u, 0x400u);
                            }
                        }


                        // Scan ring buffer for PM4 draw commands
                        PM4_OnRingBufferWrite(offs);

                        // Optional: perform a broader scan after swap to catch early setups
                        static const bool s_scan_all_on_swap = [](){
                            if (const char* v = std::getenv("MW05_PM4_SCAN_ALL_ON_SWAP"))
                                return !(v[0]=='0' && v[1]=='\0');
                            return false;
                        }();
                        // If explicitly requested, or auto after a few frames with no draws, scan whole ring
                        static int s_autoScanTicker = 0;
                        extern uint64_t PM4_GetDrawCount();
                        const bool auto_scan = (PM4_GetDrawCount() == 0 && (++s_autoScanTicker & 0x03) == 0); // ~every 4th swap until we see a draw
                        if (s_scan_all_on_swap) {
                            PM4_DebugScanAll();
                        } else if (auto_scan) {
                            extern void PM4_DebugScanAll_Force();
                            PM4_DebugScanAll_Force();
                        }

                            // Optional: also scan the System Command Buffer directly in case the title
                            // is writing PM4 there and relying on the kernel to push to the ring.
                            static const bool s_scan_sysbuf = [](){
                                if (const char* v = std::getenv("MW05_PM4_SCAN_SYSBUF"))
                                    return !(v[0]=='0' && v[1]=='\0');
                                return false;
                            }();
                            if (s_scan_sysbuf || auto_scan) {
                                uint32_t sysbuf = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
                                if (sysbuf) {
                                    // Scan a reasonable window; MW05 typically uses <= 64 KiB
                                    PM4_ScanLinear(sysbuf, 64u * 1024u);
                                }
                            }

	                            // Experimental: if requested, push any non-zero bytes from the System Command Buffer
	                            // into the ring buffer so the PM4 parser can see potential draws. This is purely a
	                            // diagnostic bridge to validate whether the title is building PM4 in sysbuf.
	                            static const bool s_sysbuf_to_ring = [](){
	                                if (const char* v = std::getenv("MW05_PM4_SYSBUF_TO_RING"))
	                                    return !(v[0]=='0' && v[1]=='\0');
	                                return false;
	                            }();
	                            if (s_sysbuf_to_ring)
	                            {
	                                uint32_t sysbuf = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
	                                uint32_t rbBase = g_RbBase.load(std::memory_order_acquire);
	                                uint32_t rbLenL2 = g_RbLen.load(std::memory_order_acquire);
	                                const uint32_t rbSizeBytes = (rbLenL2 < 32) ? (1u << (rbLenL2 & 31)) : 0u;
	                                if (sysbuf && rbBase && rbSizeBytes)
	                                {
	                                    uint8_t* sysHost = reinterpret_cast<uint8_t*>(g_memory.Translate(sysbuf));
	                                    uint8_t* rbHost  = reinterpret_cast<uint8_t*>(g_memory.Translate(rbBase));
	                                    auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(g_RbWriteBackPtr.load(std::memory_order_acquire)));
	                                    if (sysHost && rbHost && rptr)
	                                    {
	                                        // Copy entire sysbuf PAYLOAD into ring (skip 16-byte header), capped by ring size
	                                        const uint32_t headSkip  = 0x10u;
	                                        const uint32_t payloadBytes = (rbSizeBytes > headSkip) ? (rbSizeBytes - headSkip) : 0u;
	                                        bool any = false;
	                                        for (uint32_t off = 0; off + 4 <= payloadBytes; off += 4) {
	                                            if (*reinterpret_cast<uint32_t*>(sysHost + headSkip + off) != 0) { any = true; break; }
	                                        }
	                                        if (any && payloadBytes) {
	                                            memcpy(rbHost, sysHost + headSkip, payloadBytes);
	                                            // Advance write-back pointer so our PM4 parser scans the copied region
	                                            const uint32_t offs = payloadBytes & (rbSizeBytes - 1u);
	                                            *rptr = offs ? offs : 0x20u;
	                                            KernelTraceHostOpF("HOST.PM4.SysBufBridge.copy bytes=%u offs=%04X", payloadBytes, offs);
	                                            PM4_OnRingBufferWrite(offs);

	                                        }
	                                    }
	                                }
	                            }


                    }
                }
            }

            if (!set_to_write)
            {
                uint32_t cur = *rptr;
                const uint32_t mask = size ? (size - 1u) : 0xFFFFu;
                const uint32_t step = 0x80u;
                uint32_t next = (cur + step) & mask;
                *rptr = next ? next : 0x40u;
                // Also feed the PM4 parser with the new write pointer so it can scan
                // any commands that the guest may have queued even if we couldn't
                // read the precise write_cur.
                PM4_OnRingBufferWrite(next);

                // Also optionally bridge System Command Buffer -> ring even on fallback path
                {
                    static const bool s_sysbuf_to_ring = [](){
                        if (const char* v = std::getenv("MW05_PM4_SYSBUF_TO_RING"))
                            return !(v[0]=='0' && v[1]=='\0');
                        return false;
                    }();
                    if (s_sysbuf_to_ring)
                    {
                        uint32_t sysbuf = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
                        uint32_t rbBase = g_RbBase.load(std::memory_order_acquire);
                        uint32_t rbLenL2 = g_RbLen.load(std::memory_order_acquire);
                        const uint32_t rbSizeBytes = (rbLenL2 < 32) ? (1u << (rbLenL2 & 31)) : 0u;
                        if (sysbuf && rbBase && rbSizeBytes)
                        {
                            uint8_t* sysHost = reinterpret_cast<uint8_t*>(g_memory.Translate(sysbuf));
                            uint8_t* rbHost  = reinterpret_cast<uint8_t*>(g_memory.Translate(rbBase));
                            auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(g_RbWriteBackPtr.load(std::memory_order_acquire)));
                            if (sysHost && rbHost && rptr)
                            {
                                // Copy entire sysbuf PAYLOAD (skip 16-byte header), capped by ring size (fallback)
                                const uint32_t headSkip  = 0x10u;
                                const uint32_t payloadBytes = (rbSizeBytes > headSkip) ? (rbSizeBytes - headSkip) : 0u;
                                bool any = false;
                                for (uint32_t off = 0; off + 4 <= payloadBytes; off += 4) {
                                    if (*reinterpret_cast<uint32_t*>(sysHost + headSkip + off) != 0) { any = true; break; }
                                }
                                if (any && payloadBytes) {
                                    memcpy(rbHost, sysHost + headSkip, payloadBytes);
                                    const uint32_t offs = payloadBytes & (rbSizeBytes - 1u);
                                    *rptr = offs ? offs : 0x20u;
                                    KernelTraceHostOpF("HOST.PM4.SysBufBridge.copy bytes=%u offs=%04X (fallback)", payloadBytes, offs);
                                    PM4_OnRingBufferWrite(offs);
                                }
                            }
                        }
                    }
                }

	                // Fallback: if we still haven't seen draws, periodically force a full scan
	                // of the ring and the system command buffer to catch very early setup.
	                {
	                    static int s_autoScanTicker2 = 0;
	                    if (((++s_autoScanTicker2) & 0x03) == 0) { // ~every 4th swap
	                        extern uint64_t PM4_GetDrawCount();
	                        if (PM4_GetDrawCount() == 0) {
	                            extern void PM4_DebugScanAll_Force();
	                            PM4_DebugScanAll_Force();
	                            // Also scan system buffer directly
	                            uint32_t sysbuf = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
	                            if (sysbuf) {
	                                PM4_ScanLinear(sysbuf, 64u * 1024u);
	                            }
	                        }
	                    }
	                }

            }
        }
        // Optional: inject a synthetic PM4 DRAW packet to validate parser end-to-end
        // Controlled by MW05_PM4_INJECT_TEST=1. Writes a minimal TYPE3 header at ring base
        // so the PM4 parser should report draws>0 if decoding/scanning is correct.
        {
            static const bool s_inject_test = [](){ if (const char* v = std::getenv("MW05_PM4_INJECT_TEST")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
            if (s_inject_test) {
                uint32_t rbBase = g_RbBase.load(std::memory_order_acquire);
                uint32_t rbLenL2 = g_RbLen.load(std::memory_order_acquire) & 31u;
                const uint32_t rbSizeBytes = (rbLenL2 < 32u) ? (1u << rbLenL2) : 0u;
                if (rbBase && rbSizeBytes) {
                    uint32_t* rb = reinterpret_cast<uint32_t*>(g_memory.Translate(rbBase));
                    if (rb) {
                        uint32_t hdr = 0;
                        hdr |= (3u << 30);        // TYPE3
                        hdr |= (0x22u << 8);      // DRAW_INDX opcode
                        hdr |= (0u << 16);        // count=0 -> size=(0+2)*4=8 bytes
                    #if defined(_MSC_VER)
                        uint32_t be_hdr = _byteswap_ulong(hdr);
                    #else
                        uint32_t be_hdr = __builtin_bswap32(hdr);
                    #endif
                        rb[0] = be_hdr;
                        rb[1] = 0; // dummy payload dword
                        KernelTraceHostOp("HOST.PM4.InjectTest.draw_hdr_written");
                        PM4_OnRingBufferWrite(8);
                    }
                }
            }
        }

    }

    // Optional: ack swap via e68 OR if enabled
    static uint64_t s_ack_mask = [](){
        uint64_t m = 0;
        if (const char* v = std::getenv("MW05_VDSWAP_ACK_E68")) {
            m = std::strtoull(v, nullptr, 0);
        }
        if (!m) m = 0x2ull; // default to bit1
        return m;
    }();
    static const bool s_ack_enable = [](){
        if (const char* v = std::getenv("MW05_VDSWAP_ACK"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_ack_enable) {
        const uint32_t ea = 0x00060E68u;
        if (GuestOffsetInRange(ea, sizeof(uint64_t))) {
            if (auto* p = reinterpret_cast<uint64_t*>(g_memory.Translate(ea))) {
                uint64_t v = *p;
            #if defined(_MSC_VER)
                v = _byteswap_uint64(v);
            #else
                v = __builtin_bswap64(v);
            #endif
                v |= s_ack_mask;
            #if defined(_MSC_VER)
                *p = _byteswap_uint64(v);
            #else
                *p = __builtin_bswap64(v);
            #endif
                KernelTraceHostOpF("HOST.VdSwap.ack.e68 |= %llX -> %llX", (unsigned long long)s_ack_mask, (unsigned long long)v);
            }
        }
    }

    // Option A: drive display waiters forward by signaling the registered
    // Vd interrupt event once per present.
    (void)Mw05SignalVdInterruptEvent();
}

static void Mw05StartVblankPumpOnce() {
    if (!Mw05VblankPumpEnabled()) return;
    bool expected = false;
    if (!g_vblankPumpRun.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    KernelTraceHostOp("HOST.VblankPump.start");
    std::thread([]{
        using namespace std::chrono;
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
        while (g_vblankPumpRun.load(std::memory_order_acquire)) {
            // Global vblank tick counter for gating guest ISR dispatches
            const uint32_t currentTick = g_vblankTicks.fetch_add(1u, std::memory_order_acq_rel);

            // Debug: log tick count every 10 ticks AND always log tick 0
            if (currentTick == 0 || currentTick % 10 == 0) {
                fprintf(stderr, "[VBLANK-TICK] count=%u\n", currentTick);
                fflush(stderr);
            }

            // EXPERIMENTAL: Force-create video thread after initialization completes
            // In Xenia, MW05 creates the video thread (F800000C) after ~227 vblank ticks.
            // MW05 appears to be waiting for a condition that's not being met in our version.
            // Force-create the thread to unblock progression to rendering.
            static const bool s_force_video_thread = [](){
                if (const char* v = std::getenv("MW05_FORCE_VIDEO_THREAD"))
                    return !(v[0]=='0' && v[1]=='\0');
                return false; // default: disabled (investigating condition check)
            }();
            static const uint32_t s_force_video_thread_tick = [](){
                if (const char* v = std::getenv("MW05_FORCE_VIDEO_THREAD_TICK"))
                    return (uint32_t)std::strtoul(v, nullptr, 10);
                return 250u; // slightly after Xenia's 227 ticks
            }();
            static std::atomic<bool> s_video_thread_created{false};

            if (s_force_video_thread && !s_video_thread_created.load(std::memory_order_acquire)) {
                if (currentTick >= s_force_video_thread_tick) {
                    bool expected = false;
                    if (s_video_thread_created.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                        KernelTraceHostOpF("HOST.ForceVideoThread.trigger tick=%u", currentTick);

                        // Call the thread creation function sub_8284F548 which creates the video thread
                        // This function is normally called by sub_82885A70 -> sub_8284F548 -> ExCreateThread
                        // We'll call it directly to bypass the condition check

                        // Set up a minimal context for the call
                        // Based on Xenia logs, the function is called with specific parameters
                        // We'll use default values and let the function set up the thread properly
                        EnsureGuestContextForThisThread("ForceVideoThread");
                        PPCContext ctx{};
                        SetPPCContext(ctx);

                        // Initialize registers to safe defaults
                        ctx.r3.u64 = 0;  // parameter 1
                        ctx.r4.u64 = 0;  // parameter 2
                        ctx.r5.u64 = 0;  // parameter 3
                        ctx.r1.u64 = 0x00010000;  // stack pointer (safe default)
                        ctx.lr = 0;  // return address

                        KernelTraceHostOp("HOST.ForceVideoThread.call_sub_8284F548");
                        extern void sub_8284F548(PPCContext& ctx, uint8_t* base);
                        sub_8284F548(ctx, g_memory.base);
                        KernelTraceHostOpF("HOST.ForceVideoThread.complete r3=%08X", ctx.r3.u32);
                    }
                }
            }

            // Keep a pending interrupt flowing; if event not yet registered,
            // Mw05SignalVdInterruptEvent() will fail and we keep the pending flag.
            if (!Mw05SignalVdInterruptEvent()) {
                g_vdInterruptPending.store(true, std::memory_order_release);
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
                if (std::getenv("MW05_FORCE_PRESENT") || std::getenv("MW05_FORCE_PRESENT_BG") || std::getenv("MW05_KICK_VIDEO")) {
                    // Normally suppress guest ISR during forced-present bring-up, but allow
                    // the host-side default ISR if explicitly enabled.
                    if (const char* d = std::getenv("MW05_DEFAULT_VD_ISR"))
                        return !(d[0]=='0' && d[1]=='\0');
                    return false;
                }
                // Default: enabled only when not in forced-present bring-up paths
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
                        EnsureGuestContextForThisThread("VblankPump");
                        GuestToHostFunction<void>(cb, 0u, ctx);
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
            static const uint64_t s_present_heartbeat_ms = [](){
                if (const char* v = std::getenv("MW05_PRESENT_HEARTBEAT_MS"))
                    return (uint64_t)std::strtoull(v, nullptr, 10);
                return uint64_t(0);
            }();
            const uint64_t last_ms = g_lastPresentMs.load(std::memory_order_acquire);
            const uint64_t now_ms  = SDL_GetTicks64();
            const bool stale = s_present_heartbeat_ms && (now_ms - last_ms > s_present_heartbeat_ms);
            if (s_force_present || !Mw05HasGuestSwapped() || stale) {
                Video::RequestPresentFromBackground();
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
                                        // Ensure syscmd exists and get EA
                                        VdGetSystemCommandBuffer(nullptr, nullptr);
                                        uint32_t sys_ea = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
                                        uint32_t sys_val = g_SysCmdBufValue.load(std::memory_order_acquire);
                                        KernelTraceHostOpF("HOST.FPW.post.sysbuf ea=%08X val=%08X", sys_ea, sys_val);
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

                // Auto VdSwap heuristic (opt-in): when conditions look ready for N frames, seed a swap once
                static const bool s_auto_vdswap_heur = [](){
                    if (const char* v = std::getenv("MW05_AUTO_VDSWAP_HEUR"))
                        return !(v[0]=='0' && v[1]=='\0');
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
                    return 0x700ull;
                }();
                static const uint64_t s_auto_e68_mask = [](){
                    if (const char* v = std::getenv("MW05_AUTO_VDSWAP_HEUR_E68_MASK"))
                        return std::strtoull(v, nullptr, 0);
                    return 0x2ull; // require ack bit
                }();
                static int s_auto_ok_frames = 0;
                static bool s_auto_done = false;
                if (s_auto_vdswap_heur && !s_auto_done && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
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
                    if (e58_ok && e68_ok) {
                        if (++s_auto_ok_frames >= s_auto_vdswap_delay) {
                            KernelTraceHostOp("HOST.AutoVdSwapHeur.fire");
                            Mw05MarkGuestSwappedOnce();
                            Video::RequestPresentFromBackground();
                            if (s_auto_vdswap_once) s_auto_done = true;
                        }
                    } else {
                        s_auto_ok_frames = 0;
                    }
                }

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
            std::this_thread::sleep_for(period);
        }
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
                        GuestToHostFunction<void>(cb, 0u, ctx);
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

	static void Mw05ForceRegisterGfxNotifyIfRequested();
}

// Minimal reservation tracking for NtAllocateVirtualMemory reserve/commit emulation
struct NtReservation
{
    uint32_t GuestBase{};
    uint32_t Size{}; // page- (64 KiB) aligned
    void* HostOriginal{}; // original o1heap pointer
    void* HostAligned{};  // aligned base exposed to guest
};

static std::mutex g_NtAllocMutex;
static std::map<uint32_t, NtReservation> g_NtReservations; // legacy (to be removed when VmArena fully adopted)
static VmArena g_vmArena;
static std::once_flag g_vmInitOnce;

static void InitVmArenaOnce()
{
    std::call_once(g_vmInitOnce, []{
        // Compute the [RESERVED_BEGIN, RESERVED_END) range from heap layout to avoid duplicating constants.
        const uint32_t heap_begin_guest = g_memory.MapVirtual(g_userHeap.heapBase);
        const uint32_t heap_end_guest   = heap_begin_guest + static_cast<uint32_t>(g_userHeap.heapSize);
        const uint32_t phys_begin_guest = g_memory.MapVirtual(g_userHeap.physicalBase);
        if (phys_begin_guest > heap_end_guest)
        {
            g_vmArena.Init(heap_end_guest, phys_begin_guest - heap_end_guest);
        }
        else
        {
            // Fallback: if unexpected ordering, initialize a no-op arena to avoid crashes.
            g_vmArena.Init(0, 0);
        }
    });
}

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

inline void CloseKernelObject(XDISPATCHER_HEADER& header)
{
    if (header.WaitListHead.Flink != OBJECT_SIGNATURE)
    {
        return;
    }

    DestroyKernelObject(header.WaitListHead.Blink);
}

void VdHSIOCalibrationLock()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KeCertMonitorData()
{
    LOG_UTILITY("!!! STUB !!!");
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
be<uint32_t> KeTimeStampBundle   = be<uint32_t>(0);     // guest ptr to timestamp bundle (unused)
be<uint32_t> XboxHardwareInfo    = be<uint32_t>(0);     // guest ptr to hw info struct (unused)

// Video device globals expected as variables by some titles
be<uint32_t> VdGlobalDevice    = be<uint32_t>(0);    // pointer to vd device struct (unused)
be<uint32_t> VdGlobalXamDevice = be<uint32_t>(0);    // pointer to xam device struct (unused)
be<uint32_t> VdGpuClockInMHz   = be<uint32_t>(500);  // nominal Xenos GPU clock


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
    return userIndex == 0 ? 1u : 0u;
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
        *xuid = 0xB13EBABEBABEBABE;

    return 0;
}

uint32_t XamContentGetDeviceState()
{
    return 0;
}

uint32_t XamUserGetSigninInfo(uint32_t userIndex, uint32_t flags, XUSER_SIGNIN_INFO* info)
{
    if (userIndex == 0)
    {
        memset(info, 0, sizeof(*info));
        info->xuid = 0xB13EBABEBABEBABE;
        info->SigninState = 1;
        strcpy(info->Name, "SWA");
        return 0;
    }

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
    KernelTraceHostOpF("HOST.File.NtCreateFile.open path=%s", guestPath.c_str());

    if (guestPath.empty()) {

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
        *FileHandle = GUEST_INVALID_HANDLE_VALUE;
        IoStatusBlock->Status = status;
        IoStatusBlock->Information = 0;
        return status;
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
    if (handle == GUEST_INVALID_HANDLE_VALUE)
        return STATUS_INVALID_HANDLE; // 0xC0000008

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


        return kernel->Wait(timeout);
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
                    data[0] = ByteSwap(0x00001000); // USA/Canada
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
                    data[0] = ByteSwap(0x00040000);
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
        const uint32_t region_size = (base_sz < PPC_MEMORY_SIZE) ? static_cast<uint32_t>(PPC_MEMORY_SIZE - base_sz) : 0;

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
    *handle = GetKernelHandle(CreateKernelObject<Event>(!eventType, !!initialState));
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
    // For now, pass through common success and map unknown NTSTATUS to generic ERROR_GEN_FAILURE.
    // Titles often just check for zero/non-zero.
    if (Status == STATUS_SUCCESS) return 0;
    // If it's already a small Win32 error-style code, pass through.
    if ((Status & 0xFFFF0000u) == 0) return Status;
    // Generic failure (31).
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
                                BOOLEAN /*Alertable*/,
                                PLARGE_INTEGER IntervalGuest)
{
    // Mark that the last wait was a time delay, not a dispatcher; helps explain last==0
    g_lastWaitEventEA.store(0u, std::memory_order_release);
    g_lastWaitEventType.store(0xFFu, std::memory_order_release);
    KernelTraceHostOp("HOST.Wait.observe.KeDelayExecutionThread");

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

    // Read SIGNED 64-bit ticks from guest (100ns units; negative = relative)
    const int64_t ticks = read_guest_i64(IntervalGuest);

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
    }
    return STATUS_SUCCESS;
}

// Some titles gate functionality behind kernel privilege checks. Be permissive by default.
uint32_t XexCheckExecutablePrivilege()
{
    return 1; // present
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

    static std::atomic<int> s_loggedReadOnce{0};
    int expected_once = 0;
    if (s_loggedReadOnce.compare_exchange_strong(expected_once, 1)) {
        KernelTraceHostOpF("HOST.File.NtReadFile.called handle=%08X len=%u", handleId, Length);
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

uint32_t NtFreeVirtualMemory(
    uint32_t /*ProcessHandle*/,
    be<uint32_t>* BaseAddress,
    be<uint32_t>* /*RegionSize*/,
    uint32_t /*FreeType*/)
{
    auto is_valid_guest_ptr = [](const void* p, size_t bytes) -> bool {
        if (!p) return false;
        const uint8_t* u = reinterpret_cast<const uint8_t*>(p);
        const uint8_t* b = g_memory.base;
        size_t off = static_cast<size_t>(u - b);
        return off + bytes <= PPC_MEMORY_SIZE;
    };

    if (!is_valid_guest_ptr(BaseAddress, sizeof(*BaseAddress)))
        return 0xC000000DL; // STATUS_INVALID_PARAMETER

    const uint32_t base = static_cast<uint32_t>(*BaseAddress);
    // VmArena-based release path (decoupled from o1heap)
    {
        const uint32_t region64k = 0x10000u;
        const char* t1 = std::getenv("MW05_TRACE_NTFREE");
        const char* t2 = std::getenv("MW05_TRACE_MEM");
        const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
        // Release whole region at base (RegionSize not consulted in legacy path)
        const bool released = g_vmArena.Release(base, 0);
        if (on) LOGFN("[ntfree] base=0x{:08X} released={}", base, released?"yes":"no");
        *BaseAddress = 0;
        return 0;
    }
    bool freed = false;
    {
        std::lock_guard<std::mutex> lk(g_NtAllocMutex);
        auto it = g_NtReservations.find(base);
        if (it != g_NtReservations.end())
        {
            g_userHeap.Free(it->second.HostOriginal);
            g_NtReservations.erase(it);
            freed = true;
        }
        else
        {
            // Fallback: free by containment if the pointer lies within a known reservation region.
            void* host = g_memory.Translate(base);
            for (auto it2 = g_NtReservations.begin(); !freed && it2 != g_NtReservations.end(); ++it2)
            {
                const auto& res = it2->second;
                uint8_t* beg = static_cast<uint8_t*>(res.HostAligned);
                uint8_t* end = beg + res.Size;
                if (host >= beg && host < end)
                {
                    g_userHeap.Free(res.HostOriginal);
                    g_NtReservations.erase(it2);
                    freed = true;
                }
            }
        }
    }
    if (!freed)
    {
        // Fallback: translate and free whatever this points at.
        void* host = g_memory.Translate(base);
        if (host)
            g_userHeap.Free(host);
    }

    {
        const char* t1 = std::getenv("MW05_TRACE_NTFREE");
        const char* t2 = std::getenv("MW05_TRACE_MEM");
        const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
        if (on)
        {
            LOGFN("[ntfree] base=0x{:08X} matched_reservation={}", base, freed ? "yes" : "no");
        }
    }

    *BaseAddress = 0; // clear supplied base
    return 0;         // STATUS_SUCCESS
}

// Xbox 360 variant uses 4 parameters from r3..r6
uint32_t NtAllocateVirtualMemory(
    be<uint32_t>* BaseAddress,
    be<uint32_t>* RegionSize,
    uint32_t AllocationType,
    uint32_t Protect)
{
    InitVmArenaOnce();

    auto is_on = [](const char* v){ return v && !(v[0]=='0' && v[1]=='\0'); };
    auto trace_on = [&](){
        return is_on(std::getenv("MW05_TRACE_NTALLOC")) || is_on(std::getenv("MW05_TRACE_MEM"));
    };

    auto valid_ptr = [](const void* p, size_t bytes) -> bool {
        if (!p) return false;
        const uint8_t* u = reinterpret_cast<const uint8_t*>(p);
        const uint8_t* b = g_memory.base;
        if (u < b) return false;
        const size_t off = static_cast<size_t>(u - b);
        return off + bytes <= PPC_MEMORY_SIZE;
    };

    if (!valid_ptr(BaseAddress, sizeof(*BaseAddress)) ||
        !valid_ptr(RegionSize,  sizeof(*RegionSize)))
        return 0xC000000DL; // STATUS_INVALID_PARAMETER

    const bool is_reserve = (AllocationType & MEM_RESERVE) != 0;
    const bool is_commit  = (AllocationType & MEM_COMMIT)  != 0;
    if (!is_reserve && !is_commit)
        return 0xC000000DL; // must specify at least one

    const uint32_t in_base = static_cast<uint32_t>(*BaseAddress);
    const uint32_t region64k = 0x10000;

    auto align_up = [](uint32_t v, uint32_t a) -> uint32_t { return (v + (a - 1U)) & ~(a - 1U); };

    uint32_t size = static_cast<uint32_t>(*RegionSize);
    if (size == 0) return 0xC000000DL;
    const uint32_t aligned_size = align_up(size, region64k);

    uint32_t out_guest = 0;

    // Reserve phase
    if (is_reserve) {
        const uint32_t reserved = g_vmArena.Reserve(in_base, aligned_size);
        if (reserved == 0) {
            if (trace_on()) LOGFN("[ntalloc] reserve failed hint=0x{:08X} size={}", in_base, aligned_size);
            return 0xC0000018; // STATUS_CONFLICTING_ADDRESSES
        }
        out_guest  = reserved;
        *BaseAddress = out_guest;
        *RegionSize  = aligned_size;
    }

    // Commit phase
    if (is_commit) {
        uint32_t commit_base = (out_guest != 0) ? out_guest
                              : (in_base   != 0) ? in_base
                              : static_cast<uint32_t>(*BaseAddress);

        if (commit_base == 0) {
            commit_base = g_vmArena.Reserve(0, aligned_size);
            if (commit_base == 0) return 0xC0000017; // STATUS_NO_MEMORY
            out_guest = commit_base;
            *BaseAddress = out_guest;
            *RegionSize  = aligned_size;
        }

        if (!g_vmArena.Commit(commit_base, aligned_size)) {
            // If the hint wasn't a valid reservation, try a fresh spot once
            if (in_base != 0) {
                commit_base = g_vmArena.Reserve(0, aligned_size);
                if (commit_base == 0 || !g_vmArena.Commit(commit_base, aligned_size)) {
                    if (trace_on()) LOGFN("[ntalloc] commit failed base=0x{:08X} size={}", commit_base, aligned_size);
                    return 0xC0000018;
                }
                out_guest = commit_base;
                *BaseAddress = out_guest;
                *RegionSize  = aligned_size;
            } else {
                if (trace_on()) LOGFN("[ntalloc] commit failed base=0x{:08X} size={}", commit_base, aligned_size);
                return 0xC0000018;
            }
        }

        void* host = g_memory.Translate(*BaseAddress);
        std::memset(host, 0, aligned_size);
    }

    if (trace_on()) {
        const uint32_t base_ptr = g_memory.MapVirtual(reinterpret_cast<const uint8_t*>(BaseAddress));
        const uint32_t size_ptr = g_memory.MapVirtual(reinterpret_cast<const uint8_t*>(RegionSize));
        LOGFN("[ntalloc] base_ptr=0x{:08X} size_ptr=0x{:08X} in_base=0x{:08X} alloc_type=0x{:08X} protect=0x{:08X} req={} aligned={} out=0x{:08X}",
              base_ptr, size_ptr, in_base, AllocationType, Protect,
              static_cast<uint32_t>(*RegionSize), aligned_size, static_cast<uint32_t>(*BaseAddress));
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

    KernelTraceHostOp("HOST.Wait.enter.KeWaitForSingleObject");

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
    // Tolerate null/invalid critical sections during early boot
    if (!cs)
        return;
    auto* p = reinterpret_cast<uint8_t*>(cs);
    if (p < g_memory.base || p >= (g_memory.base + PPC_MEMORY_SIZE))
        return;

    uint32_t thisThread = 0;
    if (auto* ctx = GetPPCContext())
        thisThread = ctx->r13.u32;
    if (thisThread == 0)
        thisThread = 1; // Fallback owner id if TLS not yet established

    // Under forced-present bring-up (FG or BG) or when kicking video early,
    // avoid indefinite blocking on potentially uninitialized CS objects.
    // Perform a bounded spin and give up so early boot can limp forward.
    const bool non_blocking = (std::getenv("MW05_FORCE_PRESENT") != nullptr) ||
                              (std::getenv("MW05_FORCE_PRESENT_BG") != nullptr) ||
                              (std::getenv("MW05_KICK_VIDEO") != nullptr);
    int spins = non_blocking ? 1024 : INT_MAX;

    while (spins-- > 0)
    {
        uint32_t owner = cs->OwningThread;
        if (owner == 0 || owner == thisThread)
        {
            if (owner == 0)
                cs->OwningThread = thisThread;
            cs->RecursionCount++;
            cs->LockCount = (cs->LockCount < -1) ? -1 : cs->LockCount; // clamp
            cs->LockCount++;
            return;
        }

        // Light yield to avoid tight spinning; avoid atomic wait on possibly unaligned memory
        std::this_thread::yield();
    }
    // Give up acquiring in non-blocking mode; caller will likely retry later.
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

void RtlFillMemoryUlong()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KeBugCheckEx()
{
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
    if (!cs)
        return 0xC000000DL; // STATUS_INVALID_PARAMETER

    cs->Header.Absolute = 0;
    cs->LockCount = -1;
    cs->RecursionCount = 0;
    cs->OwningThread = 0;

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
    if (guestAddress != NULL)
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
static void* g_SysCmdBufHost = nullptr;
static uint32_t g_SysCmdBufGuest = 0;
static constexpr uint32_t kSysCmdBufSize = 64 * 1024;

static void EnsureSystemCommandBuffer()
{
    if (g_SysCmdBufGuest == 0)
    {
        g_SysCmdBufHost = g_userHeap.Alloc(kSysCmdBufSize, 0x100);
        g_SysCmdBufGuest = g_memory.MapVirtual(g_SysCmdBufHost);
        g_VdSystemCommandBuffer.store(g_SysCmdBufGuest);
        // Immediate visibility: scan once upon allocation to detect early PM4 usage.
        KernelTraceHostOpF("HOST.PM4.SysBufScan.ensure buf=%08X bytes=%u", g_SysCmdBufGuest, (unsigned)kSysCmdBufSize);
        extern void PM4_ScanLinear(uint32_t addr, uint32_t bytes);
        PM4_ScanLinear(g_SysCmdBufGuest, kSysCmdBufSize);
    }
}

uint32_t VdGetSystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue)
{
    KernelTraceHostOpF("HOST.VdGetSystemCommandBuffer.enter outPtr=%p outVal=%p", (void*)outCmdBufPtr, (void*)outValue);
    if (auto* ctx = GetPPCContext()) {
        KernelTraceHostOpF("HOST.VdGetSystemCommandBuffer.caller lr=%08X", (uint32_t)ctx->lr);
    }
    EnsureSystemCommandBuffer();
    // Optional: seed a small header in the System Command Buffer so titles that
    // expect a preinitialized descriptor (size/ticket) will proceed to write PM4.
    static const bool s_sysbuf_seed_hdr = [](){
        if (const char* v = std::getenv("MW05_PM4_SYSBUF_SEED_HDR")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_sysbuf_seed_hdr && g_SysCmdBufGuest != 0) {
        uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(g_SysCmdBufGuest));
        if (p) {
            // Only seed once while the first dword is zero
            if (p[0] == 0) {
            #if defined(_MSC_VER)
                const uint32_t be_val  = _byteswap_ulong(g_SysCmdBufValue.load(std::memory_order_acquire));
                const uint32_t be_size = _byteswap_ulong(kSysCmdBufSize);
            #else
                const uint32_t be_val  = __builtin_bswap32(g_SysCmdBufValue.load(std::memory_order_acquire));
                const uint32_t be_size = __builtin_bswap32(kSysCmdBufSize);
            #endif
                p[0] = be_val;   // ticket/cookie that changes over time
                p[1] = be_size;  // buffer size in bytes
                p[2] = 0;        // reserved: write offset
                p[3] = 0;        // reserved: read offset
                KernelTraceHostOpF("HOST.PM4.SysBufSeed hdr0..3: %08X %08X %08X %08X", p[0], p[1], p[2], p[3]);
            }
        }
    }
    // Optional: tick header[0] every query to simulate progress some titles expect
    // Enabled with MW05_PM4_SYSBUF_TICK_HDR=1. Uses g_SysCmdBufValue as the source ticket.
    {
        static const bool s_tick_hdr = [](){
            if (const char* v = std::getenv("MW05_PM4_SYSBUF_TICK_HDR")) return !(v[0]=='0' && v[1]=='\0');
            return false;
        }();
        if (s_tick_hdr && g_SysCmdBufGuest != 0) {
            uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(g_SysCmdBufGuest));
            if (p) {
            #if defined(_MSC_VER)
                p[0] = _byteswap_ulong(g_SysCmdBufValue.load(std::memory_order_acquire));
                p[1] = _byteswap_ulong(kSysCmdBufSize);
            #else
                p[0] = __builtin_bswap32(g_SysCmdBufValue.load(std::memory_order_acquire));
                p[1] = __builtin_bswap32(kSysCmdBufSize);
            #endif
            }
        }
    }



    // Seed a non-zero value on first query to match titles that expect a ticking
    // system-command value very early (opt-in via MW05_BOOT_TICK=1).
    static const bool s_bootTick = [](){
        if (const char* v = std::getenv("MW05_BOOT_TICK")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_bootTick) {
        uint32_t cur = g_SysCmdBufValue.load(std::memory_order_acquire);
        if (cur == 0) {
            uint32_t nv = 1u;


            g_SysCmdBufValue.store(nv, std::memory_order_release);
            // If GPU-id address is set, reflect it there as well.
            uint32_t sysIdEA = g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_acquire);
            if (sysIdEA && GuestOffsetInRange(sysIdEA, sizeof(uint32_t))) {
                if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(sysIdEA))) {
                    *p = nv;
                }
            }
        }
    }

    KernelTraceHostOpF("HOST.VdGetSystemCommandBuffer.res buf=%08X val=%08X", g_SysCmdBufGuest, g_SysCmdBufValue.load(std::memory_order_acquire));
    // Optional: dump a small window of the system command buffer on each query
    static const bool s_sysbuf_dump_on_get = [](){
        if (const char* v = std::getenv("MW05_PM4_SYSBUF_DUMP_ON_GET"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_sysbuf_dump_on_get && g_SysCmdBufGuest != 0) {
        const uint32_t base = g_SysCmdBufGuest;
        uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base));
        if (p) {
            for (int i = 0; i < 8; ++i) { // dump first 8 dwords (32 bytes)
            #if defined(_MSC_VER)
                uint32_t le = _byteswap_ulong(p[i]);
            #else
                uint32_t le = __builtin_bswap32(p[i]);
            #endif
                if (i == 0) {
                    KernelTraceHostOpF("HOST.PM4.SysBufDump %08X: %08X (first)", base + i * 4, le);
                } else {
                    KernelTraceHostOpF("HOST.PM4.SysBufDump %08X: %08X", base + i * 4, le);
                }
            }
        }
    }

    // One-time opportunistic scan of the system command buffer so we can see if the
    // title pushes PM4 here before the ring is initialized. This only logs and is safe.
    {
        static bool s_scannedOnce = false;
        if (!s_scannedOnce && g_SysCmdBufGuest != 0) {
            KernelTraceHostOpF("HOST.PM4.SysBufScan.trigger buf=%08X bytes=%u", g_SysCmdBufGuest, (unsigned)kSysCmdBufSize);
            extern void PM4_ScanLinear(uint32_t addr, uint32_t bytes);
            PM4_ScanLinear(g_SysCmdBufGuest, kSysCmdBufSize);
            KernelTraceHostOpF("HOST.PM4.SysBufScan.done");
            s_scannedOnce = true;
        }
    }
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] GetSystemCommandBuffer -> 0x%08X\n", g_SysCmdBufGuest);
        fflush(stdout);
    }
    if (outCmdBufPtr) *outCmdBufPtr = g_SysCmdBufGuest;
    if (outValue)     *outValue     = g_SysCmdBufValue.load(std::memory_order_acquire);
    return g_SysCmdBufGuest;
}

uint32_t VdQuerySystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue)
{
    KernelTraceHostOp("HOST.VdQuerySystemCommandBuffer");

    EnsureSystemCommandBuffer();
    if (outCmdBufPtr) *outCmdBufPtr = g_SysCmdBufGuest;
    if (outValue)     *outValue     = g_SysCmdBufValue.load(std::memory_order_acquire);
    return 0;
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
    KernelTraceHostOpF("HOST.VdInitializeRingBuffer base=%08X len_log2=%u", base, len);
    if (auto* ctx = GetPPCContext()) {
        KernelTraceHostOpF("HOST.VdInitializeRingBuffer.caller lr=%08X", (uint32_t)ctx->lr);
    }
    // MW05 (and Xenia logs) pass the ring buffer size as log2(len).
    // Convert to bytes to ensure we zero the correct range so readers see a clean buffer.
    g_RbBase = base;
    g_RbLen = len;
    const uint32_t size_bytes = (len < 32) ? (1u << (len & 31)) : 0u;
    if (base && size_bytes)
    {
        uint8_t* p = reinterpret_cast<uint8_t*>(g_memory.Translate(base));
        if (p) memset(p, 0, size_bytes);
    }
    // Seed write-back pointer so guest sees progress
    uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);
    if (wb)
    {
        if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb)))
            *rptr = 0x20; // small non-zero value
    }

    // Initialize PM4 parser with ring buffer info
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

// ---- forced VD bring-up (opt-in via MW05_FORCE_VD_INIT=1) ----
static inline bool Mw05ForceVdInitEnabled() {
    if (const char* v = std::getenv("MW05_FORCE_VD_INIT"))
        return !(v[0]=='0' && v[1]=='\0');
    return false;
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
extern "C" uint32_t Mw05Trace_LastSchedR3();
extern "C" void Mw05TryBuilderKickNoForward(uint32_t schedEA);

extern void MW05Shim_sub_825972B0(PPCContext& ctx, uint8_t* base);

void Mw05ForceVdInitOnce() {
    if (!Mw05ForceVdInitEnabled()) return;
    bool expected = false;
    if (!g_forceVdInitDone.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    KernelTraceHostOp("HOST.ForceVD.init.begin");

    // Ensure VD event is registered if provided via env (idempotent)
    Mw05MaybeForceRegisterVdEventFromEnv();

    // Ensure ring & write-back exist regardless of MW05_AUTO_VIDEO
    if (g_RbLen.load(std::memory_order_relaxed) == 0 ||
        g_RbWriteBackPtr.load(std::memory_order_relaxed) == 0)
    {
        // Allocate a small ring and a write-back slot
        const uint32_t len_log2 = 16; // 64 KiB
        void* ring_host = g_userHeap.Alloc(1u << len_log2, 0x1000);
        if (ring_host)
        {
            const uint32_t ring_guest = g_memory.MapVirtual(ring_host);
            void* wb_host = g_userHeap.Alloc(64, 4);
            if (wb_host)
            {
                const uint32_t wb_guest = g_memory.MapVirtual(wb_host);
                KernelTraceHostOpF("HOST.ForceVD.ensure_ring ring=%08X len_log2=%u wb=%08X", ring_guest, len_log2, wb_guest);
                VdInitializeRingBuffer(ring_guest, len_log2);
                VdEnableRingBufferRPtrWriteBack(wb_guest);
                VdSetSystemCommandBufferGpuIdentifierAddress(wb_guest + 8);
                // Optionally try to kick MW05's PM4 builder once we have ring/sysid
                uint32_t seed = Mw05Trace_LastSchedR3();
                if (!(seed >= 0x1000u)) seed = 0x00060E30u;
                if (seed >= 0x1000u) {
                    KernelTraceHostOpF("HOST.ForceVD.pm4_kick r3=%08X", seed);
                    Mw05TryBuilderKickNoForward(seed);
                    // Also forward-call the guest PM4 builder once to ensure TYPE3 emission
                    {
                        PPCContext ctx{};
                        if (auto* cur = GetPPCContext()) ctx = *cur;
                        ctx.r3.u32 = seed;
                        if (ctx.r4.u32 == 0) ctx.r4.u32 = 0x40; // typical arg observed
                        uint8_t* base = g_memory.base;
                        KernelTraceHostOpF("HOST.ForceVD.pm4_forward r3=%08X r4=%08X", ctx.r3.u32, ctx.r4.u32);
                        MW05Shim_sub_825972B0(ctx, base);
                    }
                    // One-time ring scan to surface any pre-existing TYPE3 packets
                    KernelTraceHostOpF("HOST.PM4.ScanLinear.Ring base=%08X bytes=%u", ring_guest, 1u << len_log2);
                    PM4_ScanLinear(ring_guest, 1u << len_log2);

                }

            }
        }
    }

    // Then bring engines up explicitly.
    Mw05ApplyVdPokesOnce();
    VdInitializeEngines();

    // Make sure the system command buffer is allocated (idempotent).
    VdGetSystemCommandBuffer(nullptr, nullptr);

    // One-time tick notification if ISR already registered
    VdCallGraphicsNotificationRoutines(0u);

    // Start vblank pump to keep things flowing even if the title idles early.
    Mw05StartVblankPumpOnce();
// fwd decls for locally-defined VD bridge helpers used below
void VdSetGraphicsInterruptCallback(uint32_t callback, uint32_t context);
void VdRegisterGraphicsNotificationRoutine(uint32_t callback, uint32_t context);


    // If requested, force-register the graphics notify ISR known from Xenia
    Mw05ForceRegisterGfxNotifyIfRequested();

    KernelTraceHostOp("HOST.ForceVD.init.done");

}


// Optional: force-register a graphics notify/ISR callback from env (for bring-up)
static void Mw05ForceRegisterGfxNotifyIfRequested() {
    const char* en = std::getenv("MW05_FORCE_GFX_NOTIFY_CB");
    if (!en || (en[0]=='0' && en[1]=='\0')) return;
    // Default EA from known-good Xenia capture if not provided via MW05_FORCE_GFX_NOTIFY_CB_EA
    uint32_t cb_ea = 0x825979A8u;
    if (const char* s = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_EA")) {
        cb_ea = (uint32_t)std::strtoul(s, nullptr, 0);
    }
    uint32_t ctx = 1u;
    if (const char* c = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_CTX")) {
        ctx = (uint32_t)std::strtoul(c, nullptr, 0);
    }
    // Only install if caller hasn't already set a real ISR (avoid overriding guest)
    if (auto cur = VdGetGraphicsInterruptCallback(); cur == 0 || cur == kHostDefaultVdIsrMagic) {
        KernelTraceHostOpF("HOST.VdISR.force_register cb=%08X ctx=%08X", cb_ea, ctx);
        VdSetGraphicsInterruptCallback(cb_ea, ctx);
        // Also register into notification list so VdCallGraphicsNotificationRoutines hits it
        VdRegisterGraphicsNotificationRoutine(cb_ea, ctx);
        Mw05LogIsrIfRegisteredOnce();
        // Immediately drive one notify so the newly registered ISR runs right away
        VdCallGraphicsNotificationRoutines(0u);
    } else {
        KernelTraceHostOp("HOST.VdISR.force_register.skipped (already set)\n");
    }
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
    // Trust guest-provided base/len; ensure our cache matches for VdGetSystemCommandBuffer callers.
    if (base != 0)
    {
        KernelTraceHostOpF("HOST.VdSetSystemCommandBuffer base=%08X len=%u", base, len);
        g_VdSystemCommandBuffer.store(base);
        g_SysCmdBufGuest = base;
        g_SysCmdBufHost = g_memory.Translate(base);
        // Opportunistic scan when the guest sets the system buffer explicitly.
        const uint32_t scanBytes = (len != 0) ? len : kSysCmdBufSize;
        KernelTraceHostOpF("HOST.PM4.SysBufScan.set base=%08X bytes=%u", base, (unsigned)scanBytes);
        extern void PM4_ScanLinear(uint32_t addr, uint32_t bytes);
        PM4_ScanLinear(base, scanBytes);
    }
    (void)len;
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] SetSystemCommandBuffer -> 0x%08X\n", base);
        fflush(stdout);
    }
}


void _vsnprintf_x()
{
    LOG_UTILITY("!!! STUB !!!");
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
    g_vblankPumpRun.store(false, std::memory_order_release);


}

void VdQueryVideoMode(XVIDEO_MODE* vm)
{
    KernelTraceHostOp("HOST.VdQueryVideoMode");

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
    g_VdGraphicsCallback = callback;
    g_VdGraphicsCallbackCtx = context;
    LOGFN("[vd] SetGraphicsInterruptCallback cb=0x{:08X} ctx=0x{:08X}", callback, context);
    KernelTraceHostOpF("HOST.VdSetGraphicsInterruptCallback cb=%08X ctx=%08X", callback, context);
}
void VdRegisterGraphicsNotificationRoutine(uint32_t callback, uint32_t context)
{
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


void VdInitializeEngines()
{
    KernelTraceHostOp("HOST.VdInitializeEngines");
    Mw05ApplyVdPokesOnce();
    // Consider engines initialized; also start the vblank pump to ensure
    // display-related waiters can make progress during bring-up.
    Mw05AutoVideoInitIfNeeded();
    Mw05StartVblankPumpOnce();
}

uint32_t VdIsHSIOTrainingSucceeded()
{
    // Unblock caller loops waiting for HSIO training.
    return 1;
}

void VdGetCurrentDisplayGamma()
{
    KernelTraceHostOp("HOST.VdGetCurrentDisplayGamma");
    LOG_UTILITY("!!! STUB !!!");
}

void VdQueryVideoFlags()
{
    KernelTraceHostOp("HOST.VdQueryVideoFlags");
    LOG_UTILITY("!!! STUB !!!");
}

void VdInitializeEDRAM()
{
    KernelTraceHostOp("HOST.VdInitializeEDRAM");
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] InitializeEDRAM()\n"); fflush(stdout);
    }
}

void VdCallGraphicsNotificationRoutines(uint32_t source)
{
    KernelTraceHostOpF("HOST.VdCallGraphicsNotificationRoutines source=%u", source);

    // First, dispatch any registered graphics notification routines (list),
    // which some titles rely on to advance their render scheduler.
    {
        std::vector<std::pair<uint32_t,uint32_t>> local;
        {
            std::scoped_lock lk(g_VdNotifMutex);
            local = g_VdNotifList; // copy to avoid holding lock while calling guest
        }
        static const bool s_force_ctx_sched = [](){
            if (const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED")) return !(v[0]=='0' && v[1]=='\0');
            return false;
        }();
        for (const auto& [ncb, nctx] : local) {
            if (!ncb) continue;
            if (ncb == kHostDefaultVdIsrMagic) {
                KernelTraceHostOp("HOST.VdNotify.host_isr");
                Mw05RunHostDefaultVdIsrNudge("notify");
            } else {
                // Optionally override context with discovered scheduler pointer

                uint32_t use_ctx = nctx;
                if (s_force_ctx_sched) {
                    uint32_t sched = Mw05Trace_LastSchedR3();
                    if (GuestOffsetInRange(sched, 4)) use_ctx = sched;
                }
                // Gate guest ISR dispatch for a few ticks after startup to avoid early-boot crashes
                static const uint32_t s_guest_isr_delay = [](){
                    if (const char* v = std::getenv("MW05_GUEST_ISR_DELAY_TICKS"))
                        return (uint32_t)std::strtoul(v, nullptr, 10);
                    return 0u; // default: no delay unless configured
                }();
                const uint32_t ticks = g_vblankTicks.load(std::memory_order_acquire);
                if (ticks < s_guest_isr_delay) {
                    KernelTraceHostOpF("HOST.VdNotify.dispatch.skip.early ticks=%u<%u", (unsigned)ticks, (unsigned)s_guest_isr_delay);
                } else {
                    KernelTraceHostOpF("HOST.VdNotify.dispatch cb=%08X ctx=%08X", ncb, use_ctx);
                    // Xbox 360 graphics notify routine typically receives (source, context),
                    // but allow an opt-in param swap for experiments.
            // Optional: dump a small window of the scheduler context in notify-list dispatch
            if (const char* dump = std::getenv("MW05_DUMP_SCHED_CTX")) {
                if (!(dump[0]=='0' && dump[1]=='\0') && GuestOffsetInRange(use_ctx, 64)) {
                    const uint32_t* p32 = reinterpret_cast<const uint32_t*>(g_memory.Translate(use_ctx));
                    if (p32) {
                    #if defined(_MSC_VER)
                        auto bswap = [](uint32_t v){ return _byteswap_ulong(v); };
                    #else
                        auto bswap = [](uint32_t v){ return __builtin_bswap32(v); };
                    #endif
                        KernelTraceHostOpF("HOST.SchedCtxDump %08X: %08X %08X %08X %08X", use_ctx + 0, bswap(p32[0]), bswap(p32[1]), bswap(p32[2]), bswap(p32[3]));
                        KernelTraceHostOpF("HOST.SchedCtxDump %08X: %08X %08X %08X %08X", use_ctx + 16, bswap(p32[4]), bswap(p32[5]), bswap(p32[6]), bswap(p32[7]));
                    }
                }
            }

                    EnsureGuestContextForThisThread("VdNotifyList");
                    static const bool s_isr_swap = [](){
                        if (const char* v = std::getenv("MW05_VD_ISR_SWAP_PARAMS")) return !(v[0]=='0' && v[1]=='\0');
                        return false;
                    }();
                    if (s_isr_swap) {
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
    if (cb) {
        if (cb == kHostDefaultVdIsrMagic) {
            KernelTraceHostOp("HOST.VdCallGraphicsNotificationRoutines.host_isr");
            Mw05RunHostDefaultVdIsrNudge("vd_call");
        } else {
            uint32_t ctx = VdGetGraphicsInterruptContext();
            // Optionally override context with discovered scheduler pointer
            static const bool s_force_ctx_sched2 = [](){
                if (const char* v = std::getenv("MW05_VD_ISR_CTX_SCHED")) return !(v[0]=='0' && v[1]=='\0');
                return false;
            }();
            if (s_force_ctx_sched2) {
                uint32_t sched = Mw05Trace_LastSchedR3();
                if (GuestOffsetInRange(sched, 4)) ctx = sched;
            }
            // Gate guest ISR dispatch for a few ticks after startup to avoid early-boot crashes
            static const uint32_t s_guest_isr_delay2 = [](){
                if (const char* v = std::getenv("MW05_GUEST_ISR_DELAY_TICKS"))
                    return (uint32_t)std::strtoul(v, nullptr, 10);
                return 0u; // default: no delay unless configured
            }();
            const uint32_t ticks2 = g_vblankTicks.load(std::memory_order_acquire);
            if (ticks2 < s_guest_isr_delay2) {
                KernelTraceHostOpF("HOST.VdInterruptEvent.dispatch.skip.early ticks=%u<%u (via VdCallGraphicsNotificationRoutines)", (unsigned)ticks2, (unsigned)s_guest_isr_delay2);
            } else {
                KernelTraceHostOpF("HOST.VdInterruptEvent.dispatch cb=%08X ctx=%08X (via VdCallGraphicsNotificationRoutines)", cb, ctx);
                EnsureGuestContextForThisThread("VdCallGraphicsNotificationRoutines");
                static const bool s_isr_swap2 = [](){
                    if (const char* v = std::getenv("MW05_VD_ISR_SWAP_PARAMS")) return !(v[0]=='0' && v[1]=='\0');
                    return false;
                }();
                if (s_isr_swap2) {
                    KernelTraceHostOp("HOST.VdInterruptEvent.dispatch.swap r3<->r4");
                    GuestToHostFunction<void>(cb, ctx, 0u);
                } else {
                    GuestToHostFunction<void>(cb, 0u, ctx);
                }

                // Optional: try the one-shot present-wrapper nudge from within the ISR
                // thread context. This more closely matches the title's expected calling
                // environment than firing from the host pump.
                static const bool s_force_present_wrapper_once_vd = [](){
                    if (const char* v = std::getenv("MW05_FORCE_PRESENT_WRAPPER_ONCE"))
                        return !(v[0]=='0' && v[1]=='\0');
                    return false;
                }();
                static bool s_present_wrapper_fired_vd = false;
                if (s_force_present_wrapper_once_vd && !s_present_wrapper_fired_vd && !g_sawRealVdSwap.load(std::memory_order_acquire)) {
                    const uint32_t seen = Mw05Trace_SchedR3SeenCount();
                    if (seen >= 3u) {
                        uint32_t r3_ea = Mw05Trace_LastSchedR3();
                        if (!GuestOffsetInRange(r3_ea, 4)) {
                            if (const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
                                uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
                                if (GuestOffsetInRange(env_r3, 4)) r3_ea = env_r3;
                            }
                        }
                        if (GuestOffsetInRange(r3_ea, 4)) {
                            KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.vdcall.enter r3=%08X", r3_ea);
                            EnsureGuestContextForThisThread("FPWOnce.vdcall");
                            bool use_inner_vd = false;
                            if (const char* v = std::getenv("MW05_FORCE_PRESENT_INNER"))
                                use_inner_vd = !(v[0]=='0' && v[1]=='\0');
                            const uint32_t vd_target = use_inner_vd ? 0x825A54F0u : 0x82598A20u;
                        #if defined(_WIN32)
                            __try {
                                GuestToHostFunction<void>(vd_target, r3_ea, 0x40u);
                                KernelTraceHostOp("HOST.ForcePresentWrapperOnce.vdcall.ret");
                                // Optional: kick PM4 builder even if the wrapper returned, to see if it produces draws
                                if (const char* k = std::getenv("MW05_FPW_KICK_PM4")) {
                                    if (!(k[0]=='0' && k[1]=='\0')) {
                                        __try {
                                            GuestToHostFunction<void>(0x82595FC8u, r3_ea, 64u);
                                            KernelTraceHostOpF("HOST.FPW.vdcall.kick.pm4 r3=%08X", r3_ea);
                                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                                            KernelTraceHostOpF("HOST.FPW.kick.pm4.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                        }
                                        // Also try the sibling PM4 path sub_825972B0
                                        __try {
                                            GuestToHostFunction<void>(0x825972B0u, r3_ea, 64u);
                                            KernelTraceHostOpF("HOST.FPW.vdcall.kick.pm4b r3=%08X", r3_ea);
                                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                                            KernelTraceHostOpF("HOST.FPW.kick.pm4b.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                        }
                                    }
                                }
                                s_present_wrapper_fired_vd = true;
                            } __except (EXCEPTION_EXECUTE_HANDLER) {
                                KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.vdcall.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                // Fallback on vdcall fault: try inner present-manager and PM4 kick
                                if (GuestOffsetInRange(r3_ea, 4)) {
                                    __try {
                                        GuestToHostFunction<void>(0x825A54F0u, r3_ea, 0x40u);
                                        KernelTraceHostOp("HOST.FPW.vdcall.fallback.inner.ret");
                                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                                        KernelTraceHostOpF("HOST.FPW.vdcall.fallback.inner.seh_abort code=%08X", (unsigned)GetExceptionCode());
                                    }
                                    if (const char* k = std::getenv("MW05_FPW_KICK_PM4")) {
                                        if (!(k[0]=='0' && k[1]=='\0')) {
                                            __try {
                                                GuestToHostFunction<void>(0x82595FC8u, r3_ea, 64u);
                                                KernelTraceHostOpF("HOST.FPW.vdcall.kick.pm4 r3=%08X", r3_ea);
                                            } __except (EXCEPTION_EXECUTE_HANDLER) {
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
                            KernelTraceHostOp("HOST.ForcePresentWrapperOnce.vdcall.defer r3_unsuitable");
                        }
                    } else {
                        KernelTraceHostOpF("HOST.ForcePresentWrapperOnce.vdcall.defer r3_unstable seen=%u", seen);
                    }
                }
            }
        }
    } else {
        const char* f = std::getenv("MW05_FORCE_VD_ISR");
        if (f && !(f[0]=='0' && f[1]=='\0')) {
            KernelTraceHostOp("HOST.VdCallGraphicsNotificationRoutines.forced.no_cb");
        } else {
            KernelTraceHostOp("HOST.VdCallGraphicsNotificationRoutines.no_cb");
        }
    }
}

void VdInitializeScalerCommandBuffer()
{
    KernelTraceHostOp("HOST.VdInitializeScalerCommandBuffer");
    LOG_UTILITY("!!! STUB !!!");
}

void KeLeaveCriticalRegion()
{
    LOG_UTILITY("!!! STUB !!!");
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
    LOG_UTILITY("!!! STUB !!!");
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
    return g_memory.MapVirtual(g_userHeap.AllocPhysical(size, alignment));
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
    LOG_UTILITY("!!! STUB !!!");
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
    // Having this a global thread_local variable
    // for some reason crashes on boot in debug builds.
    thread_local std::vector<uint32_t> s_tlsValues;

    if (s_tlsValues.size() <= index)
    {
        s_tlsValues.resize(index + 1, 0);
    }

    return s_tlsValues[index];
}

uint32_t KeTlsGetValue(uint32_t dwTlsIndex)
{
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
    if (buffer != nullptr)
    {
        memset(buffer, 0, *bufferSize);
    }
    else
    {
        *bufferSize = 4;
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

    hThread->suspended = false;
    hThread->suspended.notify_all();

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

    KernelTraceHostOpF("HOST.ExCreateThread entry=%08X ctx=%08X flags=%08X", startAddress, startContext, creationFlags);

    uint32_t hostThreadId;

    *handle = GetKernelHandle(GuestThread::Start({ startAddress, startContext, creationFlags }, &hostThreadId));

    if (threadId != nullptr)
        *threadId = hostThreadId;

    KernelTraceHostOpF("HOST.ExCreateThread DONE entry=%08X hostTid=%08X", startAddress, hostThreadId);

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

    object->suspended = false;
    object->suspended.notify_all();
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

void XMACreateContext()
{
    LOG_UTILITY("!!! STUB !!!");
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

GUEST_FUNCTION_STUB(__imp__NtSetTimerEx);
GUEST_FUNCTION_STUB(__imp__NtCreateTimer);

// Additional minimal stubs to satisfy link for mappings that are unused at runtime.
GUEST_FUNCTION_STUB(__imp__Refresh);
GUEST_FUNCTION_STUB(__imp__XamInputGetKeystrokeEx);
GUEST_FUNCTION_STUB(__imp__VdGetGraphicsAsicID);
GUEST_FUNCTION_HOOK(__imp__VdQuerySystemCommandBuffer, VdQuerySystemCommandBuffer);
GUEST_FUNCTION_HOOK(__imp__VdSetSystemCommandBuffer, VdSetSystemCommandBuffer);
GUEST_FUNCTION_HOOK(__imp__VdInitializeEDRAM, VdInitializeEDRAM);
GUEST_FUNCTION_STUB(__imp__MmSetAddressProtect);
GUEST_FUNCTION_STUB(__imp__NtCreateIoCompletion);
GUEST_FUNCTION_STUB(__imp__NtSetIoCompletion);
GUEST_FUNCTION_STUB(__imp__NtRemoveIoCompletion);
GUEST_FUNCTION_STUB(__imp__ObOpenObjectByPointer);
GUEST_FUNCTION_STUB(__imp__ObLookupThreadByThreadId);
GUEST_FUNCTION_STUB(__imp__KeSetDisableBoostThread);
GUEST_FUNCTION_STUB(__imp__NtQueueApcThread);
GUEST_FUNCTION_STUB(__imp__RtlCompareMemory);
GUEST_FUNCTION_STUB(__imp__XamCreateEnumeratorHandle);
GUEST_FUNCTION_STUB(__imp__XMsgSystemProcessCall);
GUEST_FUNCTION_STUB(__imp__XamGetPrivateEnumStructureFromHandle);
GUEST_FUNCTION_STUB(__imp__NetDll_XNetCleanup);

// Missing exports reported by linker for PPC mappings
GUEST_FUNCTION_STUB(__imp__NtCreateMutant);
GUEST_FUNCTION_STUB(__imp__NtReleaseMutant);
GUEST_FUNCTION_STUB(__imp__NtYieldExecution);
GUEST_FUNCTION_STUB(__imp__FscGetCacheElementCount);
GUEST_FUNCTION_STUB(__imp__XamVoiceHeadsetPresent);
GUEST_FUNCTION_STUB(__imp__XamVoiceClose);
GUEST_FUNCTION_STUB(__imp__XMsgCancelIORequest);
GUEST_FUNCTION_STUB(__imp__XamVoiceSubmitPacket);
GUEST_FUNCTION_STUB(__imp__XamVoiceCreate);
GUEST_FUNCTION_STUB(__imp__XAudioQueryDriverPerformance);
GUEST_FUNCTION_STUB(__imp__KeTryToAcquireSpinLockAtRaisedIrql);
GUEST_FUNCTION_STUB(__imp__KePulseEvent);
GUEST_FUNCTION_STUB(__imp__MmAllocatePhysicalMemory);
GUEST_FUNCTION_STUB(__imp__XMASetInputBufferReadOffset);
GUEST_FUNCTION_STUB(__imp__XMABlockWhileInUse);
GUEST_FUNCTION_STUB(__imp__XMASetLoopData);
GUEST_FUNCTION_STUB(__imp__NtCancelTimer);
GUEST_FUNCTION_STUB(__imp__ObOpenObjectByName);
GUEST_FUNCTION_STUB(__imp__NtPulseEvent);
GUEST_FUNCTION_STUB(__imp__NtSignalAndWaitForSingleObjectEx);
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
