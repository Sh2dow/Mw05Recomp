#include <stdafx.h>
#include <cpu/ppc_context.h>
#include <cpu/guest_thread.h>
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


static std::atomic<uint32_t> g_keSetEventGeneration;
static std::atomic<uint32_t> g_vdInterruptEventEA{0};
static std::atomic<bool> g_vdInterruptPending{false};
static std::atomic<bool> g_vblankPumpRun{false};
static std::atomic<bool> g_guestHasSwapped{false};

extern "C"
{
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
}

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

// Forward declaration for early calls in this file
uint32_t KeWaitForSingleObject(XDISPATCHER_HEADER* Object, uint32_t WaitReason, uint32_t WaitMode, bool Alertable, be<int64_t>* Timeout);

static std::atomic<uint32_t> g_RbWriteBackPtr{0};
static std::atomic<uint32_t> g_RbBase{0}, g_RbLen{0};

#ifndef FILE_SUPERSEDED
#define FILE_SUPERSEDED        0
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

    const uint32_t len_log2 = 12; // 4 KiB ring
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

extern "C" {
	uint32_t VdGetGraphicsInterruptCallback() { return g_VdGraphicsCallback.load(); }
	uint32_t VdGetGraphicsInterruptContext() { return g_VdGraphicsCallbackCtx.load(); }
}

struct Event final : KernelObject, HostObject<XKEVENT>
{
    bool manualReset;
    std::atomic<bool> signaled;

    Event(XKEVENT* header)
        : manualReset(!header->Type), signaled(!!header->SignalState)
    {
    }

    Event(bool manualReset, bool initialState)
        : manualReset(manualReset), signaled(initialState)
    {
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

static inline void NudgeEventWaiters() {
    g_keSetEventGeneration.fetch_add(1, std::memory_order_acq_rel);
    g_keSetEventGeneration.notify_all();
}
static bool Mw05SignalVdInterruptEvent();
static void Mw05DispatchVdInterruptIfPending();

static inline bool Mw05VblankPumpEnabled() {
    // Default ON to improve bring-up, allow disabling with MW05_VBLANK_PUMP=0
    static const bool on = [](){
        if (const char* v = std::getenv("MW05_VBLANK_PUMP"))
            return !(v[0]=='0' && v[1]=='\0');
        return true;
    }();
    return on;
}

void VdSwap()
{
    KernelTraceHostOp("HOST.VdSwap");
    // Mark that the guest performed a swap at least once
    g_guestHasSwapped.store(true, std::memory_order_release);
    // Present the current backbuffer and advance frame state
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[boot] VdSwap()\n"); fflush(stdout);
    }
    Video::Present();

    // Nudge ring-buffer RPtr write-back so guest polling sees forward progress
    uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);
    if (wb)
    {
        if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(wb)))
        {
            uint32_t cur = *rptr;
            uint32_t len_log2 = g_RbLen.load(std::memory_order_relaxed) & 31u;
            uint32_t mask = len_log2 ? ((1u << len_log2) - 1u) : 0xFFFFu;
            uint32_t next = (cur + 0x80u) & mask;
            *rptr = next ? next : 0x40u;
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
                if (std::getenv("MW05_FORCE_PRESENT") || std::getenv("MW05_FORCE_PRESENT_BG") || std::getenv("MW05_KICK_VIDEO"))
                    return false;
                // Default: enabled only when not in forced-present bring-up paths
                return true;
            }();
            if (cb_on) {
                const uint32_t cb = VdGetGraphicsInterruptCallback();
                if (cb) {
                    const uint32_t ctx = VdGetGraphicsInterruptContext();
                    // GuestToHostFunction safely constructs a PPCContext and calls the guest function.
                    GuestToHostFunction<void>(cb, ctx);
                }
            }

            // Optional: request a present each vblank to keep swapchain moving.
            // Do not call Present() from the background thread; signal the main thread instead.
            if (s_force_present) {
                Video::RequestPresentFromBackground();
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
            else if (std::getenv("MW05_FORCE_PRESENT") || std::getenv("MW05_FORCE_PRESENT_BG") || std::getenv("MW05_KICK_VIDEO"))
                cb_enabled = false;

            if (cb_enabled) {
                if (const uint32_t cb = VdGetGraphicsInterruptCallback()) {
                    const uint32_t ctx = VdGetGraphicsInterruptContext();
                    KernelTraceHostOpF("HOST.VdInterruptEvent.dispatch cb=%08X ctx=%08X", cb, ctx);
                    GuestToHostFunction<void>(cb, ctx);
                } else if (const char* f = std::getenv("MW05_FORCE_VD_ISR")) {
                    if (!(f[0]=='0' && f[1]=='\0')) {
                        KernelTraceHostOp("HOST.VdInterruptEvent.dispatch.forced.no_cb");
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

    Semaphore(XKSEMAPHORE* semaphore)
        : count(semaphore->Header.SignalState), maximumCount(semaphore->Limit)
    {
    }

    Semaphore(uint32_t count, uint32_t maximumCount)
        : count(count), maximumCount(maximumCount)
    {
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

void XexExecutableModuleHandle()
{
    LOG_UTILITY("!!! STUB !!!");
}

void ExLoadedCommandLine()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KeDebugMonitorData()
{
    LOG_UTILITY("!!! STUB !!!");
}

void ExThreadObjectType()
{
    LOG_UTILITY("!!! STUB !!!");
}

void KeTimeStampBundle()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XboxHardwareInfo()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t XGetGameRegion()
{
    if (Config::Language == ELanguage::Japanese)
        return 0x0101;

    return 0x03FF;
}

uint32_t XMsgStartIORequest(uint32_t App, uint32_t Message, XXOVERLAPPED* lpOverlapped, void* Buffer, uint32_t szBuffer)
{
    return STATUS_SUCCESS;
}

uint32_t XamUserGetSigninState(uint32_t userIndex)
{
    return userIndex == 0 ? 1u : 0u;
}

uint32_t XamGetSystemVersion()
{
    return 0;
}

void XamContentDelete()
{
    LOG_UTILITY("!!! STUB !!!");
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

void XamGetExecutionId()
{
    LOG_UTILITY("!!! STUB !!!");
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
    }

    *RequiredSize = 4;
    memcpy(Buffer, data, std::min((size_t)SizeOfBuffer, sizeof(data)));

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

void XexGetProcedureAddress()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XexGetModuleSection()
{
    LOG_UTILITY("!!! STUB !!!");
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
    const bool fastBoot  = Mw05FastBootEnabled();

    // Ensure early video bring-up keeps the UI responsive during waits/delays
	Mw05ForceVdInitOnce();  // opt-in early engines + ring/wb
    Mw05AutoVideoInitIfNeeded();
    Mw05StartVblankPumpOnce();
    // One-time forced VD event registration if requested via env
    Mw05MaybeForceRegisterVdEventFromEnv();

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

void NtQueryDirectoryFile()
{
    LOG_UTILITY("!!! STUB !!!");
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
        const bool on = (t1 && !(t1[0]=='0' && t1[1]==' ')) || (t2 && !(t2[0]=='0' && t2[1]==' '));
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

    // Heuristic: register display interrupt event on first wait to ensure vblank pump can signal it.
    if (g_vdInterruptEventEA.load(std::memory_order_acquire) == 0) {
        if (auto ea = g_memory.MapVirtual(Object)) {
            if (GuestOffsetInRange(ea, sizeof(XDISPATCHER_HEADER))) {
                Mw05RegisterVdInterruptEvent(ea, Object->Type == 0);
            }
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

void RtlImageXexHeaderField()
{
    LOG_UTILITY("!!! STUB !!!");
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
    const bool honor = (allow && allow[0] && !(allow[0]=='0' && allow[1]==' '));

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
    if (honor && honor[0] && !(honor[0]=='0' && honor[1]==' '))
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
    std::atomic_ref spinLockRef(*spinLock);
    spinLockRef = 0;
}

void KfAcquireSpinLock(uint32_t* spinLock)
{
    std::atomic_ref spinLockRef(*spinLock);

    while (true)
    {
        uint32_t expected = 0;
        if (spinLockRef.compare_exchange_weak(expected, g_ppcContext->r13.u32))
            break;

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
    }
}

uint32_t VdGetSystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue)
{
    EnsureSystemCommandBuffer();
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] GetSystemCommandBuffer -> 0x%08X\n", g_SysCmdBufGuest);
        fflush(stdout);
    }
    if (outCmdBufPtr) *outCmdBufPtr = g_SysCmdBufGuest;
    if (outValue)     *outValue     = 0; // MW05 reads this; 0 is a safe default
    return g_SysCmdBufGuest;


}

uint32_t VdQuerySystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue)
{
    KernelTraceHostOp("HOST.VdQuerySystemCommandBuffer");

    EnsureSystemCommandBuffer();
    if (outCmdBufPtr) *outCmdBufPtr = g_SysCmdBufGuest;
    if (outValue)     *outValue     = 0;
    return 0;
}

void KeReleaseSpinLockFromRaisedIrql(uint32_t* spinLock)
{
    std::atomic_ref spinLockRef(*spinLock);
    spinLockRef = 0;
}

void KeAcquireSpinLockAtRaisedIrql(uint32_t* spinLock)
{
    std::atomic_ref spinLockRef(*spinLock);

    while (true)
    {
        uint32_t expected = 0;
        if (spinLockRef.compare_exchange_weak(expected, g_ppcContext->r13.u32))
            break;

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
    Mw05DispatchVdInterruptIfPending();
    // Ensure vblank pump is running so display waiters can progress.
    Mw05StartVblankPumpOnce();
}

void VdInitializeRingBuffer(uint32_t base, uint32_t len)
{
    KernelTraceHostOpF("HOST.VdInitializeRingBuffer base=%08X len_log2=%u", base, len);
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
    g_vdInterruptPending.store(true, std::memory_order_release);
    Mw05DispatchVdInterruptIfPending();
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
void Mw05ForceVdInitOnce() {
    if (!Mw05ForceVdInitEnabled()) return;
    bool expected = false;
    if (!g_forceVdInitDone.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    KernelTraceHostOp("HOST.ForceVD.init.begin");

    // Reuse your existing small auto-init to ensure ring & write-back exist:
    Mw05AutoVideoInitIfNeeded();

    // Then bring engines up explicitly.
    // (All these helpers already exist in this file.)
    VdInitializeEngines();

    // Make sure the system command buffer is allocated (idempotent).
    VdGetSystemCommandBuffer(nullptr, nullptr);

    // Start vblank pump to keep things flowing even if the title idles early.
    Mw05StartVblankPumpOnce();

    KernelTraceHostOp("HOST.ForceVD.init.done");
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
    }
    (void)len;
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[vd] SetSystemCommandBuffer base=0x%08X len=%u\n", base, len);
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

void VdInitializeEngines()
{
    KernelTraceHostOp("HOST.VdInitializeEngines");
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

void VdCallGraphicsNotificationRoutines()
{
    KernelTraceHostOp("HOST.VdCallGraphicsNotificationRoutines");
    const uint32_t cb = VdGetGraphicsInterruptCallback();
    if (cb) {
        const uint32_t ctx = VdGetGraphicsInterruptContext();
        KernelTraceHostOpF("HOST.VdInterruptEvent.dispatch cb=%08X ctx=%08X (via VdCallGraphicsNotificationRoutines)", cb, ctx);
        GuestToHostFunction<void>(cb, ctx);
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

void XMsgStartIORequestEx()
{
    LOG_UTILITY("!!! STUB !!!");
}

void XexGetModuleHandle()
{
    LOG_UTILITY("!!! STUB !!!");
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
    LOG_UTILITY("!!! STUB !!!");
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
    // Early-boot/list-shims fast path (same behavior no matter who calls us)
    if (EarlyBootGate("MW05_FAST_BOOT",   "HOST.FastWait.KeWaitForMultipleObjects",   g_waits_t0) ||
        EarlyBootGate("MW05_LIST_SHIMS",  "HOST.MW05_LIST_SHIMS.KeWaitForMultipleObjects", g_waits_t0)) {
        // Pretend вЂњwait anyвЂќ hit index 0; вЂњwait allвЂќ -> success
        return (WaitType == 0) ? (STATUS_WAIT_0 + 0) : STATUS_SUCCESS;
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
    // Guards
    if (!HandlesOrDispatchers) return STATUS_INVALID_PARAMETER;
    // NT has a limit (64). Use your projectвЂ™s constant if it exists.
    if (Count == 0 || Count > 64) return STATUS_INVALID_PARAMETER;

    const bool fastBoot  = Mw05FastBootEnabled();
    const bool listShims = Mw05ListShimsEnabled();
    static const auto t0 = std::chrono::steady_clock::now();
    const auto elapsed   = std::chrono::steady_clock::now() - t0;

    // Early-boot short-circuit ONLY for fast-boot
    if (fastBoot && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.FastWait.NtWaitForMultipleObjectsEx");
        // Heuristically mark dispatcher headers signaled
        for (uint32_t i = 0; i < Count; ++i) {
            const uint32_t v = HandlesOrDispatchers[i];
            if (GuestOffsetInRange(v, sizeof(XDISPATCHER_HEADER))) {
                auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(v));
                hdr->SignalState = be<int32_t>(1);
            }
        }
        Mw05NudgeEventWaiters();
        // For wait-any, pretend index 0 fired; for wait-all, success.
        return (WaitType == 0) ? (STATUS_WAIT_0 + 0) : STATUS_SUCCESS;
    }

    // LIST_SHIMS: trace only (no bypass)
    if (listShims && elapsed < std::chrono::seconds(30)) {
        KernelTraceHostOp("HOST.MW05_LIST_SHIMS.NtWaitForMultipleObjectsEx");
    }

    const uint32_t timeout_ms = GuestTimeoutToMilliseconds(Timeout);
    const bool wait_all = (WaitType != 0);

    // Build a vector of KernelObject* from mixed inputs
    std::vector<KernelObject*> objs;
    objs.reserve(Count);

    for (uint32_t i = 0; i < Count; ++i) {
        const uint32_t v = HandlesOrDispatchers[i];

        if (IsKernelObject(v)) {
            KernelObject* ko = GetKernelObject(v);
            if (!IsKernelObjectAlive(ko)) return STATUS_INVALID_HANDLE;
            objs.push_back(ko);
            continue;
        }

        // Treat as guest dispatcher pointer (EA)
        if (!GuestOffsetInRange(v, sizeof(XDISPATCHER_HEADER)))
            return STATUS_INVALID_HANDLE;

        auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(v));
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
        if (!ko) return STATUS_INVALID_HANDLE;
        objs.push_back(ko);
    }

    // Portable polling loop (you can swap in your generation-wait fast path later)
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
            // TODO: if you wire APCs, return STATUS_USER_APC where appropriate
        }
        if (expired()) return STATUS_TIMEOUT;

        std::this_thread::sleep_for(std::chrono::milliseconds(1)); // light backoff
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

    uint32_t hostThreadId;

    *handle = GetKernelHandle(GuestThread::Start({ startAddress, startContext, creationFlags }, &hostThreadId));

    if (threadId != nullptr)
        *threadId = hostThreadId;

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
GUEST_FUNCTION_STUB(__imp__XamLoaderGetLaunchDataSize);
GUEST_FUNCTION_STUB(__imp__XamLoaderGetLaunchData);
GUEST_FUNCTION_STUB(__imp__XamLoaderSetLaunchData);
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
