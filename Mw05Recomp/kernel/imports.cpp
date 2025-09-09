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

#ifdef _WIN32
#include <ntstatus.h>
#endif

// Forward declaration for early calls in this file
uint32_t KeWaitForSingleObject(XDISPATCHER_HEADER* Object, uint32_t WaitReason, uint32_t WaitMode, bool Alertable, be<int64_t>* Timeout);

// helper (place near the top of the file with other helpers)
inline bool GuestOffsetInRange(uint32_t off, size_t bytes = 1) {
    if (off == 0) return false;
    if (off < 4096) return false; // guard page
    return (size_t)off + bytes <= PPC_MEMORY_SIZE;
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

static std::atomic<uint32_t> g_keSetEventGeneration;

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

uint32_t GuestTimeoutToMilliseconds(be<int64_t>* timeout)
{
    return timeout ? (*timeout * -1) / 10000 : INFINITE;
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

void XGetVideoMode()
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

void NtOpenFile()
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

uint32_t NtCreateFile
(
    be<uint32_t>* FileHandle,
    uint32_t DesiredAccess,
    XOBJECT_ATTRIBUTES* Attributes,
    XIO_STATUS_BLOCK* IoStatusBlock,
    uint64_t* AllocationSize,
    uint32_t FileAttributes,
    uint32_t ShareAccess,
    uint32_t CreateDisposition,
    uint32_t CreateOptions
)
{
    return 0;
}

uint32_t NtClose(uint32_t handle)
{
    if (handle == GUEST_INVALID_HANDLE_VALUE)
        return STATUS_INVALID_HANDLE; // 0xC0000008

    if (IsKernelObject(handle))
    {
        DestroyKernelObject(handle);
        return 0;
    }
    else
    {
        assert(false && "Unrecognized kernel object.");
        return 0xFFFFFFFF;
    }
}

void NtSetInformationFile()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t FscSetCacheElementCount()
{
    return 0;
}

uint32_t NtWaitForSingleObjectEx(uint32_t Handle, uint32_t WaitMode, uint32_t Alertable, be<int64_t>* Timeout)
{
    const uint32_t timeout = GuestTimeoutToMilliseconds(Timeout);
	// Accept any timeout; HostObject::Wait already supports finite waits on events/semaphores.

    if (IsKernelObject(Handle))
    {
        return GetKernelObject(Handle)->Wait(timeout);
    }
    else
    {
        // Thread ID path: resolve to kernel handle if known
        if (uint32_t kh = GuestThread::LookupHandleByThreadId(Handle))
        {
            if (const char* t = std::getenv("MW05_TRACE_KERNEL"); t && t[0] && !(t[0]=='0' && t[1]==0))
            {
                LOGFN("[ntwait.tid] handle=0x{:08X} -> kh=0x{:08X}", Handle, kh);
            }
            return GetKernelObject(kh)->Wait(timeout);
        }
        // Dispatcher-pointer path
        if (GuestOffsetInRange(Handle, sizeof(XDISPATCHER_HEADER)))
        {
            auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(Handle));
            if (const char* t = std::getenv("MW05_TRACE_KERNEL"); t && t[0] && !(t[0]=='0' && t[1]==0))
            {
                LOGFN("[ntwait.ptr] handle=0x{:08X} type={} state={}", Handle, (unsigned)hdr->Type, (unsigned)hdr->SignalState);
            }
            return KeWaitForSingleObject(hdr, /*WaitReason*/0, WaitMode, Alertable != 0, Timeout);
        }
        LOGFN_WARNING("[ntwait] non-kernel handle=0x{:08X} waitmode={} alertable={} timeout={} -> fallback success",
                      Handle, WaitMode, Alertable, timeout);
        return STATUS_SUCCESS;
    }

    return STATUS_TIMEOUT;
}

void NtWriteFile()
{
    LOG_UTILITY("!!! STUB !!!");
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

void RtlNtStatusToDosError()
{
    LOG_UTILITY("!!! STUB !!!");
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
    const auto reqSize = BytesInUnicodeString / sizeof(uint16_t);

    if (BytesInMultiByteString)
        *BytesInMultiByteString = reqSize;

    if (reqSize > MaxBytesInMultiByteString)
        return STATUS_FAIL_CHECK;

    for (size_t i = 0; i < reqSize; i++)
    {
        const auto c = UnicodeString[i].get();

        MultiByteString[i] = c < 256 ? c : '?';
    }

    return STATUS_SUCCESS;
}

uint32_t KeDelayExecutionThread(uint32_t /*WaitMode*/, bool Alertable, be<int64_t>* Timeout)
{
    const uint32_t ms = GuestTimeoutToMilliseconds(Timeout);

#ifdef _WIN32
    if (ms == 0) SwitchToThread(); else Sleep(ms);
#else
    if (ms == 0) std::this_thread::yield();
    else std::this_thread::sleep_for(std::chrono::milliseconds(ms));
#endif

    // Unless you actually queue APCs elsewhere, don't fake-alert.
    return STATUS_SUCCESS;
}

// Some titles gate functionality behind kernel privilege checks. Be permissive by default.
uint32_t XexCheckExecutablePrivilege()
{
    return 1; // present
}

void ExFreePool()
{
    LOG_UTILITY("!!! STUB !!!");
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

void NtReadFile()
{
    LOG_UTILITY("!!! STUB !!!");
}

void NtDuplicateObject()
{
    LOG_UTILITY("!!! STUB !!!");
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
    const uint32_t timeout = GuestTimeoutToMilliseconds(Timeout);

    switch (Object->Type)
    {
        case 0: // NotificationEvent
        case 1: // SynchronizationEvent
            QueryKernelObject<Event>(*Object)->Wait(timeout);
            break;

        case 5: // Semaphore
            QueryKernelObject<Semaphore>(*Object)->Wait(timeout);
            break;

        default:
            // Better than assert(false): treat as timed-out/unsupported waitable.
            return STATUS_TIMEOUT;
    }

    return STATUS_SUCCESS;
}

void ObDereferenceObject()
{
    LOG_UTILITY("!!! STUB !!!");
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
    if (!cs)
        return; // Be tolerant of null pointers during early boot paths

    cs->RecursionCount--;

    if (cs->RecursionCount != 0)
        return;

    std::atomic_ref owningThread(cs->OwningThread);
    owningThread.store(0);
    owningThread.notify_one();
}

void RtlEnterCriticalSection(XRTL_CRITICAL_SECTION* cs)
{
    if (!cs)
        return; // Tolerate null critical sections

    uint32_t thisThread = 0;
    if (auto* ctx = GetPPCContext())
        thisThread = ctx->r13.u32;
    if (thisThread == 0)
        thisThread = 1; // Fallback owner id if TLS not yet established

    std::atomic_ref owningThread(cs->OwningThread);

    while (true)
    {
        uint32_t previousOwner = 0;

        if (owningThread.compare_exchange_weak(previousOwner, thisThread) || previousOwner == thisThread)
        {
            cs->RecursionCount++;
            return;
        }

        owningThread.wait(previousOwner);
    }
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

bool VdPersistDisplay(uint32_t a1, uint32_t* a2)
{
    *a2 = NULL;
    return false;
}

void VdSwap()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdGetSystemCommandBuffer()
{
    LOG_UTILITY("!!! STUB !!!");
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

void VdEnableRingBufferRPtrWriteBack()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdInitializeRingBuffer()
{
    LOG_UTILITY("!!! STUB !!!");
}

uint32_t MmGetPhysicalAddress(uint32_t address)
{
    LOGF_UTILITY("0x{:x}", address);
    return address;
}

void VdSetSystemCommandBufferGpuIdentifierAddress()
{
    LOG_UTILITY("!!! STUB !!!");
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
}

void VdQueryVideoMode(XVIDEO_MODE* vm)
{
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

void VdGetCurrentDisplayInformation()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdSetDisplayMode()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdSetGraphicsInterruptCallback()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdInitializeEngines()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdIsHSIOTrainingSucceeded()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdGetCurrentDisplayGamma()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdQueryVideoFlags()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdCallGraphicsNotificationRoutines()
{
    LOG_UTILITY("!!! STUB !!!");
}

void VdInitializeScalerCommandBuffer()
{
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
    if (!cs)
        return true; // Nothing to lock

    uint32_t thisThread = 0;
    if (auto* ctx = GetPPCContext())
        thisThread = ctx->r13.u32;
    if (thisThread == 0)
        thisThread = 1;

    std::atomic_ref owningThread(cs->OwningThread);

    uint32_t previousOwner = 0;

    if (owningThread.compare_exchange_weak(previousOwner, thisThread) || previousOwner == thisThread)
    {
        cs->RecursionCount++;
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

void NtWaitForMultipleObjectsEx()
{
    LOG_UTILITY("!!! STUB !!!");
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

void KeQuerySystemTime(be<uint64_t>* time)
{
    constexpr int64_t FILETIME_EPOCH_DIFFERENCE = 116444736000000000LL;

    auto now = std::chrono::system_clock::now();
    auto timeSinceEpoch = now.time_since_epoch();

    int64_t currentTime100ns = std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, 10000000>>>(timeSinceEpoch).count();
    currentTime100ns += FILETIME_EPOCH_DIFFERENCE;

    *time = currentTime100ns;
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

void ExAllocatePoolTypeWithTag()
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

uint32_t KeWaitForMultipleObjects(uint32_t Count, xpointer<XDISPATCHER_HEADER>* Objects, uint32_t WaitType, uint32_t WaitReason, uint32_t WaitMode, uint32_t Alertable, be<int64_t>* Timeout)
{
    // FIXME: This function is only accounting for events.

    const uint64_t timeout = GuestTimeoutToMilliseconds(Timeout);
    assert(timeout == INFINITE);

    if (WaitType == 0) // Wait all
    {
        for (size_t i = 0; i < Count; i++)
            QueryKernelObject<Event>(*Objects[i])->Wait(timeout);
    }
    else
    {
        thread_local std::vector<Event*> s_events;
        s_events.resize(Count);

        for (size_t i = 0; i < Count; i++)
            s_events[i] = QueryKernelObject<Event>(*Objects[i]);

        while (true)
        {
            uint32_t generation = g_keSetEventGeneration.load();

            for (size_t i = 0; i < Count; i++)
            {
                if (s_events[i]->Wait(0) == STATUS_SUCCESS)
                {
                    return STATUS_WAIT_0 + i;
                }
            }

            g_keSetEventGeneration.wait(generation);
        }
    }

    return STATUS_SUCCESS;
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
GUEST_FUNCTION_STUB(__imp__XamReadTileToTexture);
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
GUEST_FUNCTION_HOOK(__imp__NtOpenFile, NtOpenFile);
GUEST_FUNCTION_HOOK(__imp__RtlInitAnsiString, RtlInitAnsiString);
GUEST_FUNCTION_HOOK(__imp__NtCreateFile, NtCreateFile);
GUEST_FUNCTION_HOOK(__imp__NtClose, NtClose);
GUEST_FUNCTION_HOOK(__imp__NtSetInformationFile, NtSetInformationFile);
GUEST_FUNCTION_HOOK(__imp__FscSetCacheElementCount, FscSetCacheElementCount);
GUEST_FUNCTION_HOOK(__imp__NtWaitForSingleObjectEx, NtWaitForSingleObjectEx);
GUEST_FUNCTION_HOOK(__imp__NtWriteFile, NtWriteFile);
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
GUEST_FUNCTION_HOOK(__imp__ExFreePool, ExFreePool);
GUEST_FUNCTION_HOOK(__imp__NtQueryInformationFile, NtQueryInformationFile);
GUEST_FUNCTION_HOOK(__imp__NtQueryVolumeInformationFile, NtQueryVolumeInformationFile);
GUEST_FUNCTION_HOOK(__imp__NtQueryDirectoryFile, NtQueryDirectoryFile);
GUEST_FUNCTION_HOOK(__imp__NtReadFileScatter, NtReadFileScatter);
GUEST_FUNCTION_HOOK(__imp__NtReadFile, NtReadFile);
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
GUEST_FUNCTION_HOOK(__imp__ExAllocatePoolTypeWithTag, ExAllocatePoolTypeWithTag);
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
GUEST_FUNCTION_STUB(__imp__VdQuerySystemCommandBuffer);
GUEST_FUNCTION_STUB(__imp__VdSetSystemCommandBuffer);
GUEST_FUNCTION_STUB(__imp__VdInitializeEDRAM);
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
GUEST_FUNCTION_STUB(__imp__ExAllocatePool);
GUEST_FUNCTION_STUB(__imp__XamVoiceHeadsetPresent);
GUEST_FUNCTION_STUB(__imp__XamVoiceClose);
GUEST_FUNCTION_STUB(__imp__XMsgCancelIORequest);
GUEST_FUNCTION_STUB(__imp__XamVoiceSubmitPacket);
GUEST_FUNCTION_STUB(__imp__XamVoiceCreate);
GUEST_FUNCTION_STUB(__imp__XAudioQueryDriverPerformance);
GUEST_FUNCTION_STUB(__imp__KeTryToAcquireSpinLockAtRaisedIrql);
GUEST_FUNCTION_STUB(__imp__KePulseEvent);
GUEST_FUNCTION_STUB(__imp__ExAllocatePoolWithTag);
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
GUEST_FUNCTION_STUB(__imp__XamFree);
GUEST_FUNCTION_STUB(__imp__XamAlloc);
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
