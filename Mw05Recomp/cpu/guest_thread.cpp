#include <stdafx.h>
#include "guest_thread.h"
#include <kernel/memory.h>
#include <kernel/heap.h>
#include <kernel/function.h>
#include "ppc_context.h"
#include <kernel/trace.h>
#include <unordered_map>

constexpr size_t PCR_SIZE = 0xAB0;
constexpr size_t TLS_SIZE = 0x100;
constexpr size_t TEB_SIZE = 0x2E0;
constexpr size_t STACK_SIZE = 0x40000;
constexpr size_t TOTAL_SIZE = PCR_SIZE + TLS_SIZE + TEB_SIZE + STACK_SIZE;

constexpr size_t TEB_OFFSET = PCR_SIZE + TLS_SIZE;

// Thread registry: maps guest thread IDs to kernel handles
static std::mutex g_threadRegMutex;
static std::unordered_map<uint32_t, uint32_t> g_tidToHandle;

GuestThreadContext::GuestThreadContext(uint32_t cpuNumber)
{
    assert(thread == nullptr);

    thread = (uint8_t*)g_userHeap.Alloc(TOTAL_SIZE);
    memset(thread, 0, TOTAL_SIZE);

    // CRITICAL: Store pointers in BIG-ENDIAN format (will be byte-swapped when loaded by PPC_LOAD_U32)
    *(uint32_t*)thread = __builtin_bswap32(g_memory.MapVirtual(thread + PCR_SIZE)); // tls pointer at PCR+0
    *(uint32_t*)(thread + 0x100) = __builtin_bswap32(g_memory.MapVirtual(thread + PCR_SIZE + TLS_SIZE)); // teb pointer at PCR+0x100 (256)
    *(thread + 0x10C) = cpuNumber;

    // Initialize PCR+0x150 (336) to 1 to disable error handling in sub_8262EEE0/sub_8262EEF8
    // When this is non-zero, the error handling code is skipped (early return)
    // IMPORTANT: Store in BIG-ENDIAN format (0x00000001 in memory, will be read as 1 by PPC_LOAD_U32)
    *(uint32_t*)(thread + 0x150) = 0x01000000; // Big-endian 1

    *(uint32_t*)(thread + PCR_SIZE + 0x10) = 0xFFFFFFFF; // that one TLS entry that felt quirky
    *(uint32_t*)(thread + PCR_SIZE + TLS_SIZE + 0x14C) = __builtin_bswap32(GuestThread::GetCurrentThreadId()); // thread id

    ppcContext.r1.u64 = g_memory.MapVirtual(thread + PCR_SIZE + TLS_SIZE + TEB_SIZE + STACK_SIZE); // stack pointer
    ppcContext.r13.u64 = g_memory.MapVirtual(thread);
    ppcContext.fpscr.loadFromHost();

    fprintf(stderr, "[GUEST_CTX] Creating context for tid=%08X cpu=%u r13=0x%08X PCR+0x150=0x%08X (before SetPPCContext)\n",
            GuestThread::GetCurrentThreadId(), cpuNumber, ppcContext.r13.u32, *(uint32_t*)(thread + 0x150));
    fflush(stderr);

    assert(GetPPCContext() == nullptr);
    SetPPCContext(ppcContext);

    fprintf(stderr, "[GUEST_CTX] Context set for tid=%08X, GetPPCContext()=%p\n",
            GuestThread::GetCurrentThreadId(), (void*)GetPPCContext());
    fflush(stderr);
}

GuestThreadContext::~GuestThreadContext()
{
    g_userHeap.Free(thread);
}

#ifdef USE_PTHREAD
static size_t GetStackSize()
{
    // Cache as this should not change.
    static size_t stackSize = 0;
    if (stackSize == 0)
    {
        // 8 MiB is a typical default.
        constexpr auto defaultSize = 8 * 1024 * 1024;
        struct rlimit lim;
        const auto ret = getrlimit(RLIMIT_STACK, &lim);
        if (ret == 0 && lim.rlim_cur < defaultSize)
        {
            // Use what the system allows.
            stackSize = lim.rlim_cur;
        }
        else
        {
            stackSize = defaultSize;
        }
    }
    return stackSize;
}

static void* GuestThreadFunc(void* arg)
{
    GuestThreadHandle* hThread = (GuestThreadHandle*)arg;
#else
static void GuestThreadFunc(GuestThreadHandle* hThread)
{
#endif
    const bool was_suspended = hThread->suspended.load();
    if (was_suspended) {
        fprintf(stderr, "[GUEST_THREAD] Thread tid=%08X entry=%08X WAITING for resume...\n",
            hThread->GetThreadId(), hThread->params.function);
        fflush(stderr);
    }

    hThread->suspended.wait(true);

    if (was_suspended) {
        fprintf(stderr, "[GUEST_THREAD] Thread tid=%08X entry=%08X RESUMED, starting execution\n",
            hThread->GetThreadId(), hThread->params.function);
        fflush(stderr);
    }

    GuestThread::Start(hThread->params);

    fprintf(stderr, "[GUEST_THREAD] Thread tid=%08X entry=%08X COMPLETED\n",
        hThread->GetThreadId(), hThread->params.function);
    fflush(stderr);

#ifdef USE_PTHREAD
    return nullptr;
#endif
}

GuestThreadHandle::GuestThreadHandle(const GuestThreadParams& params)
    : params(params), suspended((params.flags & 0x1) != 0)  // Honor CREATE_SUSPENDED flag - game calls NtResumeThread to resume
#ifdef USE_PTHREAD
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, GetStackSize());
    const auto ret = pthread_create(&thread, &attr, GuestThreadFunc, this);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed with error code 0x%X.\n", ret);
        return;
    }
}
#else
      , thread(GuestThreadFunc, this)
{
}
#endif

GuestThreadHandle::~GuestThreadHandle()
{
#ifdef USE_PTHREAD
    pthread_join(thread, nullptr);
#else
    if (thread.joinable())
        thread.join();
#endif
}

template <typename ThreadType>
static uint32_t CalcThreadId(const ThreadType& id)
{
    if constexpr (sizeof(id) == 4)
        return *reinterpret_cast<const uint32_t*>(&id);
    else
        return XXH32(&id, sizeof(id), 0);
}

uint32_t GuestThreadHandle::GetThreadId() const
{
#ifdef USE_PTHREAD
    return CalcThreadId(thread);
#else
    return CalcThreadId(thread.get_id());
#endif
}

uint32_t GuestThreadHandle::Wait(uint32_t timeout)
{
    assert(timeout == INFINITE);

#ifdef USE_PTHREAD
    pthread_join(thread, nullptr);
#else
    if (thread.joinable())
        thread.join();
#endif

    return STATUS_WAIT_0;
}

uint32_t GuestThread::Start(const GuestThreadParams& params)
{
    // Early diagnostic: print entry address before lookup when verbose
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE))
    {
        printf("[boot] GuestThread::Start entry=0x%08X flags=0x%08X value=0x%08X\n", params.function, params.flags, (uint32_t)params.value);
        fflush(stdout);
    }
    const auto procMask = (uint8_t)(params.flags >> 24);
    const auto cpuNumber = procMask == 0 ? 0 : 7 - std::countl_zero(procMask);

    GuestThreadContext ctx(cpuNumber);
    ctx.ppcContext.r3.u64 = params.value;

    // DEBUG: Log the function address and calculation details
    fprintf(stderr, "[DEBUG] FindFunction called with guest=0x%08X\n", params.function);
    fprintf(stderr, "[DEBUG] PPC_CODE_BASE=0x%08X PPC_IMAGE_SIZE=0x%08X\n", PPC_CODE_BASE, PPC_IMAGE_SIZE);
    fprintf(stderr, "[DEBUG] base=%p\n", g_memory.base);

    uint32_t offset_from_code_base = params.function - PPC_CODE_BASE;
    fprintf(stderr, "[DEBUG] offset_from_code_base=0x%08X (%u)\n", offset_from_code_base, offset_from_code_base);

    uint64_t table_offset = uint64_t(offset_from_code_base) * sizeof(PPCFunc*);
    fprintf(stderr, "[DEBUG] table_offset=0x%016llX (%llu)\n", table_offset, table_offset);

    void* func_table_ptr = (void*)(g_memory.base + PPC_IMAGE_SIZE + table_offset);
    fprintf(stderr, "[DEBUG] func_table_ptr=%p\n", func_table_ptr);
    fflush(stderr);

    if (auto entryFunc = g_memory.FindFunction(params.function))
    {
        KernelTraceHostOpF("HOST.TitleEntry.enter entry=%08X", params.function);
        entryFunc(ctx.ppcContext, g_memory.base);
        KernelTraceHostOpF("HOST.TitleEntry.exit entry=%08X", params.function);
    }
    else
    {
        fprintf(stderr, "[boot][error] Guest entry 0x%08X not found.\n", params.function);
#ifdef _WIN32
        MessageBoxA(nullptr, "Failed to locate guest entry point.", "Mw05 Recompiled", MB_ICONERROR);
#endif
        std::_Exit(1);
    }

    return ctx.ppcContext.r3.u32;
}

GuestThreadHandle* GuestThread::Start(const GuestThreadParams& params, uint32_t* threadId)
{
    auto hThread = CreateKernelObject<GuestThreadHandle>(params);

    if (threadId != nullptr)
    {
        *threadId = hThread->GetThreadId();
    }

    // Register thread id -> kernel handle mapping for wait by ID
    {
        std::lock_guard<std::mutex> lk(g_threadRegMutex);
        g_tidToHandle[hThread->GetThreadId()] = GetKernelHandle(hThread);
    }

    return hThread;
}

uint32_t GuestThread::GetCurrentThreadId()
{
#ifdef USE_PTHREAD
    return CalcThreadId(pthread_self());
#else
    return CalcThreadId(std::this_thread::get_id());
#endif
}

void GuestThread::SetLastError(uint32_t error)
{
    auto* thread = (char*)g_memory.Translate(GetPPCContext()->r13.u32);
    if (*(uint32_t*)(thread + 0x150))
    {
        // Program doesn't want errors
        return;
    }

    // TEB + 0x160 : Win32LastError
    *(uint32_t*)(thread + TEB_OFFSET + 0x160) = ByteSwap(error);
}

#ifdef _WIN32
void GuestThread::SetThreadName(uint32_t threadId, const char* name)
{
#pragma pack(push,8)
    const DWORD MS_VC_EXCEPTION = 0x406D1388;

    typedef struct tagTHREADNAME_INFO
    {
        DWORD dwType; // Must be 0x1000.
        LPCSTR szName; // Pointer to name (in user addr space).
        DWORD dwThreadID; // Thread ID (-1=caller thread).
        DWORD dwFlags; // Reserved for future use, must be zero.
    } THREADNAME_INFO;
#pragma pack(pop)

    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = name;
    info.dwThreadID = threadId;
    info.dwFlags = 0;

    __try
    {
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}
#endif

void SetThreadNameImpl(uint32_t a1, uint32_t threadId, uint32_t* name)
{
#ifdef _WIN32
    GuestThread::SetThreadName(threadId, (const char*)g_memory.Translate(ByteSwap(*name)));
#endif
}

int GetThreadPriorityImpl(GuestThreadHandle* hThread)
{
#ifdef _WIN32
    return GetThreadPriority(hThread == GetKernelObject(CURRENT_THREAD_HANDLE) ? GetCurrentThread() : hThread->thread.native_handle());
#else 
    return 0;
#endif
}

uint32_t SetThreadIdealProcessorImpl(GuestThreadHandle* hThread, uint32_t dwIdealProcessor)
{
    return 0;
}

GUEST_FUNCTION_HOOK(sub_82DFA2E8, SetThreadNameImpl);
GUEST_FUNCTION_HOOK(sub_82BD57A8, GetThreadPriorityImpl);
GUEST_FUNCTION_HOOK(sub_82BD5910, SetThreadIdealProcessorImpl);

GUEST_FUNCTION_STUB(sub_82BD58F8); // Some function that updates the TEB, don't really care since the field is not set
uint32_t GuestThread::LookupHandleByThreadId(uint32_t threadId)
{
    std::lock_guard<std::mutex> lk(g_threadRegMutex);
    auto it = g_tidToHandle.find(threadId);
    if (it != g_tidToHandle.end()) return it->second;
    return 0;
}
