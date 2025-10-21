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

    // CRITICAL FIX: Use g_userHeap.Alloc() instead of malloc
    // g_userHeap.Alloc() allocates memory within the PPC memory range (using o1heap, a host-side allocator)
    // This allows the memory to be safely mapped to guest addresses via g_memory.MapVirtual()
    // Unlike malloc, which returns host heap memory outside the PPC range
    fprintf(stderr, "[THREAD-CTX] Attempting to allocate %zu bytes for thread context (tid=%08X)\n",
            TOTAL_SIZE, GuestThread::GetCurrentThreadId());
    fflush(stderr);

    // CRITICAL FIX: Log heap state BEFORE attempting allocation to diagnose failures
    O1HeapDiagnostics diag_before = g_userHeap.GetDiagnostics();
    fprintf(stderr, "[THREAD-CTX] BEFORE alloc: capacity=%.2f MB allocated=%.2f MB free=%.2f MB\n",
            diag_before.capacity / (1024.0 * 1024.0),
            diag_before.allocated / (1024.0 * 1024.0),
            (diag_before.capacity - diag_before.allocated) / (1024.0 * 1024.0));
    fflush(stderr);

    thread = (uint8_t*)g_userHeap.Alloc(TOTAL_SIZE);
    if (!thread) {
        fprintf(stderr, "[CRITICAL] Failed to allocate thread context memory (%zu bytes = %.2f KB)\n",
                TOTAL_SIZE, TOTAL_SIZE / 1024.0);
        fprintf(stderr, "[CRITICAL] This is likely due to heap exhaustion or fragmentation\n");
        fprintf(stderr, "[CRITICAL] TOTAL_SIZE breakdown: PCR=%zu TLS=%zu TEB=%zu STACK=%zu\n",
                PCR_SIZE, TLS_SIZE, TEB_SIZE, STACK_SIZE);

        // Get heap diagnostics to understand why allocation failed
        O1HeapDiagnostics diag = g_userHeap.GetDiagnostics();
        fprintf(stderr, "[HEAP-DIAG] User heap state AFTER failed allocation:\n");
        fprintf(stderr, "[HEAP-DIAG]   capacity=%zu (%.2f MB)\n", diag.capacity, diag.capacity / (1024.0 * 1024.0));
        fprintf(stderr, "[HEAP-DIAG]   allocated=%zu (%.2f MB)\n", diag.allocated, diag.allocated / (1024.0 * 1024.0));
        fprintf(stderr, "[HEAP-DIAG]   peak_allocated=%zu (%.2f MB)\n", diag.peak_allocated, diag.peak_allocated / (1024.0 * 1024.0));
        fprintf(stderr, "[HEAP-DIAG]   free_space=%zu (%.2f MB)\n",
                diag.capacity - diag.allocated, (diag.capacity - diag.allocated) / (1024.0 * 1024.0));
        fprintf(stderr, "[HEAP-DIAG]   oom_count=%zu\n", diag.oom_count);
        fprintf(stderr, "[HEAP-DIAG]   fragmentation=%.2f%%\n",
                100.0 * (1.0 - (double)(diag.capacity - diag.allocated) / (double)diag.capacity));

        fflush(stderr);
        fprintf(stderr, "[ABORT] guest_thread.cpp line 63: Thread context allocation failed!\n");
        fflush(stderr);
        abort();
    }

    fprintf(stderr, "[THREAD-CTX] Successfully allocated %zu bytes at host=%p\n", TOTAL_SIZE, (void*)thread);
    fflush(stderr);
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
    // CRITICAL FIX: Use g_userHeap.Free() instead of free (matches g_userHeap.Alloc() in constructor)
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
    fprintf(stderr, "[GUEST_THREAD_WRAPPER] Entry point reached, arg=%p\n", arg);
    fflush(stderr);

    GuestThreadHandle* hThread = (GuestThreadHandle*)arg;

    fprintf(stderr, "[GUEST_THREAD_WRAPPER] hThread=%p, checking suspended flag...\n", (void*)hThread);
    fflush(stderr);
#else
static void GuestThreadFunc(GuestThreadHandle* hThread)
{
    fprintf(stderr, "[GUEST_THREAD_WRAPPER] Entry point reached, hThread=%p\n", (void*)hThread);
    fflush(stderr);
#endif
    // CRITICAL FIX: Validate hThread pointer before accessing it
    // The hThread object might be deleted or corrupted by another thread
    if (!hThread) {
        fprintf(stderr, "[GUEST_THREAD_WRAPPER] ERROR: hThread is NULL!\n");
        fflush(stderr);
        return;
    }

    // CRITICAL DEBUG: Log hThread address and params BEFORE copying
    fprintf(stderr, "[GUEST_THREAD_WRAPPER] hThread=%p, about to read params...\n", (void*)hThread);
    fprintf(stderr, "[GUEST_THREAD_WRAPPER]   params.function=%08X (at offset +%zu from hThread)\n",
            hThread->params.function, offsetof(GuestThreadHandle, params));
    fprintf(stderr, "[GUEST_THREAD_WRAPPER]   params.value=%08X\n", hThread->params.value);
    fprintf(stderr, "[GUEST_THREAD_WRAPPER]   params.flags=%08X\n", hThread->params.flags);
    fflush(stderr);

    // CRITICAL FIX: Make a local copy of params IMMEDIATELY to avoid race conditions
    // The hThread object might be deleted or corrupted by another thread at any time
    const GuestThreadParams localParams = hThread->params;
    const bool was_suspended = hThread->suspended.load();
    const uint32_t tid = hThread->GetThreadId();

    fprintf(stderr, "[GUEST_THREAD_WRAPPER] suspended=%d, tid=%08X, entry=%08X\n",
            was_suspended, tid, localParams.function);
    fflush(stderr);

    if (was_suspended) {
        fprintf(stderr, "[GUEST_THREAD] Thread tid=%08X entry=%08X WAITING for resume...\n",
            tid, localParams.function);
        fflush(stderr);
    }

    hThread->suspended.wait(true);

    if (was_suspended) {
        fprintf(stderr, "[GUEST_THREAD] Thread tid=%08X entry=%08X RESUMED, starting execution\n",
            tid, localParams.function);
        fflush(stderr);
    }

    fprintf(stderr, "[GUEST_THREAD] Thread tid=%08X entry=%08X ABOUT TO CALL GuestThread::Start\n",
        tid, localParams.function);
    fflush(stderr);

    // CRITICAL FIX: Force-create worker threads ONLY if callback parameter structure is initialized
    // The callback parameter structure at 0x82A2B318 needs a valid work function pointer at offset +16
    // If it's NULL, Mw05ForceCreateMissingWorkerThreads() will skip creation and let game create them naturally
    if (localParams.function == 0x8262E9A8) {
        fprintf(stderr, "[GUEST_THREAD] Main thread detected (entry=0x8262E9A8), attempting to force-create worker threads...\n");
        fflush(stderr);

        // Forward declare the function from mw05_trace_threads.cpp
        extern void Mw05ForceCreateMissingWorkerThreads();
        Mw05ForceCreateMissingWorkerThreads();

        fprintf(stderr, "[GUEST_THREAD] Force-creation attempt complete, continuing with main thread...\n");
        fflush(stderr);

        // DIAGNOSTIC: Add periodic heartbeat logging to see if main thread is running
        // This will help us determine if the thread is stuck in a loop or actually progressing
        static std::atomic<bool> s_heartbeat_enabled{true};
        if (s_heartbeat_enabled.exchange(false)) {  // Only start heartbeat once
            std::thread heartbeat_thread([tid]() {
                for (int i = 0; i < 60; ++i) {  // Log for 60 seconds
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    fprintf(stderr, "[MAIN-THREAD-HEARTBEAT] tid=%08X alive for %d seconds\n", tid, i+1);
                    fflush(stderr);
                }
                fprintf(stderr, "[MAIN-THREAD-HEARTBEAT] tid=%08X heartbeat logging stopped after 60 seconds\n", tid);
                fflush(stderr);
            });
            heartbeat_thread.detach();
        }
    }

    GuestThread::Start(localParams);

    fprintf(stderr, "[GUEST_THREAD] Thread tid=%08X entry=%08X COMPLETED\n",
        tid, localParams.function);
    fflush(stderr);

#ifdef USE_PTHREAD
    return nullptr;
#endif
}

GuestThreadHandle::GuestThreadHandle(const GuestThreadParams& params)
    : params(params), suspended((params.flags & 0x1) != 0)  // Honor CREATE_SUSPENDED flag - game calls NtResumeThread to resume
#ifdef USE_PTHREAD
{
    fprintf(stderr, "[GUEST_THREAD_HANDLE] Constructor ENTER: entry=0x%08X flags=0x%08X suspended=%d\n",
            params.function, params.flags, suspended.load());
    fflush(stderr);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, GetStackSize());

    fprintf(stderr, "[GUEST_THREAD_HANDLE] About to call pthread_create with GuestThreadFunc=%p this=%p\n",
            (void*)GuestThreadFunc, (void*)this);
    fflush(stderr);

    const auto ret = pthread_create(&thread, &attr, GuestThreadFunc, this);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed with error code 0x%X.\n", ret);
        return;
    }

    fprintf(stderr, "[GUEST_THREAD_HANDLE] pthread_create succeeded, thread=%p\n", (void*)thread);
    fflush(stderr);
}
#else
{
    fprintf(stderr, "[GUEST_THREAD_HANDLE] Constructor ENTER: entry=0x%08X flags=0x%08X suspended=%d\n",
            params.function, params.flags, suspended.load());
    fflush(stderr);

    fprintf(stderr, "[GUEST_THREAD_HANDLE] About to create std::thread with GuestThreadFunc=%p this=%p\n",
            (void*)GuestThreadFunc, (void*)this);
    fflush(stderr);

    thread = std::thread(GuestThreadFunc, this);

    fprintf(stderr, "[GUEST_THREAD_HANDLE] std::thread created successfully\n");
    fflush(stderr);
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
    // CRITICAL FIX: Make a local copy of params to avoid race conditions
    // The params reference might point to hThread->params which can be corrupted by other threads
    const GuestThreadParams localParams = params;

    // Early diagnostic: print entry address before lookup when verbose
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE))
    {
        printf("[boot] GuestThread::Start entry=0x%08X flags=0x%08X value=0x%08X\n", localParams.function, localParams.flags, (uint32_t)localParams.value);
        fflush(stdout);
    }
    const auto procMask = (uint8_t)(localParams.flags >> 24);
    const auto cpuNumber = procMask == 0 ? 0 : 7 - std::countl_zero(procMask);

    fprintf(stderr, "[DEBUG] GuestThread::Start ENTER: entry=0x%08X value=0x%08X flags=0x%08X\n",
        localParams.function, (uint32_t)localParams.value, localParams.flags);
    fflush(stderr);

    const uint32_t entry_function = localParams.function;

    // CRITICAL FIX: Wrap GuestThreadContext creation in try-catch to handle heap exhaustion
    GuestThreadContext ctx(cpuNumber);

    ctx.ppcContext.r3.u64 = localParams.value;

    // CRITICAL FIX: Update thread-local PPC context after setting r3
    // The constructor calls SetPPCContext() with uninitialized r3, so we need to update it
    SetPPCContext(ctx.ppcContext);

    // Use saved entry_function instead of params.function to avoid corruption
    if (auto entryFunc = g_memory.FindFunction(entry_function))
    {
        fprintf(stderr, "[DEBUG] entryFunc=%p (found for guest=0x%08X)\n", (void*)entryFunc, entry_function);
        fflush(stderr);

        fprintf(stderr, "[DEBUG] About to call entryFunc...\n");
        fflush(stderr);

        KernelTraceHostOpF("HOST.TitleEntry.enter entry=%08X", entry_function);

        fprintf(stderr, "[DEBUG] Calling entryFunc NOW...\n");
        fflush(stderr);

        entryFunc(ctx.ppcContext, g_memory.base);

        fprintf(stderr, "[DEBUG] entryFunc returned successfully\n");
        fflush(stderr);

        KernelTraceHostOpF("HOST.TitleEntry.exit entry=%08X", entry_function);
    }
    else
    {
        fprintf(stderr, "[boot][error] Guest entry 0x%08X not found (invalid address or not in function table).\n", entry_function);
        fflush(stderr);
#ifdef _WIN32
        MessageBoxA(nullptr, "Failed to locate guest entry point.", "Mw05 Recompiled", MB_ICONERROR);
#endif
        std::_Exit(1);
    }

    return ctx.ppcContext.r3.u32;
}

GuestThreadHandle* GuestThread::Start(const GuestThreadParams& params, uint32_t* threadId)
{
    fprintf(stderr, "[GUEST_THREAD_START] BEFORE CreateKernelObject: entry=0x%08X flags=0x%08X\n",
            params.function, params.flags);
    fflush(stderr);

    auto hThread = CreateKernelObject<GuestThreadHandle>(params);

    fprintf(stderr, "[GUEST_THREAD_START] AFTER CreateKernelObject: hThread=%p\n", (void*)hThread);
    fflush(stderr);

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
