// Midasm hooks for tracing main thread initialization to find where it gets stuck
#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <cstdio>

// Main thread entry - hook at ACTUAL function start (sub_8262E9A0)
void MainThreadEntry_sub_8262E9A0()
{
    static uint32_t s_call_count = 0;
    s_call_count++;
    fprintf(stderr, "[MAIN-THREAD-ENTRY] ACTUAL main thread entry function 0x8262E9A0 called (count=%u)\n", s_call_count);
    fflush(stderr);
}

// Main thread entry - hook at function start (this is actually _xstart, the CRT function)
void MainThreadEntry_sub_8262E9A8()
{
    static uint32_t s_call_count = 0;
    s_call_count++;
    fprintf(stderr, "[MAIN-THREAD-ENTRY] CRT _xstart function 0x8262E9A8 called (count=%u)\n", s_call_count);
    fflush(stderr);
}

// Main thread entry - old hook (keeping for compatibility)
void MainThreadEntryTrace(PPCRegister& r3, PPCRegister& r4, PPCRegister& r5)
{
    static bool first_call = true;
    if (first_call) {
        first_call = false;
        fprintf(stderr, "[MAIN-THREAD-ENTRY-OLD] Main thread entry 0x8262E9A8 called! r3=%08X r4=%08X r5=%08X\n",
                r3.u32, r4.u32, r5.u32);
        fflush(stderr);
    }
}

// Initialization function 1
void Init1_sub_82630068()
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init1 0x82630068 called\n");
    fflush(stderr);
}

// Initialization function 2
void Init2_sub_8262FDA8(PPCRegister& r3)
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init2 0x8262FDA8 called, r3=%08X\n", r3.u32);
    fflush(stderr);
}

// Initialization function 3
void Init3_sub_826BE558()
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init3 0x826BE558 called\n");
    fflush(stderr);
}

// Initialization function 4
void Init4_sub_8262FD30(PPCRegister& r3)
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init4 0x8262FD30 called, r3=%08X\n", r3.u32);
    fflush(stderr);
}

// Initialization function 5
void Init5_sub_8262FC50(PPCRegister& r3)
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init5 0x8262FC50 called, r3=%08X\n", r3.u32);
    fflush(stderr);
}

// Initialization function 6
void Init6_sub_8262E7F8(PPCRegister& r3)
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init6 0x8262E7F8 called, r3=%08X\n", r3.u32);
    fflush(stderr);
}

// Hook AFTER Init6 to see its return value
void Init6_Return(PPCRegister& r3)
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init6 RETURNED r3=%08X (%s)\n",
            r3.u32, r3.u32 ? "TRUE - will call Init7" : "FALSE - will skip Init7");
    fflush(stderr);
}

// NOTE: _xstart override removed - the recompiled version works correctly
// The main loop IS being called and IS running. The issue is that the game
// is not issuing draw commands yet, which is a different problem.

// Initialization function 7 (conditional)
void Init7_sub_826BDA60()
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init7 0x826BDA60 called (conditional)\n");
    fflush(stderr);
}

// Initialization function 8 (command line parsing)
void Init8_sub_8262FB78()
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init8 0x8262FB78 called (command line parsing)\n");
    fflush(stderr);
}

// Main thread wrapper (should be called after all initialization)
void MainThreadWrapper_sub_82441E80(PPCRegister& r3, PPCRegister& r4, PPCRegister& r5)
{
    fprintf(stderr, "[MAIN-THREAD-WRAPPER] Main thread wrapper 0x82441E80 called! r3=%08X r4=%08X r5=%08X\n",
            r3.u32, r4.u32, r5.u32);
    fflush(stderr);
}

// Main loop flag check (at 0x82441D38: lwz r9, dword_82A2CF40@l(r27))
void MainLoopFlagCheck(PPCRegister& r9, PPCRegister& r27)
{
    static uint32_t s_check_count = 0;
    s_check_count++;

    // Log first 10 checks and then every 100th check
    if (s_check_count <= 10 || s_check_count % 100 == 0) {
        fprintf(stderr, "[MAIN-LOOP-FLAG-CHECK] Check #%u: r9=%08X r27=%08X (about to load flag from 0x82A2CF40)\n",
                s_check_count, r9.u32, r27.u32);
        fflush(stderr);
    }
}

// Hooks INSIDE the wrapper function to trace execution
void Wrapper_AfterAlloc(PPCRegister& r3)
{
    fprintf(stderr, "[WRAPPER-TRACE] After allocation: r3=%08X (allocated pointer)\n", r3.u32);
    fflush(stderr);
}

void Wrapper_BeforeCall_sub_8261A5E8()
{
    fprintf(stderr, "[WRAPPER-TRACE] About to call sub_8261A5E8() - THIS IS WHERE IT MIGHT GET STUCK\n");
    fflush(stderr);
}

void Wrapper_AfterCall_sub_8261A5E8()
{
    fprintf(stderr, "[WRAPPER-TRACE] Returned from sub_8261A5E8() - function completed successfully\n");
    fflush(stderr);
}

void Wrapper_BeforeMainLoopCall()
{
    fprintf(stderr, "[WRAPPER-TRACE] About to call main loop sub_82441CF0(0) - wrapper initialization complete!\n");
    fprintf(stderr, "[CRITICAL] Main loop is an infinite loop - if you see this message but no logs from inside the loop, the loop is NOT executing!\n");
    fprintf(stderr, "[CRITICAL] Expected logs: MAIN-LOOP-FLAG-CHECK, sub_8262D9D0 (sleep), sub_8262DE60 (frame update)\n");
    fflush(stderr);
}

// Hooks for the allocation function to see if it's being called and returning
void Alloc_sub_8215CB08_Entry(PPCRegister& r3, PPCRegister& r4)
{
    static uint32_t s_call_count = 0;
    s_call_count++;

    // Log first 10 calls
    if (s_call_count <= 10) {
        fprintf(stderr, "[ALLOC-TRACE] Call #%u: sub_8215CB08(size=%u, r4=%08X) - ENTRY\n",
                s_call_count, r3.u32, r4.u32);
        fflush(stderr);
    }
}

void Alloc_sub_8215CB08_Exit(PPCRegister& r3)
{
    static uint32_t s_return_count = 0;
    s_return_count++;

    // Log first 10 returns
    if (s_return_count <= 10) {
        fprintf(stderr, "[ALLOC-TRACE] Return #%u: sub_8215CB08 returned r3=%08X - EXIT\n",
                s_return_count, r3.u32);
        fflush(stderr);
    }
}

// Test function to manually check loader state and try to trigger it
void MainLoopLoaderTest()
{
    static uint32_t s_call_count = 0;
    s_call_count++;

    // Only check on specific iterations
    if (s_call_count == 10 || s_call_count == 100 || s_call_count == 500) {
        fprintf(stderr, "[LOADER-TEST] Main loop iteration %u - checking loader state\n", s_call_count);
        fflush(stderr);

        // Loader callback structure is at 0x82A2B318
        uint32_t callback_param_addr = 0x82A2B318;
        uint32_t* callback_struct = reinterpret_cast<uint32_t*>(g_memory.base + callback_param_addr);

        uint32_t param1 = __builtin_bswap32(callback_struct[4]);
        uint32_t param2 = __builtin_bswap32(callback_struct[5]);
        uint32_t work_func = __builtin_bswap32(callback_struct[7]);

        fprintf(stderr, "[LOADER-TEST]   param1=0x%08X param2=0x%08X work_func=0x%08X\n",
                param1, param2, work_func);
        fflush(stderr);

        if (work_func == 0) {
            fprintf(stderr, "[LOADER-TEST]   NO WORK QUEUED - game is stuck waiting for loader job\n");
            fflush(stderr);
        } else {
            fprintf(stderr, "[LOADER-TEST]   WORK QUEUED - loader should be processing\n");
            fflush(stderr);
        }
    }
}

