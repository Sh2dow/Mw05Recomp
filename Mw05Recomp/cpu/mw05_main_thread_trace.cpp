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

// Initialization function 5 - FUNCTION POINTER TABLE ITERATOR
// This function iterates through a table of function pointers and calls each one
// Table 1: 0x828DF0FC to 0x828DF108 (2 functions)
// Table 2: 0x828D0010 to 0x828DF0F8 (15,418 functions - C++ static constructors!)
// One of these functions is stuck and never returns!

// OVERRIDE Init5 to add logging for each function call
PPC_FUNC_IMPL(__imp__sub_8262FC50);
PPC_FUNC(sub_8262FC50)
{
    fprintf(stderr, "[INIT5] START - will iterate through function pointer tables\n");
    fprintf(stderr, "[INIT5]   Table 1: 0x828DF0FC-0x828DF108 (2 functions)\n");
    fprintf(stderr, "[INIT5]   Table 2: 0x828D0010-0x828DF0F8 (15,418 C++ static constructors!)\n");
    fflush(stderr);

    // First function pointer (off_828E14F8)
    uint32_t first_func_ptr_addr = 0x828E14F8;
    uint32_t first_func = *(uint32_t*)(base + first_func_ptr_addr);
    if (first_func != 0) {
        fprintf(stderr, "[INIT5] Calling first function at 0x%08X\n", first_func);
        fflush(stderr);
        PPC_CALL_INDIRECT_FUNC(first_func);
        fprintf(stderr, "[INIT5] First function returned\n");
        fflush(stderr);
    }

    // Table 1: 0x828DF0FC to 0x828DF108
    uint32_t table1_start = 0x828DF0FC;
    uint32_t table1_end = 0x828DF108;
    uint32_t result = 0;

    fprintf(stderr, "[INIT5] Processing Table 1 (0x828DF0FC-0x828DF108)\n");
    fflush(stderr);

    for (uint32_t addr = table1_start; addr < table1_end; addr += 4) {
        if (result != 0) break;

        uint32_t func_ptr = *(uint32_t*)(base + addr);
        if (func_ptr != 0) {
            fprintf(stderr, "[INIT5] Table1[0x%08X] = 0x%08X - calling...\n", addr, func_ptr);
            fflush(stderr);

            ctx.lr = 0x8262FCBC;
            PPC_CALL_INDIRECT_FUNC(func_ptr);
            result = ctx.r3.u32;

            fprintf(stderr, "[INIT5] Table1[0x%08X] returned r3=%08X\n", addr, result);
            fflush(stderr);
        }
    }

    if (result != 0) {
        fprintf(stderr, "[INIT5] Table 1 returned non-zero (%08X), exiting early\n", result);
        fflush(stderr);
        ctx.r3.u32 = result;
        return;
    }

    // Table 2: 0x828D0010 to 0x828DF0F8 (15,418 C++ static constructors!)
    uint32_t table2_start = 0x828D0010;
    uint32_t table2_end = 0x828DF0F8;

    fprintf(stderr, "[INIT5] Processing Table 2 (0x828D0010-0x828DF0F8) - 15,418 constructors!\n");
    fprintf(stderr, "[INIT5] Will log every 100th constructor to avoid spam...\n");
    fflush(stderr);

    uint32_t count = 0;
    for (uint32_t addr = table2_start; addr < table2_end; addr += 4) {
        uint32_t func_ptr = *(uint32_t*)(base + addr);
        if (func_ptr != 0 && func_ptr != 0xFFFFFFFF) {
            count++;

            // Log every 100th constructor to avoid spam
            if (count % 100 == 0) {
                fprintf(stderr, "[INIT5] Table2[%u/15418] addr=0x%08X func=0x%08X - calling...\n",
                        count, addr, func_ptr);
                fflush(stderr);
            }

            ctx.lr = 0x8262FD08;
            PPC_CALL_INDIRECT_FUNC(func_ptr);

            if (count % 100 == 0) {
                fprintf(stderr, "[INIT5] Table2[%u/15418] returned\n", count);
                fflush(stderr);
            }
        }
    }

    fprintf(stderr, "[INIT5] COMPLETE - processed %u constructors, returning 0\n", count);
    fflush(stderr);

    ctx.r3.u32 = 0;
}

// Initialization function 6 - REGION/PRIVILEGE CHECK
// This function checks Xbox executable privileges and config settings (region, language)
// If it returns 1 (true), the game calls sub_826BDA60 (XamLoaderTerminateTitle) and exits
// If it returns 0 (false), the game continues to sub_82441E80 (main game function)
//
// ROOT CAUSE FIXED: XexCheckExecutablePrivilege now returns 0 for privilege 0xA
// This makes the region check fail and return 0, so game continues to main loop
void Init6_sub_8262E7F8(PPCRegister& r3)
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init6 0x8262E7F8 called, r3=%08X\n", r3.u32);
    fflush(stderr);
}

// Hook AFTER Init6 to see its return value
void Init6_Return(PPCRegister& r3)
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init6 RETURNED r3=%08X (%s)\n",
            r3.u32, r3.u32 ? "FAIL - will terminate" : "PASS - will continue");
    fflush(stderr);
}

// Initialization function 7 (conditional) - TERMINATION FUNCTION
// This function calls XamLoaderTerminateTitle to exit the game
// It should NEVER be called if our region check fix is working
void Init7_sub_826BDA60()
{
    fprintf(stderr, "[MAIN-THREAD-INIT] Init7 0x826BDA60 called (TERMINATION FUNCTION - SHOULD NOT BE CALLED!)\n");
    fprintf(stderr, "[ERROR] Region check fix failed! Game is terminating!\n");
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

