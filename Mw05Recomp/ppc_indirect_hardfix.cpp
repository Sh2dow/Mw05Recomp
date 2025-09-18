// Minimal hardcoded redirects for frequent indirect-miss targets observed in logs.
// These complement the auto-generated redirects and ensure coverage for specific callsites.

#include <kernel/memory.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>


static void RegisterIndirectHardfixes() {
    // From log: [ppc][indirect-miss] target=0x82181688
    // Redirect to nearest function start at 0x821816F8
    g_memory.InsertFunction(0x82181688, sub_821816F8);

    // From log: target=0x821D6F80 → sub_821D6FF8
    g_memory.InsertFunction(0x821D6F80, sub_821D6FF8);

    // From log: target=0x821D64B0 → sub_821D6528
    g_memory.InsertFunction(0x821D64B0, sub_821D6528);
}

#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl ppc_indirect_hardfix_ctor();
    __declspec(allocate(".CRT$XCU")) void (*ppc_indirect_hardfix_ctor_)(void) = ppc_indirect_hardfix_ctor;
    static void __cdecl ppc_indirect_hardfix_ctor() { RegisterIndirectHardfixes(); }
#else
    __attribute__((constructor)) static void ppc_indirect_hardfix_ctor() { RegisterIndirectHardfixes(); }
#endif





