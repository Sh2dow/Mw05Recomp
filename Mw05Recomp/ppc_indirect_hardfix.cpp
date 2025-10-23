// Minimal hardcoded redirects for frequent indirect-miss targets observed in logs.
// These complement the auto-generated redirects and ensure coverage for specific callsites.

#include <kernel/memory.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>
#include <kernel/init_manager.h>


static void RegisterIndirectHardfixes() {
    // From log: [ppc][indirect-miss] target=0x82181688
    // Redirect to nearest function start at 0x821816F8
    g_memory.InsertFunction(0x82181688, sub_821816F8);

    // From log: target=0x821D6F80 → sub_821D6FF8
    g_memory.InsertFunction(0x821D6F80, sub_821D6FF8);

    // From log: target=0x821D64B0 → sub_821D6528
    g_memory.InsertFunction(0x821D64B0, sub_821D6528);
}

// Register with InitManager (priority 100 = default, runs after core systems)
REGISTER_INIT_CALLBACK("IndirectHardfixes", []() {
    RegisterIndirectHardfixes();
});





