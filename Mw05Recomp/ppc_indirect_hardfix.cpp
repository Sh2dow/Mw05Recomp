// Minimal hardcoded redirects for frequent indirect-miss targets observed in logs.
// These complement the auto-generated redirects and ensure coverage for specific callsites.

#include <kernel/memory.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>
#include <kernel/init_manager.h>


// DISABLED (2025-11-02): These functions are no longer recompiled (only 7 functions in MW05.toml)
// The game will use kernel imports for these functions instead
static void RegisterIndirectHardfixes() {
    // All indirect hardfixes disabled - using kernel imports
    fprintf(stderr, "[MAIN] DISABLED indirect hardfixes - using kernel imports\n");
}

// Register with InitManager (priority 100 = default, runs after core systems)
REGISTER_INIT_CALLBACK("IndirectHardfixes", []() {
    RegisterIndirectHardfixes();
});





