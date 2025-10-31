// Force-start the loader system by calling the loader dispatcher directly
// This is a TEMPORARY FIX to test if the loader system works

#include <api/memory.h>
#include <api/ppc.h>
#include <kernel/trace.h>
#include <cstdio>

// Read environment variable helper
static bool ReadEnvBool(const char* name, bool defaultValue = false) {
    const char* val = std::getenv(name);
    if (!val) return defaultValue;
    return (strcmp(val, "1") == 0 || strcmp(val, "true") == 0 || strcmp(val, "TRUE") == 0);
}

// Force-start the loader by calling a loader function directly
extern "C" void ForceStartLoader() {
    static bool s_started = false;
    static const bool s_enabled = ReadEnvBool("MW05_FORCE_START_LOADER", false);

    if (!s_enabled || s_started) {
        return;
    }

    s_started = true;

    fprintf(stderr, "[FORCE_START_LOADER] Calling loader dispatcher to start file loading...\n");
    fflush(stderr);

    // Try calling sub_8215CB08 which is the main initialization function
    // This might trigger the loader to start
    uint32_t init_func_addr = 0x8215CB08;
    PPCFunc* init_func = g_memory.FindFunction(init_func_addr);

    if (init_func) {
        fprintf(stderr, "[FORCE_START_LOADER] Found init function at 0x%08X, calling it...\n", init_func_addr);
        fflush(stderr);

        PPCContext ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.r3.u32 = 0;  // param

        init_func(ctx, g_memory.GetBase());

        fprintf(stderr, "[FORCE_START_LOADER] Init function returned\n");
        fflush(stderr);
    } else {
        fprintf(stderr, "[FORCE_START_LOADER] Init function NOT found!\n");
        fflush(stderr);
    }
}

