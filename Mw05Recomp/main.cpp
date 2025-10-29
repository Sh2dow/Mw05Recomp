#include <stdafx.h>
#ifdef __x86_64__
#include <cpuid.h>
#endif
#include <cpu/guest_thread.h>
#include <gpu/video.h>
#include <kernel/function.h>
#include <kernel/memory.h>
#include <kernel/heap.h>
#include <kernel/xam.h>
#include <kernel/io/file_system.h>
#include <kernel/init_manager.h>
#include <file.h>
#include <xex.h>
#include <apu/audio.h>
#include <hid/hid.h>
#include <user/config.h>
#include <user/paths.h>
#include <user/persistent_storage_manager.h>
#include <user/registry.h>
#include <kernel/xdbf.h>
#if MW05_ENABLE_UNLEASHED
#include <install/installer.h>
#include <install/update_checker.h>
#endif
#include <os/logger.h>
#include <os/process.h>
#include <os/registry.h>
#include <ui/game_window.h>
#if MW05_ENABLE_UNLEASHED
#include <ui/installer_wizard.h>
#include <mod/mod_loader.h>
#endif
#include <preload_executable.h>
#include <kernel/trace.h>

#include <ppc/ppc_context.h>

#include <cstdlib>
#include <csignal>
#include <fstream>
#include <unordered_map>

// Floating point exception masking
#ifdef _WIN32
#include <float.h>
#else
#include <fenv.h>
#endif

// Forward declarations for kernel functions
extern uint32_t KeTlsAlloc();

// Ordinal-to-name mappings for Xbox kernel exports (defined in XenonUtils/xex.cpp)
extern std::unordered_map<size_t, const char*> XamExports;
extern std::unordered_map<size_t, const char*> XboxKernelExports;

// Forward declare all __imp__ functions we need
// These are defined in kernel/imports.cpp via GUEST_FUNCTION_HOOK
PPC_EXTERN_FUNC(__imp__VdInitializeEngines);
PPC_EXTERN_FUNC(__imp__VdShutdownEngines);
PPC_EXTERN_FUNC(__imp__VdSetGraphicsInterruptCallback);
// ... (we'll need to add more as we discover which ones are actually used)


// --- MW'05 specific tiny PPC shims discovered via traces/IDA ---
// 0x8243B618: clears two 32-bit words at r3 and returns (used as default callback)
PPC_FUNC(sub_8243B618)
{
    uint8_t* p = static_cast<uint8_t*>(g_memory.Translate(ctx.r3.u32));
    if (p)
    {
        *reinterpret_cast<uint32_t*>(p + 0) = 0;
        *reinterpret_cast<uint32_t*>(p + 4) = 0;
    }
}

static void MwSetEnv(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v ? v : "");
#else
    if (v) setenv(k, v, 1); else unsetenv(k);
#endif
}

static void MwSetEnvDefault(const char* k, const char* v) {
    const char* cur = std::getenv(k);
    if (cur && *cur) return; // respect caller-provided env
    MwSetEnv(k, v);
}

static void MwApplyDebugProfile() {
    MwSetEnvDefault("MW05_HOST_TRACE_FILE",              "mw05_host_trace.log");
    MwSetEnvDefault("MW05_HOST_TRACE_IMPORTS",           "1");
    MwSetEnvDefault("MW05_HOST_TRACE_HOSTOPS",           "1");
    MwSetEnvDefault("MW05_TRACE_KERNEL",                 "1");
    MwSetEnvDefault("MW05_STREAM_BRIDGE",                "1");
    MwSetEnvDefault("MW05_STREAM_ANY_LR",                "1");
    MwSetEnvDefault("MW05_STREAM_ACK_NO_PATH",           "0");
    // MW05_UNBLOCK_MAIN disabled by default - let game run naturally
    // MwSetEnvDefault("MW05_UNBLOCK_MAIN",                 "1");
    // CRITICAL: Enable VD initialization to allow game to progress to file loading
    MwSetEnvDefault("MW05_FORCE_VD_INIT",                "1");
    // DISABLED: Force-initialization causes KeBugCheckEx (0xF4) - structure must be initialized naturally
    // The callback parameter structure at 0x82A2B318 is dynamically allocated/initialized by game code
    // Need to find and call the initialization function instead of force-initializing
    // MwSetEnvDefault("MW05_FORCE_INIT_CALLBACK_PARAM",    "1");
    MwSetEnvDefault("MW05_PM4_TRACE",                    "1");
    MwSetEnvDefault("MW05_PM4_SCAN_ALL",                 "1");
    MwSetEnvDefault("MW05_PM4_ARM_RING_SCRATCH",         "1");
    MwSetEnvDefault("MW05_PM4_SCAN_SYSBUF",              "1");
    MwSetEnvDefault("MW05_PM4_SYSBUF_DUMP_ON_GET",       "1");
    MwSetEnvDefault("MW05_ALLOW_FLAG_CLEAR_AFTER_MS",    "300000");
    MwSetEnvDefault("MW05_UNBLOCK_LOG_MS",               "2000");
    MwSetEnvDefault("MW05_UNBLOCK_LOG_MAX",              "12");
    // Additional debug defaults to surface MW05 PM4/micro-IB behavior and guarded draws
    MwSetEnvDefault("MW05_PM4_APPLY_STATE",              "1");
    MwSetEnvDefault("MW05_PM4_EMIT_DRAWS",               "1");
    MwSetEnvDefault("MW05_PM4_SCAN_AFTER_BUILDER",       "1");
    MwSetEnvDefault("MW05_FORCE_MICROIB",                 "1");
    MwSetEnvDefault("MW05_PM4_SYSBUF_WATCH",             "1");
    MwSetEnvDefault("MW05_PM4_SYSBUF_TO_RING",           "1");
    MwSetEnvDefault("MW05_FORCE_ACK_WAIT",               "1");

    // Try kicking the PM4 builder around main loop/present hot spots
    MwSetEnvDefault("MW05_LOOP_TRY_PM4_PRE",             "1");
    MwSetEnvDefault("MW05_LOOP_TRY_PM4",                 "1");
    MwSetEnvDefault("MW05_INNER_TRY_PM4",                "1");
    MwSetEnvDefault("MW05_PRES_TRY_PM4",                 "1");
    // Keep deep paths optional (can be enabled manually if needed)
    MwSetEnvDefault("MW05_LOOP_TRY_PM4_DEEP",            "0");
    MwSetEnvDefault("MW05_INNER_TRY_PM4_DEEP",           "0");
    MwSetEnvDefault("MW05_PRES_TRY_PM4_DEEP",            "0");

    // Scanning aggressiveness
    MwSetEnvDefault("MW05_PM4_EAGER_SCAN",               "1");

}

PPC_EXTERN_FUNC(sub_82621640);
PPC_EXTERN_FUNC(sub_8284E658);
PPC_EXTERN_FUNC(sub_826346A8);
PPC_EXTERN_FUNC(sub_828508A8);  // Thread #1 entry point wrapper
PPC_EXTERN_FUNC(sub_82812ED0);
PPC_EXTERN_FUNC(sub_828134E0);
PPC_EXTERN_FUNC(sub_824411E0);

extern "C" void HostSchedulerWake(PPCContext& ctx, uint8_t* /*base*/); // declaration with exact signature
extern "C" bool Mw05HasGuestSwapped();
extern "C" void UnblockMainThreadEarly(); // Workaround to set flag before main thread starts


#ifdef _WIN32
#include <timeapi.h>
#include <windows.h>
#endif

#if defined(_WIN32) && defined(MW05_RECOMP_D3D12)
static std::array<std::string_view, 3> g_D3D12RequiredModules =
{
    "D3D12/D3D12Core.dll",
    "dxcompiler.dll",
    "dxil.dll"
};
#endif

// Optional installer for generated indirect redirects (defined by generator TU)
#if MW05_GEN_INDIRECT_REDIRECTS
#  if !defined(_MSC_VER)
extern "C" __attribute__((weak)) void MwInstallGeneratedIndirectRedirects();
#  else
extern "C" void MwInstallGeneratedIndirectRedirects();
#  endif
#endif

const size_t XMAIOBegin = 0x7FEA0000;
const size_t XMAIOEnd = XMAIOBegin + 0x0000FFFF;

Memory g_memory;
Heap g_userHeap;
XDBFWrapper g_xdbfWrapper;
std::unordered_map<uint16_t, GuestTexture*> g_xdbfTextureCache;

// Ensure early kernel variable exports (ExLoadedImageName/CommandLine) are initialized
extern void Mw05InitKernelVarExportsOnce();

void HostStartup()
{
#ifdef _WIN32
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
#endif

    hid::Init();
}

// Name inspired from nt's entry point
// Forward declare VdGetSystemCommandBuffer to ensure system command buffer is initialized early
extern "C" uint32_t VdGetSystemCommandBuffer(void* outCmdBufPtr, void* outValue);

void KiSystemStartup()
{
    KernelTraceHostOpF("HOST.KiSystemStartup ENTER");

    if (g_memory.base == nullptr)
    {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), Localise("System_MemoryAllocationFailed").c_str(), GameWindow::s_pWindow);
        std::_Exit(1);
    }

    // Initialize heap now that C runtime is fully ready
    g_userHeap.Init();
    g_userHeap.inGlobalConstruction = false;  // Mark that global construction is complete

    // Run all registered initialization callbacks in priority order
    // This replaces the old static constructor approach which caused crashes
    fprintf(stderr, "[MAIN] Running initialization callbacks...\n");
    fflush(stderr);
    InitManager::Instance().RunAll();
    fprintf(stderr, "[MAIN] Initialization complete! %zu callbacks registered.\n",
            InitManager::Instance().Count());
    fflush(stderr);

    // Publish ExLoadedImageName/ExLoadedCommandLine guest pointers (needs heap)
    Mw05InitKernelVarExportsOnce();

    // Initialize system command buffer early so it's available when the game starts
    VdGetSystemCommandBuffer(nullptr, nullptr);
    KernelTraceHostOpF("HOST.KiSystemStartup.SysBufInit");

    // Install any generated indirect redirects after memory init
    #if MW05_GEN_INDIRECT_REDIRECTS

        #if !defined(_MSC_VER)
            if (&MwInstallGeneratedIndirectRedirects)
                MwInstallGeneratedIndirectRedirects();
        #else
            MwInstallGeneratedIndirectRedirects();
        #endif
    #endif

    // NOTE: This flag setting is now controlled by MW05_UNBLOCK_MAIN environment variable
    // and handled in UnblockMainThreadEarly() in mw05_trace_threads.cpp
    // Removed unconditional flag setting to allow natural game behavior when MW05_UNBLOCK_MAIN=0
    KernelTraceHostOpF("HOST.Init.UnblockMainThread AFTER");

    const auto gameContent = XamMakeContent(XCONTENTTYPE_RESERVED, "Game");
    const auto updateContent = XamMakeContent(XCONTENTTYPE_RESERVED, "Update");
    const std::string gamePath = (const char*)(GetGamePath() / "game").u8string().c_str();
    const std::string updatePath = (const char*)(GetGamePath() / "update").u8string().c_str();
    XamRegisterContent(gameContent, gamePath);
    XamRegisterContent(updateContent, updatePath);

    const auto saveFilePath = GetSaveFilePath(true);
    bool saveFileExists = std::filesystem::exists(saveFilePath);

    if (!saveFileExists)
    {
        // Copy base save data to modded save as fallback.
        std::error_code ec;
        std::filesystem::create_directories(saveFilePath.parent_path(), ec);

        if (!ec)
        {
            std::filesystem::copy_file(GetSaveFilePath(false), saveFilePath, ec);
            saveFileExists = !ec;
        }
    }

    if (saveFileExists)
    {
        std::u8string savePathU8 = saveFilePath.parent_path().u8string();
        XamRegisterContent(XamMakeContent(XCONTENTTYPE_SAVEDATA, "SYS-DATA"), (const char*)(savePathU8.c_str()));
    }

    // CRITICAL FIX: Create user profile directory and dummy .gpd files
    // The game expects profile files to exist before it will load resources
    // Profile files are stored in the save directory (XCONTENTTYPE_SAVEDATA)
    // Based on Xenia log analysis: HostPathDevice::ResolvePath(\FFFE07D1.gpd) and (\454107D9.gpd)
    {
        const std::filesystem::path savePath = GetSavePath(true);
        std::error_code ec;
        std::filesystem::create_directories(savePath, ec);

        fprintf(stderr, "[BOOT] Creating user profile directory: %s\n", savePath.string().c_str());
        fflush(stderr);

        // Create dummy profile files that the game expects
        // These are the files Xenia creates: FFFE07D1.gpd and 454107D9.gpd
        const std::vector<std::string> profileFiles = {
            "FFFE07D1.gpd",  // User profile data
            "454107D9.gpd"   // Game-specific profile data (NFS Most Wanted title ID)
        };

        for (const auto& filename : profileFiles) {
            const std::filesystem::path profilePath = savePath / filename;
            if (!std::filesystem::exists(profilePath)) {
                // Create a minimal dummy .gpd file (just a header)
                std::ofstream file(profilePath, std::ios::binary);
                if (file.is_open()) {
                    // Write a minimal GPD header (16 bytes of zeros is enough for now)
                    const char header[16] = {0};
                    file.write(header, sizeof(header));
                    file.close();
                    fprintf(stderr, "[BOOT] Created dummy profile file: %s\n", filename.c_str());
                    fflush(stderr);
                } else {
                    fprintf(stderr, "[BOOT] WARNING: Failed to create profile file: %s\n", filename.c_str());
                    fflush(stderr);
                }
            } else {
                fprintf(stderr, "[BOOT] Profile file already exists: %s\n", filename.c_str());
                fflush(stderr);
            }
        }
    }

    // Mount game
    fprintf(stderr, "[MAIN-DEBUG] Before XamContentCreateEx for 'game'\n");
    fflush(stderr);
    KernelTraceHostOpF("HOST.KiSystemStartup calling XamContentCreateEx for 'game'");
    XamContentCreateEx(0, "game", &gameContent, OPEN_EXISTING, nullptr, nullptr, 0, 0, nullptr);
    fprintf(stderr, "[MAIN-DEBUG] After XamContentCreateEx for 'game'\n");
    fflush(stderr);

    fprintf(stderr, "[MAIN-DEBUG] Before XamContentCreateEx for 'update'\n");
    fflush(stderr);
    KernelTraceHostOpF("HOST.KiSystemStartup calling XamContentCreateEx for 'update'");

    // MW05_FIX: Try calling XamContentCreateEx for "update" - game might be waiting for this
    fprintf(stderr, "[MAIN-DEBUG] Calling XamContentCreateEx for 'update'\n");
    fflush(stderr);
    XamContentCreateEx(0, "update", &updateContent, OPEN_EXISTING, nullptr, nullptr, 0, 0, nullptr);

    fprintf(stderr, "[MAIN-DEBUG] After XamContentCreateEx for 'update'\n");
    fflush(stderr);

    // OS mounts game data to D:
    fprintf(stderr, "[MAIN-DEBUG] Before XamContentCreateEx for 'D'\n");
    fflush(stderr);
    KernelTraceHostOpF("HOST.KiSystemStartup calling XamContentCreateEx for 'D'");

    // MW05_FIX: Try calling XamContentCreateEx for "D" - game might be waiting for this
    fprintf(stderr, "[MAIN-DEBUG] Calling XamContentCreateEx for 'D'\n");
    fflush(stderr);
    XamContentCreateEx(0, "D", &gameContent, OPEN_EXISTING, nullptr, nullptr, 0, 0, nullptr);

    fprintf(stderr, "[MAIN-DEBUG] After XamContentCreateEx for 'D'\n");
    fflush(stderr);

    fprintf(stderr, "[MAIN-DEBUG] Before DLC directory iteration\n");
    fflush(stderr);
    std::error_code ec;
    for (auto& file : std::filesystem::directory_iterator(GetGamePath() / "dlc", ec))
    {
        if (file.is_directory())
        {
            std::u8string fileNameU8 = file.path().filename().u8string();
            std::u8string filePathU8 = file.path().u8string();
            XamRegisterContent(XamMakeContent(XCONTENTTYPE_DLC, (const char*)(fileNameU8.c_str())), (const char*)(filePathU8.c_str()));
        }
    }
    fprintf(stderr, "[MAIN-DEBUG] After DLC directory iteration\n");
    fflush(stderr);

    fprintf(stderr, "[MAIN-DEBUG] Before XAudioInitializeSystem\n");
    fflush(stderr);
    XAudioInitializeSystem();
    fprintf(stderr, "[MAIN-DEBUG] After XAudioInitializeSystem\n");
    fflush(stderr);

    // CRITICAL FIX: Start VBlank pump BEFORE guest thread starts
    // In Xenia, VBlank ticks start immediately after audio system init (before game module load)
    // The game waits for VBlank ticks to progress through initialization
    fprintf(stderr, "[MAIN-DEBUG] Before Mw05AutoVideoInitIfNeeded\n");
    fflush(stderr);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it for now.
    // KernelTraceHostOpF("HOST.KiSystemStartup starting VBlank pump");
    Mw05AutoVideoInitIfNeeded();  // Initialize video system (ring buffer, etc.)
    fprintf(stderr, "[MAIN-DEBUG] After Mw05AutoVideoInitIfNeeded\n");
    fflush(stderr);

    fprintf(stderr, "[MAIN-DEBUG] Before Mw05StartVblankPumpOnce\n");
    fflush(stderr);
    Mw05StartVblankPumpOnce();    // Start VBlank ticks
    fprintf(stderr, "[MAIN-DEBUG] After Mw05StartVblankPumpOnce\n");
    fflush(stderr);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.KiSystemStartup VBlank pump started");

    // CRITICAL FIX: Initialize the VD ISR flag that enables frame callbacks
    // The VD interrupt callback at sub_825979A8 checks this flag at 0x7FC86544
    // If set, it calls the frame callback that sets dword_82A2CF40 each frame
    // This is what keeps the main game loop running naturally
    {
        const uint32_t vd_isr_flag_ea = 0x7FC86544;
        uint32_t* vd_isr_flag_ptr = static_cast<uint32_t*>(g_memory.Translate(vd_isr_flag_ea));
        if (vd_isr_flag_ptr) {
            #if defined(_MSC_VER)
                *vd_isr_flag_ptr = _byteswap_ulong(1);  // Set flag (big-endian)
            #else
                *vd_isr_flag_ptr = __builtin_bswap32(1);  // Set flag (big-endian)
            #endif
            fprintf(stderr, "[INIT] Set VD ISR flag at 0x%08X to 1 (enables frame callbacks)\n", vd_isr_flag_ea);
            fflush(stderr);
            // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
            // KernelTraceHostOpF("HOST.Init.VdIsrFlag addr=%08X value=1", vd_isr_flag_ea);
        } else {
            fprintf(stderr, "[INIT] ERROR: Failed to translate VD ISR flag address 0x%08X\n", vd_isr_flag_ea);
            fflush(stderr);
        }
    }

    // CRITICAL FIX: Register the VD ISR callback that the game expects
    // The game should call VdSetGraphicsInterruptCallback itself, but it's stuck in a loop
    // waiting for the callback to be called. This is a chicken-and-egg problem.
    // Solution: Register the callback during initialization, before the game enters the main loop.
    {
        extern void VdSetGraphicsInterruptCallback(uint32_t callback_ea, uint32_t context_ea);
        const uint32_t vd_isr_callback_ea = 0x825979A8;  // sub_825979A8
        const uint32_t vd_isr_context_ea = 0x40007180;   // Graphics context (allocated earlier)

        fprintf(stderr, "[INIT] Registering VD ISR callback at 0x%08X with context 0x%08X\n",
                vd_isr_callback_ea, vd_isr_context_ea);
        fflush(stderr);

        VdSetGraphicsInterruptCallback(vd_isr_callback_ea, vd_isr_context_ea);

        fprintf(stderr, "[INIT] VD ISR callback registered successfully\n");
        fflush(stderr);
        // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
        // KernelTraceHostOpF("HOST.Init.VdIsrCallback cb=%08X ctx=%08X", vd_isr_callback_ea, vd_isr_context_ea);

        // CRITICAL FIX: Initialize the frame callback pointer in the GAME'S graphics context
        // The game uses a graphics context at 0x00061000 (static variable in XEX data section)
        // The VD ISR callback at sub_825979A8 checks context[3899] for a frame callback pointer
        // If set, it calls this function each frame to update the main loop flag at 0x82A2CF40
        // context[3899] = *(0x00061000 + 0x3CEC) = *(0x00064CEC)
        // We need to set this to point to a function that sets dword_82A2CF40
        // For now, we'll set the flag directly during initialization
        {
            const uint32_t game_gfx_context_ea = 0x00061000;  // Game's graphics context (static variable)
            const uint32_t frame_callback_ptr_ea = game_gfx_context_ea + 0x3CEC;  // context[3899]
            const uint32_t main_loop_flag_ea = 0x82A2CF40;

            // Set the main loop flag to 1 to unblock the main loop
            uint32_t* main_loop_flag_ptr = static_cast<uint32_t*>(g_memory.Translate(main_loop_flag_ea));
            if (main_loop_flag_ptr) {
                #if defined(_MSC_VER)
                    *main_loop_flag_ptr = _byteswap_ulong(1);  // Set flag (big-endian)
                #else
                    *main_loop_flag_ptr = __builtin_bswap32(1);  // Set flag (big-endian)
                #endif
                fprintf(stderr, "[INIT] Set main loop flag at 0x%08X to 1 (unblocks main loop)\n", main_loop_flag_ea);
                fflush(stderr);
                // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
                // KernelTraceHostOpF("HOST.Init.MainLoopFlag addr=%08X value=1", main_loop_flag_ea);
            } else {
                fprintf(stderr, "[INIT] ERROR: Failed to translate main loop flag address 0x%08X\n", main_loop_flag_ea);
                fflush(stderr);
            }

            // TODO: Find the real frame callback function and set it at frame_callback_ptr_ea
            // For now, the main loop flag is set once during initialization
            // The game might clear it and expect the VD ISR to set it again each frame
            // If that happens, we'll need to implement a proper frame callback
        }
    }

    // EXPERIMENTAL: Send notification that the game is waiting for
    // Send it from a background thread with a delay to ensure the game has created listeners
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));  // Wait 5 seconds for game to create listeners

        extern void XamNotifyEnqueueEvent(uint32_t dwId, uint32_t dwParam);

        // The game is polling for notification message ID 0x11 (17 decimal)
        // Listener areas = 0x2F (binary 00101111) = areas {0,1,2,3,5}
        // Notification format: (area << 16) | message_number (NOT area << 25!)
        // Try area 0 with message 0x11
        const uint32_t NOTIFICATION_AREA_0_MSG_0x11 = (0 << 16) | 0x11;

        fprintf(stderr, "[NOTIFICATION-THREAD] Sending notification area=0 msg=0x11 (dwId=%08X) param=0x00000001 (user 0 signed in)\n", NOTIFICATION_AREA_0_MSG_0x11);
        fflush(stderr);
        // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
        // KernelTraceHostOpF("HOST.NotificationThread sending notification area=0 msg=0x11 (dwId=%08X)", NOTIFICATION_AREA_0_MSG_0x11);
        // CRITICAL FIX: Parameter is user slot mask! For user 0 signed in, param = (1 << 0) = 1
        XamNotifyEnqueueEvent(NOTIFICATION_AREA_0_MSG_0x11, 1);

        fprintf(stderr, "[NOTIFICATION-THREAD] Notification sent\n");
        fflush(stderr);
        // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
        // KernelTraceHostOpF("HOST.NotificationThread notification sent");
    }).detach();
}

// Helper to get address of __imp__ function by name
// Returns nullptr if not found
extern "C" PPCFunc* GetImportFunctionByName(const char* name);
// Helper to get address of an imported variable by name (allocates storage on first use)
extern "C" uint32_t GetImportVariableGuestAddress(const char* name);


// Process XEX import table and patch with kernel function addresses
// This matches Xenia's behavior where imports are resolved before game execution
void ProcessImportTable(const uint8_t* xexData, uint32_t loadAddress)
{
    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.ProcessImportTable ENTER");
    fprintf(stderr, "[XEX] Processing import table...\n");
    fflush(stderr);

    // Assign guest addresses for imports starting after the game code
    // PPC_CODE_BASE=0x820E0000, PPC_CODE_SIZE=0x7E8DA0, so code ends at ~0x828C8DA0
    // We'll start imports at 0x828CA000 (aligned to 4KB boundary for safety)
    uint32_t nextImportAddress = 0x828CA000;

    // Get import libraries header
    // For XEX_HEADER_IMPORT_LIBRARIES (0x000103FF), getOptHeaderPtr returns moduleBytes + offset
    // because (0x000103FF & 0xFF) == 0xFF, which triggers the "else" case in getOptHeaderPtr
    const auto* importHeader = reinterpret_cast<const Xex2ImportHeader*>(
        getOptHeaderPtr(xexData, XEX_HEADER_IMPORT_LIBRARIES));

    if (!importHeader)
    {
        fprintf(stderr, "[XEX] No import table found (XEX_HEADER_IMPORT_LIBRARIES not present)\n");
        fflush(stderr);
        // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
        // KernelTraceHostOp("HOST.ProcessImportTable no_imports");
        return;
    }

    const uint32_t numLibraries = importHeader->numImports.get();
    fprintf(stderr, "[XEX] Import table: %u libraries, stringTableSize=%u\n",
            numLibraries, importHeader->sizeOfStringTable.get());
    fflush(stderr);

    // Build string table (library names are null-terminated and padded to 4-byte boundaries)
    // The library->name field is an INDEX into this array, not a byte offset
    const char* pStrTable = reinterpret_cast<const char*>(importHeader + 1);
    std::vector<const char*> stringTable;
    size_t paddedStringOffset = 0;
    for (uint32_t i = 0; i < numLibraries; i++)
    {
        stringTable.push_back(pStrTable + paddedStringOffset);

        // Calculate length and pad to next multiple of 4
        size_t len = strlen(stringTable.back()) + 1; // +1 for null terminator
        paddedStringOffset += ((len + 3) & ~3);
    }

    // Import libraries follow the string table
    const auto* library = reinterpret_cast<const Xex2ImportLibrary*>(
        reinterpret_cast<const uint8_t*>(importHeader) +
        sizeof(Xex2ImportHeader) +
        importHeader->sizeOfStringTable.get());

    uint32_t totalImportsPatched = 0;
    uint32_t totalImportsFailed = 0;

    // Process each library
    for (uint32_t libIdx = 0; libIdx < numLibraries; libIdx++)
    {
        const uint16_t nameIndex = library->name.get();
        const char* libraryName = (nameIndex < stringTable.size()) ? stringTable[nameIndex] : "<invalid>";
        const uint32_t numImports = library->numberOfImports.get();

        fprintf(stderr, "\n[XEX] Library #%u: '%s' (name_index=%u), version=%u.%u.%u.%u, %u imports\n",
                libIdx,
                libraryName,
                nameIndex,
                (library->version.get() >> 24) & 0xFF,
                (library->version.get() >> 16) & 0xFF,
                (library->version.get() >> 8) & 0xFF,
                library->version.get() & 0xFF,
                numImports);
        fflush(stderr);

        // Select the appropriate ordinal-to-name mapping for this library
        const std::unordered_map<size_t, const char*>* exportTable = nullptr;
        if (strcmp(libraryName, "xam.xex") == 0)
        {
            exportTable = &XamExports;
        }
        else if (strcmp(libraryName, "xboxkrnl.exe") == 0)
        {
            exportTable = &XboxKernelExports;
        }

        // Import descriptors follow the library header
        const auto* importDesc = reinterpret_cast<const Xex2ImportDescriptor*>(library + 1);

        // Process each import in this library
        for (uint32_t i = 0; i < numImports; i++)
        {
            // DEBUG: Log every 50 imports to track progress
            if (i % 50 == 0)
            {
                fprintf(stderr, "[XEX]   Processing import %u/%u...\n", i, numImports);
                fflush(stderr);
            }

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: About to get thunkAddr\n");
                fflush(stderr);
            }

            const uint32_t thunkAddr = importDesc[i].firstThunk.get();

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: thunkAddr=0x%08X, about to translate\n", thunkAddr);
                fflush(stderr);
            }

            // Get the thunk data from guest memory
            auto* thunkData = reinterpret_cast<Xex2ThunkData*>(g_memory.Translate(thunkAddr));

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: thunkData=%p\n", (void*)thunkData);
                fflush(stderr);
            }

            if (!thunkData)
            {
                fprintf(stderr, "[XEX]   Import %u: thunk address 0x%08X not in guest memory\n", i, thunkAddr);
                fflush(stderr);
                totalImportsFailed++;
                continue;
            }

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: About to get ordinal\n");
                fflush(stderr);
            }

            // Extract ordinal from thunk data
            const uint32_t ordinal = thunkData->ordinal.get();

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: ordinal=0x%08X\n", ordinal);
                fflush(stderr);
            }

            // CRITICAL FIX: The thunk data is in big-endian format in the XEX file.
            // The structure in big-endian memory is: [type:8][hint:8][ordinal:16]
            // We need to extract the fields from the BIG-ENDIAN representation, not the byte-swapped one.
            // Read the raw bytes directly:
            const uint8_t* rawBytes = reinterpret_cast<const uint8_t*>(thunkData);
            const uint8_t importType = rawBytes[0];  // Type is in byte 0 (big-endian)
            const uint8_t importHint = rawBytes[1];  // Hint is in byte 1 (big-endian)
            const uint16_t importOrdinal = (static_cast<uint16_t>(rawBytes[2]) << 8) | rawBytes[3];  // Ordinal is in bytes 2-3 (big-endian)

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: importType=%u importOrdinal=%u importHint=%u\n", importType, importOrdinal, importHint);
                fprintf(stderr, "[XEX-DEBUG]   Import 0: Raw thunk data bytes: %02X %02X %02X %02X\n",
                        rawBytes[0], rawBytes[1], rawBytes[2], rawBytes[3]);
                fflush(stderr);
            }

            // Look up function name from ordinal
            const char* functionName = nullptr;

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: About to lookup in exportTable (ptr=%p)\n", (void*)exportTable);
                fflush(stderr);
            }

            if (exportTable)
            {
                // DEBUG: Log first import in detail
                if (i == 0)
                {
                    fprintf(stderr, "[XEX-DEBUG]   Import 0: exportTable exists, calling find(%u)\n", importOrdinal);
                    fflush(stderr);
                }

                auto it = exportTable->find(importOrdinal);

                // DEBUG: Log first import in detail
                if (i == 0)
                {
                    fprintf(stderr, "[XEX-DEBUG]   Import 0: find() returned, checking if found\n");
                    fflush(stderr);
                }

                if (it != exportTable->end())
                {
                    functionName = it->second;
                }
            }

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: functionName=%s\n", functionName ? functionName : "(null)");
                fflush(stderr);
            }

            if (!functionName)
            {
                fprintf(stderr, "[XEX]   Import %u: ordinal=%u (0x%03X) type=%u thunk=0x%08X - NO NAME FOUND\n",
                        i, importOrdinal, importOrdinal, importType, thunkAddr);
                fflush(stderr);
                totalImportsFailed++;
                continue;
            }

            // CRITICAL FIX: In the XEX format, the type field appears to be 0 for ALL imports.
            // We'll treat ALL imports as functions for now.
            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: About to call GetImportFunctionByName(%s)\n", functionName);
                fflush(stderr);
            }

            // Get the address of the __imp__ function
            // Note: functionName already includes the "__imp__" prefix from the ordinal table
            PPCFunc* hostFunc = GetImportFunctionByName(functionName);

            // DEBUG: Log first import in detail
            if (i == 0)
            {
                fprintf(stderr, "[XEX-DEBUG]   Import 0: GetImportFunctionByName returned hostFunc=%p\n", (void*)hostFunc);
                fflush(stderr);
            }

            if (!hostFunc)
            {
                fprintf(stderr, "[XEX]   Import %u: %s (ordinal=%u) type=%u - NOT IMPLEMENTED\n",
                        i, functionName, importOrdinal, importType);
                fflush(stderr);
                totalImportsFailed++;
                continue;
            }

            // Assign a unique guest address for this import
            uint32_t importGuestAddr = nextImportAddress;
            nextImportAddress += 4; // Each import gets 4 bytes (enough for a function pointer)

            // Register the function at this guest address
            g_memory.InsertFunction(importGuestAddr, hostFunc);

            // Patch the thunk to point to this guest address
            // The thunk data is in big-endian format (be<uint32_t>)

            // DEBUG: Log before patch for VdSwap
            if (strcmp(functionName, "__imp__VdSwap") == 0) {
                const uint8_t* rawBefore = reinterpret_cast<const uint8_t*>(thunkData);
                fprintf(stderr, "[XEX-VDSWAP-DEBUG] BEFORE patch: thunk=0x%08X bytes=%02X %02X %02X %02X\n",
                        thunkAddr, rawBefore[0], rawBefore[1], rawBefore[2], rawBefore[3]);
                fflush(stderr);
            }

            thunkData->function = importGuestAddr;

            // DEBUG: Log after patch for VdSwap
            if (strcmp(functionName, "__imp__VdSwap") == 0) {
                const uint8_t* rawAfter = reinterpret_cast<const uint8_t*>(thunkData);
                fprintf(stderr, "[XEX-VDSWAP-DEBUG] AFTER patch: thunk=0x%08X bytes=%02X %02X %02X %02X (should be guest=0x%08X)\n",
                        thunkAddr, rawAfter[0], rawAfter[1], rawAfter[2], rawAfter[3], importGuestAddr);
                fflush(stderr);
            }

            fprintf(stderr, "[XEX]   Import %u: %s (ordinal=%u) type=%u thunk=0x%08X -> guest=0x%08X PATCHED\n",
                    i, functionName, importOrdinal, importType, thunkAddr, importGuestAddr);
            fflush(stderr);
            totalImportsPatched++;
        }

        // Move to next library (libraries are variable size)
        library = reinterpret_cast<const Xex2ImportLibrary*>(
            reinterpret_cast<const uint8_t*>(library) + library->size.get());
    }

    fprintf(stderr, "\n[XEX] Import table processing complete: %u patched, %u failed\n",
            totalImportsPatched, totalImportsFailed);
    fflush(stderr);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.ProcessImportTable DONE patched=%u failed=%u",
    //                    totalImportsPatched, totalImportsFailed);
}

uint32_t LdrLoadModule(const std::filesystem::path &path)
{
    auto loadResult = LoadFile(path);
    if (loadResult.empty())
    {
        // Print a helpful message and fail gracefully instead of asserting
        fprintf(stderr, "[boot][error] Failed to load module: %s\n", path.string().c_str());
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), ("Failed to load module:\n" + path.string()).c_str(), GameWindow::s_pWindow);
        return 0;
    }

    auto* header = reinterpret_cast<const Xex2Header*>(loadResult.data());
    auto* security = reinterpret_cast<const Xex2SecurityInfo*>(loadResult.data() + header->securityOffset.get());
    const auto* fileFormatInfo = reinterpret_cast<const Xex2OptFileFormatInfo*>(getOptHeaderPtr(loadResult.data(), XEX_HEADER_FILE_FORMAT_INFO));
    auto entry = *reinterpret_cast<const uint32_t*>(getOptHeaderPtr(loadResult.data(), XEX_HEADER_ENTRY_POINT));
    ByteSwapInplace(entry);

    auto srcData = loadResult.data() + header->headerSize.get();
    auto destData = reinterpret_cast<uint8_t*>(g_memory.Translate(security->loadAddress.get()));

    if (fileFormatInfo->compressionType.get() == XEX_COMPRESSION_NONE)
    {
        memcpy(destData, srcData, security->imageSize.get());
    }
    else if (fileFormatInfo->compressionType.get() == XEX_COMPRESSION_BASIC)
    {
        auto* blocks = reinterpret_cast<const Xex2FileBasicCompressionBlock*>(fileFormatInfo + 1);
        const size_t numBlocks = (fileFormatInfo->infoSize.get() / sizeof(Xex2FileBasicCompressionInfo)) - 1;

        for (size_t i = 0; i < numBlocks; i++)
        {
            memcpy(destData, srcData, blocks[i].dataSize.get());

            srcData += blocks[i].dataSize.get();
            destData += blocks[i].dataSize.get();

            memset(destData, 0, blocks[i].zeroSize.get());
            destData += blocks[i].zeroSize.get();
        }
    }
    else
    {
        assert(false && "Unknown compression type.");
    }

    // CRITICAL FIX: Process base relocations
    // The XEX contains offsets that need to be converted to absolute addresses
    // This is the ROOT CAUSE of crashes where r3 contains offsets (0x000BD6C0) instead of pointers (0x820BD6C0)
    auto* baseRefPtr = reinterpret_cast<const be<uint32_t>*>(getOptHeaderPtr(loadResult.data(), XEX_HEADER_BASE_REFERENCE));

    uint32_t baseRef = 0;
    uint32_t loadAddress = security->loadAddress.get();

    if (baseRefPtr != nullptr)
    {
        baseRef = baseRefPtr->get();
        fprintf(stderr, "[XEX] Base reference header found: baseRef=0x%08X\n", baseRef);
    }
    else
    {
        // CRITICAL FIX: If no base reference header, assume XEX was linked at 0x00000000
        // This is common for XEX files that don't have a base reference header
        // The static initializer table contains OFFSETS that need to be converted to ABSOLUTE ADDRESSES
        baseRef = 0x00000000;
        fprintf(stderr, "[XEX] No base reference header found - assuming baseRef=0x00000000\n");
    }

    // The base reference is the address the XEX was originally linked at
    // We need to apply relocations if the load address is different
    if (baseRef != loadAddress)
    {
        int32_t delta = static_cast<int32_t>(loadAddress) - static_cast<int32_t>(baseRef);
        fprintf(stderr, "[XEX] Base relocation: baseRef=0x%08X loadAddr=0x%08X delta=0x%08X\n",
                baseRef, loadAddress, delta);

        // Process PE base relocations from .reloc section
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(g_memory.Translate(loadAddress));
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS32*>(g_memory.Translate(loadAddress + dosHeader->e_lfanew));

        uint32_t relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        uint32_t relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (relocRva != 0 && relocSize != 0)
        {
            auto* relocBase = reinterpret_cast<uint8_t*>(g_memory.Translate(loadAddress + relocRva));
            auto* relocEnd = relocBase + relocSize;

            uint32_t relocCount = 0;
            while (relocBase < relocEnd)
            {
                auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocBase);
                if (block->SizeOfBlock == 0)
                    break;

                uint32_t numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                auto* entries = reinterpret_cast<uint16_t*>(block + 1);

                for (uint32_t i = 0; i < numEntries; i++)
                {
                    uint16_t entry = entries[i];
                    uint16_t type = entry >> 12;
                    uint16_t offset = entry & 0xFFF;

                    if (type == IMAGE_REL_BASED_HIGHLOW)  // 32-bit absolute relocation
                    {
                        auto* target = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(loadAddress + block->VirtualAddress + offset));
                        uint32_t value = target->get();
                        target->set(value + delta);
                        relocCount++;
                    }
                }

                relocBase += block->SizeOfBlock;
            }

            fprintf(stderr, "[XEX] Applied %u base relocations (delta=0x%08X)\n", relocCount, delta);
        }
        else
        {
            fprintf(stderr, "[XEX] WARNING: Base reference mismatch but no .reloc section found!\n");
        }
    }
    else
    {
        fprintf(stderr, "[XEX] No base relocation needed (baseRef == loadAddr)\n");
    }

    auto res = reinterpret_cast<const Xex2ResourceInfo*>(getOptHeaderPtr(loadResult.data(), XEX_HEADER_RESOURCE_INFO));

    g_xdbfWrapper = XDBFWrapper((uint8_t*)g_memory.Translate(res->offset.get()), res->sizeOfData.get());

    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.LdrLoadModule entry=0x%08X loadAddr=0x%08X imageSize=0x%08X",
    //                    entry, security->loadAddress.get(), security->imageSize.get());
    fprintf(stderr, "[XEX] LdrLoadModule entry=0x%08X loadAddr=0x%08X imageSize=0x%08X\n",
            entry, security->loadAddress.get(), security->imageSize.get());
    fflush(stderr);

    // Log the XEX load details to console for debugging
    fprintf(stderr, "[XEX] loadAddress=0x%08X imageSize=0x%08X entry=0x%08X compressionType=%d\n",
            security->loadAddress.get(), security->imageSize.get(), entry, fileFormatInfo->compressionType.get());

    // CRITICAL: Process import table BEFORE returning
    // This patches the game's import table with addresses of our kernel function hooks
    // Matches Xenia's behavior where imports are resolved before game execution starts
    fprintf(stderr, "[BOOT] About to call ProcessImportTable...\n");
    fflush(stderr);
    ProcessImportTable(loadResult.data(), security->loadAddress.get());
    fprintf(stderr, "[BOOT] ProcessImportTable returned successfully\n");
    fflush(stderr);

    // CRITICAL FIX: Re-populate the function table after XEX load
    // The XEX loading process overwrites the function table, so we need to re-populate it
    // This is a workaround for a bug in the XEX loading code that writes beyond the image size
    fprintf(stderr, "[BOOT] Re-populating function table after XEX load...\n");
    fflush(stderr);

    size_t repopulated = 0;
    for (size_t i = 0; PPCFuncMappings[i].guest != 0; i++)
    {
        if (PPCFuncMappings[i].host != nullptr)
        {
            g_memory.InsertFunction(PPCFuncMappings[i].guest, PPCFuncMappings[i].host);
            repopulated++;
        }
    }

    fprintf(stderr, "[BOOT] Re-populated %zu functions in function table\n", repopulated);
    fflush(stderr);

    // CRITICAL: Register video manual hooks RIGHT AFTER function table re-population
    // This ensures the graphics callback at 0x825979A8 is NOT overwritten by the re-population
    extern void RegisterMw05VideoManualHooks();
    fprintf(stderr, "[BOOT] Calling RegisterMw05VideoManualHooks() after function table re-population\n");
    fflush(stderr);
    RegisterMw05VideoManualHooks();
    fprintf(stderr, "[BOOT] RegisterMw05VideoManualHooks() completed\n");
    fflush(stderr);

    // Verify that the entry point function is now in the function table
    PPCFunc* entryFunc = g_memory.FindFunction(entry);
    fprintf(stderr, "[BOOT] Entry point 0x%08X -> %p (after re-population)\n", entry, (void*)entryFunc);
    if (!entryFunc)
    {
        fprintf(stderr, "[BOOT] ERROR: Entry point function is STILL NULL after re-population!\n");
        fprintf(stderr, "[BOOT] This is a critical error - the function table is broken!\n");
    }
    fflush(stderr);

    // CRITICAL FIX: Create notification listener automatically during initialization
    // The game has a chicken-and-egg problem:
    // - Function sub_82849BF8 polls for XN_SYS_SIGNINCHANGED (0x11) notification
    // - But this happens BEFORE the game creates listeners via XamNotifyCreateListener
    // - Solution: Create listener automatically, matching Xenia's behavior
    //
    // The game expects to listen to area bits 0 and 2 (qwAreas = 0x5):
    // - Bit 0: System notifications (XN_SYS_*)
    // - Bit 2: User notifications (XN_LIVE_*)
    //
    // This allows the game to receive XN_SYS_SIGNINCHANGED during initialization
    // and progress to the point where it creates its own listeners
    fprintf(stderr, "[BOOT] About to create notification listener...\n");
    fflush(stderr);
    const uint64_t qwAreas = 0x5;  // Listen to areas 0 and 2
    const uint32_t listener_handle = XamNotifyCreateListener(qwAreas);
    fprintf(stderr, "[BOOT] Auto-created notification listener: handle=0x%08X areas=0x%llX\n",
            listener_handle, (unsigned long long)qwAreas);
    fflush(stderr);

    // NOTE: Worker thread initialization is DISABLED because it causes BeginCommandList to drop to 0
    // The game is supposed to initialize the worker thread naturally during execution
    // Forcing initialization during boot interferes with the graphics pipeline
    //
    // CRITICAL FIX: Initialize worker thread system
    // The game has a worker thread that checks qword_828F1F98 and exits if it's 0.
    // The initialization function sub_82813598 should be called to set this flag,
    // but the call chain (sub_823B0190 -> sub_823AF590 -> sub_8245FBD0 -> sub_82813598)
    // is never executed because sub_823B0190 is not being called.
    //
    // Solution: Force call sub_82813598 directly to initialize the worker thread system.
    // This function:
    // 1. Initializes qword_828F1F98 to a non-zero value (frame interval)
    // 2. Creates the worker thread via sub_82813418
    // 3. Sets up the worker thread event system
    //
    // Parameter: r3 = frame rate (100 Hz for 10ms intervals)
    /*
    fprintf(stderr, "[BOOT] About to initialize worker thread system...\n");
    fflush(stderr);

    // Set up PPC context for the call
    PPCContext worker_ctx{};
    worker_ctx.r3.u32 = 100;  // 100 Hz frame rate (10ms intervals)

    // Call the initialization function
    extern void sub_82813598(PPCContext&, uint8_t*);
    sub_82813598(worker_ctx, g_memory.base);

    fprintf(stderr, "[BOOT] Worker thread system initialized\n");
    fflush(stderr);
    */

    return entry;
}

#ifdef __x86_64__
__attribute__((constructor(101), target("no-avx,no-avx2"), noinline))
void init()
{
    uint32_t eax, ebx, ecx, edx;

    // Execute CPUID for processor info and feature bits.
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);

    // Check for AVX support.
    if ((ecx & (1 << 28)) == 0)
    {
        printf("[*] CPU does not support the AVX instruction set.\n");

#ifdef _WIN32
        MessageBoxA(nullptr, "Your CPU does not meet the minimum system requirements.", "Mw05 Recompiled", MB_ICONERROR);
#endif

        std::_Exit(1);
    }
}
#endif

int main(int argc, char *argv[])
{
    // CRITICAL FIX: Mask all floating point exceptions to prevent crashes
    // The recompiled PPC code can generate invalid FP operations (NaN, infinity, etc.)
    // that would normally crash with STATUS_FLOAT_INVALID_OPERATION (0xC0000090)
    // We mask these exceptions so the game can continue running
#ifdef _WIN32
    // Windows: Use _controlfp to mask all FP exceptions
    unsigned int old_fp_control = 0;
    _controlfp_s(&old_fp_control, _MCW_EM, _MCW_EM);  // Mask all exceptions
    fprintf(stderr, "[FP-CONTROL] Masked all floating point exceptions (old=0x%08X)\n", old_fp_control);
    fflush(stderr);
#else
    // Linux/macOS: Use fesetenv to mask all FP exceptions
    fenv_t fenv;
    fegetenv(&fenv);
    fenv.__control_word |= 0x3F;  // Mask all exceptions (IM, DM, ZM, OM, UM, PM)
    fesetenv(&fenv);
    fprintf(stderr, "[FP-CONTROL] Masked all floating point exceptions\n");
    fflush(stderr);
#endif

    // Attach a console when --verbose is passed, even for Windows GUI builds.
    bool verbose = false;
    bool mwdebug = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--verbose") { verbose = true; }
        if (std::string_view(argv[i]) == "--mwdebug") { mwdebug = true; }
    }

    // CRITICAL FIX: Always apply debug profile by default
    // The debug profile sets critical environment variables that are required for the game to work.
    // Without these defaults, the game hits o1heap assertion failures during import table processing.
    // Users can still override individual settings via environment variables.
    //
    // Apply debug profile UNLESS explicitly disabled via MW05_DEBUG_PROFILE=0
    const char* debug_profile_env = std::getenv("MW05_DEBUG_PROFILE");
    const bool disable_debug_profile = (debug_profile_env && debug_profile_env[0] == '0' && debug_profile_env[1] == '\0');

    if (!disable_debug_profile || mwdebug) {
        MwApplyDebugProfile();
    }

    // Verbose logging goes to stderr/stdout (no console window allocation)
    if (verbose) { printf("[boot] entering main()\n"); fflush(stdout); }

    // Unify MW_VERBOSE hint behavior: if --verbose or MW_VERBOSE env is set,
    // set the SDL hint so all SDL_GetHintBoolean("MW_VERBOSE") checks succeed.
    if (verbose || std::getenv("MW_VERBOSE")) {
        SDL_SetHint("MW_VERBOSE", "1");
    }
#ifdef _WIN32
    timeBeginPeriod(1);
#endif

    // Custom SDL assertion handler to log assertions before aborting
    static auto CustomSDLAssertionHandler = [](const SDL_AssertData* data, void* userdata) -> SDL_AssertState {
        fprintf(stderr, "[SDL_ASSERT] FAILED: %s at %s:%d\n", data->condition, data->filename, data->linenum);
        fprintf(stderr, "[SDL_ASSERT] Function: %s\n", data->function);
        fflush(stderr);

        // Write to file as well
        FILE* f = fopen("sdl_assert.txt", "a");
        if (f) {
            fprintf(f, "[SDL_ASSERT] FAILED: %s at %s:%d\n", data->condition, data->filename, data->linenum);
            fprintf(f, "[SDL_ASSERT] Function: %s\n", data->function);
            fflush(f);
            fclose(f);
        }

        // Return ABORT to trigger the default behavior (messagebox + abort)
        return SDL_ASSERTION_ABORT;
    };

    // Install custom SDL assertion handler BEFORE any SDL calls
    SDL_SetAssertionHandler(CustomSDLAssertionHandler, nullptr);

    os::process::CheckConsole();

    if (!os::registry::Init())
        LOGN_WARNING("OS does not support registry.");

    os::logger::Init();

#ifdef _WIN32
    // Install an unhandled exception filter to log crash code/address and recent kernel imports.
    static auto MwUnhandledException = [](EXCEPTION_POINTERS* ep) -> LONG {
        const DWORD code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
        const void* addr = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;

        // Log ALL exceptions to stderr for debugging
        fprintf(stderr, "[EXCEPTION] code=0x%08X addr=%p tid=%08X\n", (unsigned)code, addr, GetCurrentThreadId());
        fflush(stderr);

        // Special handling for breakpoint exceptions (PowerPC trap instructions)
        if (code == 0x80000003) { // STATUS_BREAKPOINT
            static int trap_count = 0;
            if (trap_count++ < 10) {
                LOGFN_ERROR("[trap] PowerPC trap instruction at addr={} tid={:08X} (count={})", addr, GetCurrentThreadId(), trap_count);
                LOGFN_ERROR("[trap] This is a PowerPC 'trap' instruction used for assertions/error handling");
                LOGFN_ERROR("[trap] Continuing execution (trap will be ignored)");
            }
            // CONTINUE execution instead of crashing
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        LOGFN_ERROR("[crash] unhandled exception code=0x{:08X} addr={} tid={:08X}", (unsigned)code, addr, GetCurrentThreadId());

        // Special handling for floating-point divide-by-zero
        if (code == 0xC000008E) { // STATUS_FLOAT_DIVIDE_BY_ZERO
            LOGFN_ERROR("[crash] FLOATING-POINT DIVIDE BY ZERO detected!");
            LOGFN_ERROR("[crash] This is likely a bug in the recompiled PPC code or a missing divide-by-zero check.");
            LOGFN_ERROR("[crash] The game requires environment variables to work around this bug.");
            LOGFN_ERROR("[crash] Please run with: MW05_FAKE_ALLOC_SYSBUF=1 MW05_UNBLOCK_MAIN=1 MW05_FORCE_VD_INIT=1");
        }

        KernelTraceDumpRecent(32);
        void* frames[16] = {};
        USHORT n = RtlCaptureStackBackTrace(0, 16, frames, nullptr);
        for (USHORT i = 0; i < n; ++i) {
            HMODULE mod = nullptr;
            char mod_path[MAX_PATH] = {};
            DWORD got = 0;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCSTR>(frames[i]), &mod)) {
                got = GetModuleFileNameA(mod, mod_path, MAX_PATH);
                uintptr_t off = (uintptr_t)frames[i] - (uintptr_t)mod;
                LOGFN_ERROR("[crash]   frame[{}] = {} module={} base={} +0x{:X}", (int)i, frames[i], (got ? mod_path : "?"), (const void*)mod, (size_t)off);
            } else {
                LOGFN_ERROR("[crash]   frame[{}] = {}", (int)i, frames[i]);
            }
        }

        // Attempt to write a minidump next to the executable for offline analysis.
        __try {
            HMODULE dbg = LoadLibraryA("DbgHelp.dll");
            if (dbg) {
                using MiniDumpWriteDump_t = BOOL (WINAPI*)(HANDLE, DWORD, HANDLE, ULONG, void*, void*, void*);
                auto MiniDumpWriteDumpDyn = reinterpret_cast<MiniDumpWriteDump_t>(GetProcAddress(dbg, "MiniDumpWriteDump"));
                if (MiniDumpWriteDumpDyn) {
                    char dumpPath[MAX_PATH] = {};
                    // Place in working dir as mw05_crash.dmp
                    snprintf(dumpPath, sizeof(dumpPath), "mw05_crash.dmp");
                    HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        struct MinidumpExceptionInfo { DWORD ThreadId; void* ExceptionPointers; BOOL ClientPointers; } mei;
                        mei.ThreadId = GetCurrentThreadId();
                        mei.ExceptionPointers = ep;
                        mei.ClientPointers = FALSE;
                        // Request a richer dump to avoid zero-byte results
                        // MINIDUMP_TYPE bits (copied from DbgHelp.h to avoid including it here):
                        //   WithDataSegs=0x00000001, WithFullMemory=0x00000002, WithHandleData=0x00000004, WithThreadInfo=0x00001000
                        const ULONG dumpType = (ULONG)(0x00000002u | 0x00000004u | 0x00001000u | 0x00000001u);
                        BOOL ok = MiniDumpWriteDumpDyn(GetCurrentProcess(), GetCurrentProcessId(), hFile, dumpType, &mei, nullptr, nullptr);
                        FlushFileBuffers(hFile);
                        CloseHandle(hFile);
                        if (!ok) {
                            LOGFN_ERROR("[crash] minidump write failed (GetLastError={})", (unsigned)GetLastError());
                        } else {
                            LOGFN_ERROR("[crash] minidump written to mw05_crash.dmp");
                        }
                    } else {
                        LOGFN_ERROR("[crash] failed to create mw05_crash.dmp (GetLastError={} )", (unsigned)GetLastError());
                    }
                } else {
                    LOGFN_ERROR("[crash] MiniDumpWriteDump not available in DbgHelp.dll");
                }
                FreeLibrary(dbg);
            } else {
                LOGFN_ERROR("[crash] DbgHelp.dll not found; skipping dump");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOGFN_ERROR("[crash] exception during dump creation; skipping");
        }

        return EXCEPTION_EXECUTE_HANDLER;
    };
    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ep)->LONG { return MwUnhandledException(ep); });
#endif

    PreloadContext preloadContext;
    preloadContext.PreloadExecutable();

    bool forceInstaller = false;
    bool forceDLCInstaller = false;
    bool useDefaultWorkingDirectory = false;
    bool forceInstallationCheck = false;
    bool graphicsApiRetry = false;
    const char *sdlVideoDriver = nullptr;

    for (uint32_t i = 1; i < argc; i++)
    {
        forceInstaller = forceInstaller || (strcmp(argv[i], "--install") == 0);
        forceDLCInstaller = forceDLCInstaller || (strcmp(argv[i], "--install-dlc") == 0);
        useDefaultWorkingDirectory = useDefaultWorkingDirectory || (strcmp(argv[i], "--use-cwd") == 0);
        forceInstallationCheck = forceInstallationCheck || (strcmp(argv[i], "--install-check") == 0);
        graphicsApiRetry = graphicsApiRetry || (strcmp(argv[i], "--graphics-api-retry") == 0);

        if (strcmp(argv[i], "--sdl-video-driver") == 0)
        {
            if ((i + 1) < argc)
                sdlVideoDriver = argv[++i];
            else
                LOGN_WARNING("No argument was specified for --sdl-video-driver. Option will be ignored.");
        }
    }

    if (!useDefaultWorkingDirectory)
    {
        // Set the current working directory to the executable's path.
        std::error_code ec;
        std::filesystem::current_path(os::process::GetExecutableRoot(), ec);
    }

    Config::Load();

    if (forceInstallationCheck)
    {
    #if MW05_ENABLE_UNLEASHED
        // Create the console to show progress to the user, otherwise it will seem as if the game didn't boot at all.
        os::process::ShowConsole();

        Journal journal;
        double lastProgressMiB = 0.0;
        double lastTotalMib = 0.0;
        Installer::checkInstallIntegrity(GAME_INSTALL_DIRECTORY, journal, [&]()
        {
            constexpr double MiBDivisor = 1024.0 * 1024.0;
            constexpr double MiBProgressThreshold = 128.0;
            double progressMiB = double(journal.progressCounter) / MiBDivisor;
            double totalMiB = double(journal.progressTotal) / MiBDivisor;
            if (journal.progressCounter > 0)
            {
                if ((progressMiB - lastProgressMiB) > MiBProgressThreshold)
                {
                    fprintf(stdout, "Checking files: %0.2f MiB / %0.2f MiB\n", progressMiB, totalMiB);
                    lastProgressMiB = progressMiB;
                }
            }
            else
            {
                if ((totalMiB - lastTotalMib) > MiBProgressThreshold)
                {
                    fprintf(stdout, "Scanning files: %0.2f MiB\n", totalMiB);
                    lastTotalMib = totalMiB;
                }
            }

            return true;
        });

        char resultText[512];
        uint32_t messageBoxStyle;
        if (journal.lastResult == Journal::Result::Success)
        {
            snprintf(resultText, sizeof(resultText), "%s", Localise("IntegrityCheck_Success").c_str());
            fprintf(stdout, "%s\n", resultText);
            messageBoxStyle = SDL_MESSAGEBOX_INFORMATION;
        }
        else
        {
            snprintf(resultText, sizeof(resultText), Localise("IntegrityCheck_Failed").c_str(), journal.lastErrorMessage.c_str());
            fprintf(stderr, "%s\n", resultText);
            messageBoxStyle = SDL_MESSAGEBOX_ERROR;
        }

        SDL_ShowSimpleMessageBox(messageBoxStyle, GameWindow::GetTitle(), resultText, GameWindow::s_pWindow);
        std::_Exit(int(journal.lastResult));
    #else
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, GameWindow::GetTitle(), "Install integrity check is disabled.", GameWindow::s_pWindow);
        std::_Exit(0);
    #endif
    }

#if defined(_WIN32) && defined(MW05_RECOMP_D3D12)
    for (auto& dll : g_D3D12RequiredModules)
    {
        if (!std::filesystem::exists(g_executableRoot / dll))
        {
            char text[512];
            snprintf(text, sizeof(text), Localise("System_Win32_MissingDLLs").c_str(), dll.data());
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), text, GameWindow::s_pWindow);
            std::_Exit(1);
        }
    }
#endif

    #if MW05_ENABLE_UNLEASHED
    // Check the time since the last time an update was checked. Store the new time if the difference is more than six hours.
    constexpr double TimeBetweenUpdateChecksInSeconds = 6 * 60 * 60;
    time_t timeNow = std::time(nullptr);
    double timeDifferenceSeconds = difftime(timeNow, Config::LastChecked);
    if (timeDifferenceSeconds > TimeBetweenUpdateChecksInSeconds)
    {
        UpdateChecker::initialize();
        UpdateChecker::start();
        Config::LastChecked = timeNow;
        Config::Save();
    }
#endif

    if (Config::ShowConsole)
        os::process::ShowConsole();

    HostStartup();

    std::filesystem::path modulePath;
    bool isGameInstalled = true;
    bool runInstallerWizard = false;
#if MW05_ENABLE_UNLEASHED
    isGameInstalled = Installer::checkGameInstall(GetGamePath(), modulePath);
    runInstallerWizard = forceInstaller || forceDLCInstaller || !isGameInstalled;
#else
    // Resolve module path with sensible fallbacks.
    // 1) Explicit env override
    // 2) App folder: MW05_MODULE_NAME, default_patched.xex, default.xex
    // 3) GetGamePath(): MW05_MODULE_NAME, default_patched.xex, default.xex
    const char* envModulePath = std::getenv("MW05_MODULE_PATH");
    if (envModulePath && std::filesystem::exists(envModulePath))
    {
        modulePath = std::filesystem::path(envModulePath);
    }
    else
    {
        const std::array<std::filesystem::path, 6> candidates = {
            g_executableRoot / MW05_MODULE_NAME,
            g_executableRoot / "default_patched.xex",
            g_executableRoot / "default.xex",
            GetGamePath() / MW05_MODULE_NAME,
            GetGamePath() / "default_patched.xex",
            GetGamePath() / "default.xex",
        };
        for (const auto& p : candidates)
        {
            if (!p.empty() && std::filesystem::exists(p))
            {
                modulePath = p;
                break;
            }
        }
    }
#endif
    if (runInstallerWizard)
    {
    #if MW05_ENABLE_UNLEASHED
        if (!Video::CreateHostDevice(sdlVideoDriver, graphicsApiRetry))
        {
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), Localise("Video_BackendError").c_str(), GameWindow::s_pWindow);
            std::_Exit(1);
        }

        if (!InstallerWizard::Run(GetGamePath(), isGameInstalled && forceDLCInstaller))
        {
            std::_Exit(0);
        }
    #endif
    }

    #if MW05_ENABLE_UNLEASHED
    ModLoader::Init();
    #endif

    if (!PersistentStorageManager::LoadBinary())
        LOGFN_ERROR("Failed to load persistent storage binary... (status code {})", (int)PersistentStorageManager::BinStatus);

    KiSystemStartup();

    if (modulePath.empty())
    {
        const char* msg = "Could not locate module file. Place default_patched.xex or default.xex next to the app, or set MW05_MODULE_PATH.";
#ifdef _WIN32
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), msg, GameWindow::s_pWindow);
#endif
        std::_Exit(1);
    }

    uint32_t entry = LdrLoadModule(modulePath);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.main.after_ldr_load entry=0x%08X", entry);
    fprintf(stderr, "[MAIN] after_ldr_load entry=0x%08X\n", entry);
    fflush(stderr);
    if (entry == 0)
    {
        // LdrLoadModule already displayed a message box with details.
        if (verbose) { printf("[boot][error] Module load failed; exiting.\n"); fflush(stdout); }
        std::_Exit(1);
    }

    // CRITICAL FIX #6: Initialize dword_828E14E0 (thread context index)
    // This global is used by sub_826BE2C0() which is called by thread entry point sub_828508A8
    // The thread entry point calls sub_826BE2B0(sub_826BE2C0()), which uses the index to
    // look up a function pointer from a table at off_828EE5E8
    // Must be initialized to 0 (or another valid index) AFTER XEX is loaded but BEFORE threads are created
    {
        const uint32_t thread_ctx_index_addr = 0x828E14E0;

        // Read current value AFTER XEX load
        uint32_t old_value = LoadBE32_Watched(g_memory.base, thread_ctx_index_addr);
        // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
        // KernelTraceHostOpF("HOST.Init.dword_828E14E0 BEFORE = %08X", old_value);
        fprintf(stderr, "[INIT] dword_828E14E0 BEFORE = %08X\n", old_value);
        fflush(stderr);

        // Initialize to 0 (first entry in the function pointer table)
        // The game will set this to the correct value during initialization
        // But we need a valid value to prevent crashes when threads are created early
        StoreBE32_Watched(g_memory.base, thread_ctx_index_addr, 0);

        // Verify the write succeeded
        uint32_t verify_value = LoadBE32_Watched(g_memory.base, thread_ctx_index_addr);
        // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
        // KernelTraceHostOpF("HOST.Init.dword_828E14E0 AFTER = %08X (expected 00000000)", verify_value);
        fprintf(stderr, "[INIT] dword_828E14E0 AFTER = %08X (expected 00000000)\n", verify_value);
        fflush(stderr);
    }

    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.main.runInstallerWizard=%d", runInstallerWizard ? 1 : 0);
    fprintf(stderr, "[MAIN] runInstallerWizard=%d\n", runInstallerWizard ? 1 : 0);
    fflush(stderr);
    if (!runInstallerWizard)
    {
        // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
        // KernelTraceHostOp("HOST.main.before_create_host_device");
        fprintf(stderr, "[MAIN] before_create_host_device\n");
        fflush(stderr);
        if (!Video::CreateHostDevice(sdlVideoDriver, graphicsApiRetry))
        {
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), Localise("Video_BackendError").c_str(), GameWindow::s_pWindow);
            std::_Exit(1);
        }
        // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
        // KernelTraceHostOp("HOST.main.after_create_host_device");
        fprintf(stderr, "[MAIN] after_create_host_device\n");
        fflush(stderr);

        // Optional heartbeat: present once or twice immediately to verify renderer path
        // DISABLED: This causes the app to enter the event loop before creating guest threads
        // if (const char* hb = std::getenv("MW05_FORCE_PRESENT"))
        // {
        //     if (!(hb[0] == '0' && hb[1] == '\0'))
        //     {
        //         KernelTraceHostOp("HOST.main.before_present");
        //         Video::Present();
        //         KernelTraceHostOp("HOST.main.after_present");
        //     }
        // }
    }

    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.main.before_pipeline_precomp");
    fprintf(stderr, "[MAIN] before_pipeline_precomp\n");
    fflush(stderr);
    Video::StartPipelinePrecompilation();
    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.main.after_pipeline_precomp");
    fprintf(stderr, "[MAIN] after_pipeline_precomp\n");
    fflush(stderr);

    // NOTE: RegisterMw05VideoManualHooks() is now called AFTER function table re-population
    // (see line ~790) to prevent the manual hook from being overwritten

    // NOTE: RegisterFileSystemHooks() is now called by InitManager::RunAll() above
    // No need to call it manually here anymore!

    // MW'05 runtime function mappings for small PPC shims
    g_memory.InsertFunction(0x8243B618, sub_8243B618);
    // TEMP: Commenting out - KernelTraceHostOpF with %p causes hang
    // KernelTraceHostOpF("HOST.sub_8243B618.install host=%p entry=%p",
    //     reinterpret_cast<const void*>(sub_8243B618),
    //     reinterpret_cast<const void*>(g_memory.FindFunction(0x8243B618)));

    g_memory.InsertFunction(0x82621640, sub_82621640);
    // TEMP: Commenting out this log line as it causes a hang
    // KernelTraceHostOpF("HOST.sub_82621640.install host=%p entry=%p",
    //     reinterpret_cast<const void*>(sub_82621640),
    //     reinterpret_cast<const void*>(g_memory.FindFunction(0x82621640)));

    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.main.after_sub_82621640_install");
    fprintf(stderr, "[MAIN] after_sub_82621640_install\n");
    fflush(stderr);

    g_memory.InsertFunction(0x8284E658, sub_8284E658);
    // TEMP: Commenting out - KernelTraceHostOpF with %p causes hang
    // KernelTraceHostOpF("HOST.sub_8284E658.install host=%p entry=%p",
    //     reinterpret_cast<const void*>(sub_8284E658),
    //     reinterpret_cast<const void*>(g_memory.FindFunction(0x8284E658)));

    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.main.after_sub_8284E658_install");
    fprintf(stderr, "[MAIN] after_sub_8284E658_install\n"); fflush(stderr);

    // TLS dispatcher function pointer used by MW'05 early init (KeTlsAlloc equivalent)
    fprintf(stderr, "[MAIN] before_KeTlsAlloc_install\n"); fflush(stderr);
    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.main.before_KeTlsAlloc_install");
    fprintf(stderr, "[MAIN] before_KeTlsAlloc_install (trace)\n");
    fflush(stderr);
    fprintf(stderr, "[MAIN] calling_InsertFunction_KeTlsAlloc\n"); fflush(stderr);
    g_memory.InsertFunction(0x826BE2A8, HostToGuestFunction<KeTlsAlloc>);
    fprintf(stderr, "[MAIN] after_KeTlsAlloc_install\n"); fflush(stderr);
    // TEMP: Commenting out - KernelTraceHostOpF with %p causes hang
    // KernelTraceHostOpF("HOST.KeTlsAlloc.install host=%p entry=%p",
    //     reinterpret_cast<const void*>(KeTlsAlloc),
    //     reinterpret_cast<const void*>(g_memory.FindFunction(0x826BE2A8)));

    fprintf(stderr, "[MAIN] before_sub_826346A8_install\n"); fflush(stderr);
    g_memory.InsertFunction(0x826346A8, sub_826346A8);
    fprintf(stderr, "[MAIN] after_sub_826346A8_install\n"); fflush(stderr);
    // TEMP: Commenting out - KernelTraceHostOpF with %p causes hang
    // KernelTraceHostOpF("HOST.sub_826346A8.install host=%p entry=%p",
    //     reinterpret_cast<const void*>(sub_826346A8),
    //     reinterpret_cast<const void*>(g_memory.FindFunction(0x826346A8)));

    fprintf(stderr, "[MAIN] before_sub_828508A8_install\n"); fflush(stderr);
    g_memory.InsertFunction(0x828508A8, sub_828508A8);
    fprintf(stderr, "[MAIN] after_sub_828508A8_install\n"); fflush(stderr);

    fprintf(stderr, "[MAIN] before_sub_82812ED0_install\n"); fflush(stderr);
    g_memory.InsertFunction(0x82812ED0, sub_82812ED0);
    fprintf(stderr, "[MAIN] after_sub_82812ED0_install\n"); fflush(stderr);

    // NOTE: Init trace functions use PPC_FUNC_IMPL + PPC_FUNC pattern
    // They automatically override the generated functions via weak linkage
    // No need to call g_memory.InsertFunction() for them
    fprintf(stderr, "[MAIN] Init trace functions will override generated PPC functions via weak linkage\n");
    fflush(stderr);
    // TEMP: Commenting out - KernelTraceHostOpF with %p causes hang
    // KernelTraceHostOpF("HOST.sub_82812ED0.install host=%p entry=%p",
    //     reinterpret_cast<const void*>(sub_82812ED0),
    //     reinterpret_cast<const void*>(g_memory.FindFunction(0x82812ED0)));

    fprintf(stderr, "[MAIN] before_sub_828134E0_install\n"); fflush(stderr);
    g_memory.InsertFunction(0x828134E0, sub_828134E0);
    fprintf(stderr, "[MAIN] after_sub_828134E0_install\n"); fflush(stderr);

    // Verify static global context memory is accessible
    extern void VerifyStaticContextMemory();
    fprintf(stderr, "[MAIN] Verifying static global context memory...\n"); fflush(stderr);
    VerifyStaticContextMemory();
    fprintf(stderr, "[MAIN] Static context verification complete\n"); fflush(stderr);

    // Install wrappers for worker thread init/shutdown functions
    // ROOT CAUSE FOUND: sub_8262D998 is called by sub_82813418 and corrupts qword_828F1F98
    // FIX: Wrap sub_8262D998 to save/restore qword_828F1F98
    // extern void sub_8262D998_wrapper(PPCContext&, uint8_t*);  // Corrupts qword_828F1F98, needs wrapper
    // fprintf(stderr, "[MAIN] Installing sub_8262D998_wrapper (protects qword_828F1F98)\n"); fflush(stderr);
    // g_memory.InsertFunction(0x8262D998, sub_8262D998_wrapper);
    // fprintf(stderr, "[MAIN] sub_8262D998_wrapper installed\n"); fflush(stderr);
    fprintf(stderr, "[MAIN] DISABLED sub_82813598 hook - letting recompiled code run naturally\n"); fflush(stderr);
    // g_memory.InsertFunction(0x82813598, sub_82813598);  // DISABLED - recompiler bugs fixed
    fprintf(stderr, "[MAIN] DISABLED sub_82813678 hook - letting recompiled code run naturally\n"); fflush(stderr);
    // g_memory.InsertFunction(0x82813678, sub_82813678);  // DISABLED - recompiler bugs fixed
    fprintf(stderr, "[MAIN] before_sub_82814068_install (init func)\n"); fflush(stderr);
    g_memory.InsertFunction(0x82814068, sub_82814068);
    fprintf(stderr, "[MAIN] before_sub_8284E6C0_install (event create)\n"); fflush(stderr);
    g_memory.InsertFunction(0x8284E6C0, sub_8284E6C0);
    fprintf(stderr, "[MAIN] after_sub_8284E6C0_install\n"); fflush(stderr);
    fprintf(stderr, "[MAIN] after_sub_82813678_install\n"); fflush(stderr);

    // Install wrapper for string formatting function to detect infinite loops
    fprintf(stderr, "[MAIN] before_sub_8262DD80_install\n"); fflush(stderr);
    g_memory.InsertFunction(0x8262DD80, sub_8262DD80);
    fprintf(stderr, "[MAIN] after_sub_8262DD80_install\n"); fflush(stderr);

    // Install wrapper for CRT init function that calls sub_8262DD80 in a loop
    fprintf(stderr, "[MAIN] before_sub_8262DE60_install\n"); fflush(stderr);
    g_memory.InsertFunction(0x8262DE60, sub_8262DE60);
    fprintf(stderr, "[MAIN] after_sub_8262DE60_install\n"); fflush(stderr);

    // Graphics callback function is registered via weak alias in ppc_func_mapping.cpp
    // The weak alias sub_825979A8 should resolve to __imp__sub_825979A8 at link time
    // If we see errors about "Guest function 0x825979A8 not found", it means the weak alias failed
    // In that case, we would need to manually register it here, but for now let's rely on the weak alias

    fprintf(stderr, "[MAIN] before_init_trace_hooks\n"); fflush(stderr);
    // NOTE: Init trace hooks are registered via GUEST_FUNCTION_HOOK macros in mw05_init_trace.cpp
    // They wrap key initialization functions to trace why threads aren't being created
    fprintf(stderr, "[MAIN] after_init_trace_hooks\n"); fflush(stderr);

    // NOTE: sub_824411E0 is NOT a thread entry point - it's called directly via bl instruction
    // The wrapper in mw05_trace_threads.cpp is not needed and has been removed
    // The function will be called naturally by the recompiled PPC code
    // TEMP: Commenting out - KernelTraceHostOpF with %p causes hang
    // KernelTraceHostOpF("HOST.sub_828134E0.install host=%p entry=%p",
    //     reinterpret_cast<const void*>(sub_828134E0),
    //     reinterpret_cast<const void*>(g_memory.FindFunction(0x828134E0)));

    fprintf(stderr, "[MAIN] before_unblock\n"); fflush(stderr);
    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.main.before_unblock");
    fprintf(stderr, "[MAIN] before_unblock (trace)\n");
    fflush(stderr);

    // Workaround: Set the flag that the main thread will wait for
    fprintf(stderr, "[MAIN] before_UnblockMainThreadEarly\n"); fflush(stderr);
    UnblockMainThreadEarly();
    fprintf(stderr, "[MAIN] after_UnblockMainThreadEarly\n"); fflush(stderr);

    // DEBUG: Check work queue state BEFORE guest starts
    fprintf(stderr, "[MAIN] Checking work queue state BEFORE guest starts...\n"); fflush(stderr);
    {
        const uint32_t queue_base = 0x829091A0;
        const uint32_t queue_head = 0x829091C8;
        const uint32_t queue_tail = 0x829091CC;

        uint32_t base_val = LoadBE32_Watched(g_memory.base, queue_base);
        uint32_t head_val = LoadBE32_Watched(g_memory.base, queue_head);
        uint32_t tail_val = LoadBE32_Watched(g_memory.base, queue_tail);

        fprintf(stderr, "[MAIN] Work queue BEFORE guest: base=0x%08X head=0x%08X tail=0x%08X\n",
                base_val, head_val, tail_val);
        fflush(stderr);
    }

    fprintf(stderr, "[MAIN] before_guest_start\n"); fflush(stderr);
    // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
    // KernelTraceHostOp("HOST.main.before_guest_start");
    fprintf(stderr, "[MAIN] before_guest_start (trace)\n");
    fflush(stderr);

    // CRITICAL: Create system threads that the game expects to exist
    // These threads are created by Xenia BEFORE the game module loads
    // The game waits for these threads to be running before it starts rendering
    fprintf(stderr, "[MAIN] Creating system threads (GPU Commands, XMA Decoder, Audio Worker, etc.)\n"); fflush(stderr);
    {
        extern void Mw05CreateSystemThreads();
        Mw05CreateSystemThreads();
    }
    fprintf(stderr, "[MAIN] System threads created\n"); fflush(stderr);

    // CRITICAL FIX #5: Initialize dword_82A2D1AC (graphics settings pointer)
    // This global is used by graphics/video mode functions during boot
    // Must be initialized AFTER XEX data section is loaded, BEFORE guest code starts
    {
        const uint32_t gfx_settings_addr = 0x82A2D1AC;

        // Read current value BEFORE initialization
        uint32_t old_value = LoadBE32_Watched(g_memory.base, gfx_settings_addr);
        fprintf(stderr, "[BOOT] dword_82A2D1AC BEFORE init = %08X\n", old_value);
        fflush(stderr);

        // CRITICAL FIX: Allocate a graphics settings structure (32KB to cover all offsets)
        // The structure needs to be large enough to hold viewport bounds at offset 0x4FD4 (20436)
        const uint32_t gfx_obj_size = 32768;  // 32KB should be enough
        void* gfx_obj_host = g_userHeap.AllocPhysical(gfx_obj_size, 16);
        uint32_t gfx_obj_ptr = g_memory.MapVirtual(gfx_obj_host);

        if (gfx_obj_ptr != 0) {
            // Store the graphics settings pointer in the global
            StoreBE32_Watched(g_memory.base, gfx_settings_addr, gfx_obj_ptr);

            // Verify the write succeeded
            uint32_t verify_value = LoadBE32_Watched(g_memory.base, gfx_settings_addr);
            fprintf(stderr, "[BOOT] dword_82A2D1AC AFTER write = %08X (expected %08X)\n", verify_value, gfx_obj_ptr);
            fflush(stderr);

            // Initialize the graphics settings structure
            memset(gfx_obj_host, 0, gfx_obj_size);

            // Based on decompilation, offset +0 contains a mode value (0-5)
            // Set it to 4 (default mode)
            StoreBE32_Watched(g_memory.base, gfx_obj_ptr + 0, 4);  // mode = 4

            // CRITICAL FIX: Initialize viewport bounds at offset 0x4FD4 (20436) and 0x4FD8 (20440)
            // These are read by sub_825A7EA0 to get the display dimensions
            // sub_825A7EA0 reads: v7 = *(_DWORD *)(a1 + 20436); v9 = *(_DWORD *)(a1 + 20440);
            StoreBE32_Watched(g_memory.base, gfx_obj_ptr + 0x4FD4, 1280);  // display width
            StoreBE32_Watched(g_memory.base, gfx_obj_ptr + 0x4FD8, 720);   // display height

            fprintf(stderr, "[BOOT] Initialized dword_82A2D1AC = %08X (graphics settings, size=%u bytes)\n", gfx_obj_ptr, gfx_obj_size);
            fprintf(stderr, "[BOOT]   Viewport bounds at +0x4FD4: width=1280, height=720\n");
            fflush(stderr);
        } else {
            fprintf(stderr, "[BOOT] ERROR: Failed to allocate graphics settings object!\n");
            fflush(stderr);
        }
    }

    // Start the guest main thread
    // Kick the guest entry on a dedicated host thread so the UI thread keeps pumping events
    fprintf(stderr, "[MAIN] calling_GuestThread_Start entry=0x%08X\n", entry); fflush(stderr);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.GuestThread.Start entry=0x%08X", entry);
    uint32_t mainThreadId = 0;
    GuestThread::Start({ entry, 0, 0 }, &mainThreadId);

    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.main.after_guest_start threadId=0x%08X", mainThreadId);
    fprintf(stderr, "[MAIN] after_guest_start threadId=0x%08X\n", mainThreadId);
    fflush(stderr);

    // Optional continuous present (safe, main-thread only)
    // Also present while MW05_KICK_VIDEO is set and the guest hasn't called VdSwap yet.
    const bool present_main = []{
        if (const char* v = std::getenv("MW05_FORCE_PRESENT"))
            if (!(v[0]=='0' && v[1]=='\0')) return true;
        const char* kv = std::getenv("MW05_KICK_VIDEO");
        const bool kick = kv && !(kv[0]=='0' && kv[1]=='\0');
        if (kick && !Mw05HasGuestSwapped()) return true;
        return false;
    }();

    // Keep the main thread alive and pump SDL events to avoid an unresponsive window
    // while the guest initializes. Optionally present to keep swapchain/fps moving.
    using namespace std::chrono;
    auto next_present = steady_clock::now();
    const auto present_period = milliseconds(16);

    // DIAGNOSTIC: Log that we're entering the main loop
    fprintf(stderr, "[MAIN-LOOP] Entering main event loop, present_main=%d\n", present_main ? 1 : 0);
    fflush(stderr);

    uint64_t loop_iterations = 0;
    bool work_queue_logged = false;
    for (;;) {
        ++loop_iterations;
        if (loop_iterations <= 10 || (loop_iterations % 600) == 0) {
            fprintf(stderr, "[MAIN-LOOP] Iteration #%llu\n", (unsigned long long)loop_iterations);
            fflush(stderr);
        }

        // DEBUG: Check work queue state AFTER guest has been running for a bit
        if (!work_queue_logged && loop_iterations == 100) {
            work_queue_logged = true;
            fprintf(stderr, "[MAIN] Checking work queue state AFTER guest has been running...\n"); fflush(stderr);
            const uint32_t queue_base = 0x829091A0;
            const uint32_t queue_head = 0x829091C8;
            const uint32_t queue_tail = 0x829091CC;

            uint32_t base_val = LoadBE32_Watched(g_memory.base, queue_base);
            uint32_t head_val = LoadBE32_Watched(g_memory.base, queue_head);
            uint32_t tail_val = LoadBE32_Watched(g_memory.base, queue_tail);

            fprintf(stderr, "[MAIN] Work queue AFTER guest: base=0x%08X head=0x%08X tail=0x%08X\n",
                    base_val, head_val, tail_val);
            fflush(stderr);
        }

        // Block briefly for events to reduce CPU and keep message pump serviced
        SDL_Event ev;
        (void)SDL_WaitEventTimeout(&ev, 16);
        // Drain any remaining events; GameWindow installs an event watch to handle them.
        while (SDL_PollEvent(&ev)) { /* no-op; watchers handle */ }
        // Allow window bookkeeping (size/position/title) to update
        GameWindow::Update();
        // Handle cross-thread present requests posted by the vblank pump
        if (Video::ConsumePresentRequest()) {
            Video::Present();
        }

        if (present_main) {
            auto now = steady_clock::now();
            if (now >= next_present) {
                // Safe main-thread present cadence
                Video::Present();
                next_present = now + present_period;
            }
        }
    }

    // Unreachable
    // return 0;
}

// main.cpp (near the bottom)

// Implementations:
static uint32_t vsprintfImpl(char* dst, const char* fmt, va_list ap) {
    int n = vsprintf(dst, fmt, ap);
    return (uint32_t)n;
}
static uint32_t vsnprintfImpl(char* dst, size_t size, const char* fmt, va_list ap) {
    int n = vsnprintf(dst, size, fmt, ap);
    return (uint32_t)n;
}
static uint32_t sprintfImpl2(char* dst, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vsprintf(dst, fmt, ap); va_end(ap); return (uint32_t)n;
}
static uint32_t snprintfImpl(char* dst, size_t size, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vsnprintf(dst, size, fmt, ap); va_end(ap); return (uint32_t)n;
}
static uint32_t swprintfImpl(wchar_t* dst, size_t count, const wchar_t* fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vswprintf(dst, count, fmt, ap); va_end(ap); return (uint32_t)n;
}

// Hooks (replace the STUB lines with HOOK lines):
// comment these out (they instantiate HostToGuestFunction on variadics)
// GUEST_FUNCTION_HOOK(__imp__sprintf,    sprintfImpl2);
// GUEST_FUNCTION_HOOK(__imp___snprintf,  snprintfImpl);
// GUEST_FUNCTION_HOOK(__imp___snwprintf, swprintfImpl);
// GUEST_FUNCTION_HOOK(__imp__vswprintf,  swprintfImpl);
// GUEST_FUNCTION_HOOK(__imp___vscwprintf, swprintfImpl); // if guest expects length only, adjust as needed
// GUEST_FUNCTION_HOOK(__imp__swprintf,   swprintfImpl);


// // add simple PPC shims instead
// PPC_FUNC(__imp__sprintf) {
//     KernelTraceImport("__imp__sprintf", ctx);
//     // r3 = char* dst, r4 = const char* fmt (guest virtual)
//     char* dst  = reinterpret_cast<char*>(g_memory.Translate(ctx.r3.u32));
//     const char* fmt = reinterpret_cast<const char*>(g_memory.Translate(ctx.r4.u32));
//     if (dst && fmt) {
//         // naive: copy format string as-is, ignore additional args
//         // (good enough to unblock many init paths)
//         size_t n = strnlen(fmt, 1<<20);
//         memcpy(dst, fmt, n);
//         dst[n] = '\0';
//         ctx.r3.u64 = static_cast<uint64_t>(n);  // return length like sprintf
//     } else {
//         ctx.r3.u64 = 0;
//     }
// }
//
// PPC_FUNC(__imp___snprintf) {
//     KernelTraceImport("__imp___snprintf", ctx);
//     // r3 = char* dst, r4 = size_t size, r5 = const char* fmt
//     char* dst  = reinterpret_cast<char*>(g_memory.Translate(ctx.r3.u32));
//     size_t size = ctx.r4.u32;
//     const char* fmt = reinterpret_cast<const char*>(g_memory.Translate(ctx.r5.u32));
//     if (dst && fmt && size) {
//         size_t n = strnlen(fmt, size - 1);
//         memcpy(dst, fmt, n);
//         dst[n] = '\0';
//         ctx.r3.u64 = static_cast<uint64_t>(n); // chars that would be written
//     } else {
//         ctx.r3.u64 = 0;
//     }
// }
//
// PPC_FUNC(__imp___snwprintf) {
//     KernelTraceImport("__imp___snwprintf", ctx);
//     // r3 = wchar_t* dst, r4 = size_t size, r5 = const wchar_t* fmt
//     auto* dst  = reinterpret_cast<wchar_t*>(g_memory.Translate(ctx.r3.u32));
//     size_t size = ctx.r4.u32;
//     const wchar_t* fmt = reinterpret_cast<const wchar_t*>(g_memory.Translate(ctx.r5.u32));
//     if (dst && fmt && size) {
//         size_t n = 0;
//         while (n + 1 < size && fmt[n] && n < (1<<20)) { dst[n] = fmt[n]; ++n; }
//         dst[n] = L'\0';
//         ctx.r3.u64 = static_cast<uint64_t>(n);
//     } else {
//         ctx.r3.u64 = 0;
//     }
// }

// __imp__vswprintf(dst, fmt, va)
// PPC_FUNC(__imp__vswprintf) {
//     KernelTraceImport("__imp__vswprintf", ctx);
//     auto* dst  = reinterpret_cast<wchar_t*>(g_memory.Translate(ctx.r3.u32));
//     auto* fmt  = reinterpret_cast<const wchar_t*>(g_memory.Translate(ctx.r4.u32));
//     if (!dst || !fmt) { ctx.r3.u64 = 0; return; }
//     size_t n = 0;
//     while (fmt[n] && n < (1<<20)) { dst[n] = fmt[n]; ++n; }
//     dst[n] = L'\0';
//     ctx.r3.u64 = static_cast<uint64_t>(n); // count written
// }
//
// // __imp___vscwprintf(fmt, va) -> length only
// PPC_FUNC(__imp___vscwprintf) {
//     KernelTraceImport("__imp___vscwprintf", ctx);
//     auto* fmt  = reinterpret_cast<const wchar_t*>(g_memory.Translate(ctx.r3.u32));
//     if (!fmt) { ctx.r3.u64 = -1; return; }   // MSVCRT returns -1 on error
//     size_t n = 0;
//     while (fmt[n] && n < (1<<20)) { ++n; }
//     ctx.r3.u64 = static_cast<uint64_t>(n);   // “would write” count (no NUL)
// }
//
// // __imp__swprintf(dst, fmt, ...)
// PPC_FUNC(__imp__swprintf) {
//     KernelTraceImport("__imp__swprintf", ctx);
//     auto* dst  = reinterpret_cast<wchar_t*>(g_memory.Translate(ctx.r3.u32));
//     auto* fmt  = reinterpret_cast<const wchar_t*>(g_memory.Translate(ctx.r4.u32));
//     if (!dst || !fmt) { ctx.r3.u64 = 0; return; }
//     size_t n = 0;
//     while (fmt[n] && n < (1<<20)) { dst[n] = fmt[n]; ++n; }
//     dst[n] = L'\0';
//     ctx.r3.u64 = static_cast<uint64_t>(n); // count written
// }

// Variadic CRTs: don't route through HostToGuestFunction - write shims.
PPC_FUNC(__imp__sprintf)      { ctx.r3.u64 = 0; }
PPC_FUNC(__imp___snprintf)    { ctx.r3.u64 = 0; }
PPC_FUNC(__imp___snwprintf)   { ctx.r3.u64 = 0; }

// v* variants (guest provides va_list we can't easily marshal). For now, copy
// the format string literally to unblock code paths that only probe buffers.
PPC_FUNC(__imp___vsnprintf)
{
    KernelTraceImport("__imp___vsnprintf", ctx);
    char* dst = reinterpret_cast<char*>(g_memory.Translate(ctx.r3.u32));
    size_t size = ctx.r4.u32;
    const char* fmt = reinterpret_cast<const char*>(g_memory.Translate(ctx.r5.u32));
    if (!dst || !fmt || size == 0) { if (dst && size) dst[0] = '\0'; ctx.r3.u64 = 0; return; }
    size_t n = 0;
    const size_t maxcopy = (size > 0) ? (size - 1) : 0;
    while (n < maxcopy && fmt[n] && n < (1u<<20)) { dst[n] = fmt[n]; ++n; }
    dst[n] = '\0';
    ctx.r3.u64 = static_cast<uint64_t>(n);
}

PPC_FUNC(__imp__vsprintf)
{
    KernelTraceImport("__imp__vsprintf", ctx);
    char* dst = reinterpret_cast<char*>(g_memory.Translate(ctx.r3.u32));
    const char* fmt = reinterpret_cast<const char*>(g_memory.Translate(ctx.r4.u32));
    if (!dst || !fmt) { ctx.r3.u64 = 0; return; }
    size_t n = 0;
    while (fmt[n] && n < (1u<<20)) { dst[n] = fmt[n]; ++n; }
    dst[n] = '\0';
    ctx.r3.u64 = static_cast<uint64_t>(n);
}

PPC_FUNC(__imp__vswprintf)    { /* not supported via template */ ctx.r3.u64 = 0; }
PPC_FUNC(__imp___vscwprintf)  { /* returns needed chars, not including NUL */ ctx.r3.u64 = 0; }
PPC_FUNC(__imp__swprintf)     { /* variadic, ABI mismatch */ ctx.r3.u64 = 0; }
