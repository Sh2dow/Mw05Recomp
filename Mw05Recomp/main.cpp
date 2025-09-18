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

void HostStartup()
{
#ifdef _WIN32
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
#endif

    hid::Init();
}

// Name inspired from nt's entry point
void KiSystemStartup()
{
    if (g_memory.base == nullptr)
    {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), Localise("System_MemoryAllocationFailed").c_str(), GameWindow::s_pWindow);
        std::_Exit(1);
    }

    g_userHeap.Init();

    // Install any generated indirect redirects after memory init
    #if MW05_GEN_INDIRECT_REDIRECTS
        #if !defined(_MSC_VER)
            if (&MwInstallGeneratedIndirectRedirects)
                MwInstallGeneratedIndirectRedirects();
        #else
            MwInstallGeneratedIndirectRedirects();
        #endif
    #endif

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

    // Mount game
    XamContentCreateEx(0, "game", &gameContent, OPEN_EXISTING, nullptr, nullptr, 0, 0, nullptr);
    XamContentCreateEx(0, "update", &updateContent, OPEN_EXISTING, nullptr, nullptr, 0, 0, nullptr);

    // OS mounts game data to D:
    XamContentCreateEx(0, "D", &gameContent, OPEN_EXISTING, nullptr, nullptr, 0, 0, nullptr);

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

    XAudioInitializeSystem();
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
    auto* security = reinterpret_cast<const Xex2SecurityInfo*>(loadResult.data() + header->securityOffset);
    const auto* fileFormatInfo = reinterpret_cast<const Xex2OptFileFormatInfo*>(getOptHeaderPtr(loadResult.data(), XEX_HEADER_FILE_FORMAT_INFO));
    auto entry = *reinterpret_cast<const uint32_t*>(getOptHeaderPtr(loadResult.data(), XEX_HEADER_ENTRY_POINT));
    ByteSwapInplace(entry);

    auto srcData = loadResult.data() + header->headerSize;
    auto destData = reinterpret_cast<uint8_t*>(g_memory.Translate(security->loadAddress));

    if (fileFormatInfo->compressionType == XEX_COMPRESSION_NONE)
    {
        memcpy(destData, srcData, security->imageSize);
    }
    else if (fileFormatInfo->compressionType == XEX_COMPRESSION_BASIC)
    {
        auto* blocks = reinterpret_cast<const Xex2FileBasicCompressionBlock*>(fileFormatInfo + 1);
        const size_t numBlocks = (fileFormatInfo->infoSize / sizeof(Xex2FileBasicCompressionInfo)) - 1;

        for (size_t i = 0; i < numBlocks; i++)
        {
            memcpy(destData, srcData, blocks[i].dataSize);

            srcData += blocks[i].dataSize;
            destData += blocks[i].dataSize;

            memset(destData, 0, blocks[i].zeroSize);
            destData += blocks[i].zeroSize;
        }
    }
    else
    {
        assert(false && "Unknown compression type.");
    }

    auto res = reinterpret_cast<const Xex2ResourceInfo*>(getOptHeaderPtr(loadResult.data(), XEX_HEADER_RESOURCE_INFO));

    g_xdbfWrapper = XDBFWrapper((uint8_t*)g_memory.Translate(res->offset.get()), res->sizeOfData);

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
    // Attach a console when --verbose is passed, even for Windows GUI builds.
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--verbose") { verbose = true; break; }
    }
#if defined(_WIN32)
    if (verbose) {
        AllocConsole();
        FILE* fOut = nullptr; FILE* fErr = nullptr;
        freopen_s(&fOut, "CONOUT$", "w", stdout);
        freopen_s(&fErr, "CONOUT$", "w", stderr);
        printf("[boot] Mw05Recomp starting (--verbose)\n");
        fflush(stdout);
    }
#endif
    if (verbose) { printf("[boot] entering main()\n"); fflush(stdout); }

    // Unify MW_VERBOSE hint behavior: if --verbose or MW_VERBOSE env is set,
    // set the SDL hint so all SDL_GetHintBoolean("MW_VERBOSE") checks succeed.
    if (verbose || std::getenv("MW_VERBOSE")) {
        SDL_SetHint("MW_VERBOSE", "1");
    }
#ifdef _WIN32
    timeBeginPeriod(1);
#endif

    os::process::CheckConsole();

    if (!os::registry::Init())
        LOGN_WARNING("OS does not support registry.");

    os::logger::Init();

#ifdef _WIN32
    // Install an unhandled exception filter to log crash code/address and recent kernel imports.
    static auto MwUnhandledException = [](EXCEPTION_POINTERS* ep) -> LONG {
        const DWORD code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
        const void* addr = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;
        LOGFN_ERROR("[crash] unhandled exception code=0x{:08X} addr={} tid={:08X}", (unsigned)code, addr, GetCurrentThreadId());
        KernelTraceDumpRecent(32);
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
    if (entry == 0)
    {
        // LdrLoadModule already displayed a message box with details.
        if (verbose) { printf("[boot][error] Module load failed; exiting.\n"); fflush(stdout); }
        std::_Exit(1);
    }

    if (!runInstallerWizard)
    {
        if (!Video::CreateHostDevice(sdlVideoDriver, graphicsApiRetry))
        {
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), Localise("Video_BackendError").c_str(), GameWindow::s_pWindow);
            std::_Exit(1);
        }

        // Optional heartbeat: present once or twice immediately to verify renderer path
        if (const char* hb = std::getenv("MW05_FORCE_PRESENT"))
        {
            if (!(hb[0] == '0' && hb[1] == '\0'))
            {
                Video::Present();
            }
        }
    }

    Video::StartPipelinePrecompilation();

    // MW'05 runtime function mappings for small PPC shims
    extern void sub_8243B618(PPCContext& __restrict ctx, uint8_t* base);
    g_memory.InsertFunction(0x8243B618, sub_8243B618);

    // TLS dispatcher function pointer used by MW'05 early init (KeTlsAlloc equivalent)
    extern uint32_t KeTlsAlloc();
    g_memory.InsertFunction(0x826BE2A8, HostToGuestFunction<KeTlsAlloc>);

    // Start the guest main thread
    // Kick the guest entry on a dedicated host thread so the UI thread keeps pumping events
    GuestThread::Start({ entry, 0, 0 }, nullptr);

    // Optional continuous present (safe, main-thread only)
    const bool force_present_main = []{
        if (const char* v = std::getenv("MW05_FORCE_PRESENT"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();

    // Keep the main thread alive and pump SDL events to avoid an unresponsive window
    // while the guest initializes. Optionally present to keep swapchain/fps moving.
    using namespace std::chrono;
    auto next_present = steady_clock::now();
    const auto present_period = milliseconds(16);
    for (;;) {
        // Block briefly for events to reduce CPU and keep message pump serviced
        SDL_Event ev;
        (void)SDL_WaitEventTimeout(&ev, 16);
        // Drain any remaining events; GameWindow installs an event watch to handle them.
        while (SDL_PollEvent(&ev)) { /* no-op; watchers handle */ }
        // Allow window bookkeeping (size/position/title) to update
        GameWindow::Update();

        if (force_present_main) {
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
