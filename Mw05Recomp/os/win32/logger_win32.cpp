#include <os/logger.h>
#include <os/process.h>
#include <cstdio>
#include <mutex>
#include <cstdlib>
#include <chrono>
#include <ctime>
#include <io.h>

#define FOREGROUND_WHITE  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)

static HANDLE g_hStandardOutput;
static FILE* g_logFile = nullptr;
static bool g_logFlush = false;
static bool g_forceConsole = true;
static std::mutex g_logMutex;

static bool EnvYes(const char* name)
{
    const char* v = std::getenv(name);
    if (!v) return false;
    if (v[0]=='0' && v[1]=='\0') return false;
    return true;
}

static void WriteFileLine(const char* type, const char* func, const std::string_view& str)
{
    if (!g_logFile) return;
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    char ts[32];
    std::snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec, (int)ms.count());
    if (func)
        std::fprintf(g_logFile, "%s [%s] [%s] %.*s\n", ts, type, func, (int)str.size(), str.data());
    else
        std::fprintf(g_logFile, "%s [%s] %.*s\n", ts, type, (int)str.size(), str.data());
    if (g_logFlush)
    {
        std::fflush(g_logFile);
        int fd = _fileno(g_logFile);
        if (fd >= 0)
        {
            _commit(fd);
            intptr_t osfh = _get_osfhandle(fd);
            if (osfh != -1)
            {
                FlushFileBuffers(reinterpret_cast<HANDLE>(osfh));
            }
        }
    }
}

void os::logger::Init()
{
    g_hStandardOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    // Optional file logging
    const char* path = std::getenv("MW05_LOG_FILE");
    if (path && path[0])
    {
        const bool append = EnvYes("MW05_LOG_APPEND");
        g_logFlush = EnvYes("MW05_LOG_FLUSH");
        g_logFile = std::fopen(path, append ? "ab" : "wb");
    }
    // Allow disabling console output via env
    if (const char* v = std::getenv("MW05_LOG_CONSOLE"))
    {
        g_forceConsole = !(v[0]=='0' && v[1]=='\0');
    }
}

void os::logger::Log(const std::string_view str, ELogType type, const char* func)
{
    const bool consoleVisible = os::process::g_consoleVisible && g_forceConsole;

    std::lock_guard<std::mutex> lk(g_logMutex);

    if (consoleVisible)
    {
        switch (type)
        {
            case ELogType::Utility:
                SetConsoleTextAttribute(g_hStandardOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                break;
            case ELogType::Warning:
                SetConsoleTextAttribute(g_hStandardOutput, FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
                break;
            case ELogType::Error:
                SetConsoleTextAttribute(g_hStandardOutput, FOREGROUND_RED | FOREGROUND_INTENSITY);
                break;
            default:
                SetConsoleTextAttribute(g_hStandardOutput, FOREGROUND_WHITE);
                break;
        }
        if (func)
            fmt::println("[{}] {}", func, str);
        else
            fmt::println("{}", str);
        SetConsoleTextAttribute(g_hStandardOutput, FOREGROUND_WHITE);
    }

    // File sink
    const char* type_name = (type == ELogType::Error) ? "ERR" : (type == ELogType::Warning) ? "WRN" : (type == ELogType::Utility) ? "DBG" : "LOG";
    WriteFileLine(type_name, func, str);
}
