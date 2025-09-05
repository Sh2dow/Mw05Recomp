#include <os/logger.h>
#include <cstdio>
#include <mutex>
#include <cstdlib>
#include <chrono>
#include <ctime>
#include <unistd.h>

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
    localtime_r(&t, &tm);
    char ts[32];
    std::snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec, (int)ms.count());
    if (func)
        std::fprintf(g_logFile, "%s [%s] [%s] %.*s\n", ts, type, func, (int)str.size(), str.data());
    else
        std::fprintf(g_logFile, "%s [%s] %.*s\n", ts, type, (int)str.size(), str.data());
    if (g_logFlush)
    {
        std::fflush(g_logFile);
        fsync(fileno(g_logFile));
    }
}

void os::logger::Init()
{
    const char* path = std::getenv("MW05_LOG_FILE");
    if (path && path[0])
    {
        const bool append = EnvYes("MW05_LOG_APPEND");
        g_logFlush = EnvYes("MW05_LOG_FLUSH");
        g_logFile = std::fopen(path, append ? "ab" : "wb");
    }
    if (const char* v = std::getenv("MW05_LOG_CONSOLE"))
    {
        g_forceConsole = !(v[0]=='0' && v[1]=='\0');
    }
}

void os::logger::Log(const std::string_view str, ELogType type, const char* func)
{
    std::lock_guard<std::mutex> lk(g_logMutex);
    if (g_forceConsole)
    {
        if (func) fmt::println("[{}] {}", func, str);
        else      fmt::println("{}", str);
    }
    const char* type_name = (type == ELogType::Error) ? "ERR" : (type == ELogType::Warning) ? "WRN" : (type == ELogType::Utility) ? "DBG" : "LOG";
    WriteFileLine(type_name, func, str);
}
