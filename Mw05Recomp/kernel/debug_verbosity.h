#pragma once

#include <cstdlib>
#include <atomic>

// Debug verbosity control system
// Allows fine-grained control over debug logging to reduce spam
// Set environment variables to control verbosity levels (0=off, 1=minimal, 2=normal, 3=verbose)

namespace DebugVerbosity {

// Verbosity levels
enum Level {
    OFF = 0,      // No logging
    MINIMAL = 1,  // Only critical events (errors, first-time events)
    NORMAL = 2,   // Important events (changes, state transitions)
    VERBOSE = 3   // All events (including "no change" messages)
};

// Get verbosity level from environment variable
// Returns MINIMAL by default (only log important events)
inline Level GetLevel(const char* env_var, Level default_level = MINIMAL) {
    static thread_local std::atomic<int> s_cache{-1};
    
    int cached = s_cache.load(std::memory_order_relaxed);
    if (cached >= 0) {
        return static_cast<Level>(cached);
    }
    
    const char* env = std::getenv(env_var);
    Level level = default_level;
    
    if (env) {
        int val = std::atoi(env);
        if (val >= OFF && val <= VERBOSE) {
            level = static_cast<Level>(val);
        }
    }
    
    s_cache.store(static_cast<int>(level), std::memory_order_relaxed);
    return level;
}

// Specific subsystem verbosity controls
inline Level GetGraphicsVerbosity() {
    return GetLevel("MW05_DEBUG_GRAPHICS", MINIMAL);
}

inline Level GetKernelVerbosity() {
    return GetLevel("MW05_DEBUG_KERNEL", MINIMAL);
}

inline Level GetThreadVerbosity() {
    return GetLevel("MW05_DEBUG_THREAD", MINIMAL);
}

inline Level GetHeapVerbosity() {
    return GetLevel("MW05_DEBUG_HEAP", MINIMAL);
}

inline Level GetFileIOVerbosity() {
    return GetLevel("MW05_DEBUG_FILEIO", MINIMAL);
}

inline Level GetPM4Verbosity() {
    return GetLevel("MW05_DEBUG_PM4", MINIMAL);
}

// Helper macros for conditional logging
#define DEBUG_LOG_IF(subsystem, level, ...) \
    do { \
        if (DebugVerbosity::Get##subsystem##Verbosity() >= DebugVerbosity::level) { \
            fprintf(stderr, __VA_ARGS__); \
            fflush(stderr); \
        } \
    } while(0)

#define DEBUG_LOG_GRAPHICS(level, ...) DEBUG_LOG_IF(Graphics, level, __VA_ARGS__)
#define DEBUG_LOG_KERNEL(level, ...) DEBUG_LOG_IF(Kernel, level, __VA_ARGS__)
#define DEBUG_LOG_THREAD(level, ...) DEBUG_LOG_IF(Thread, level, __VA_ARGS__)
#define DEBUG_LOG_HEAP(level, ...) DEBUG_LOG_IF(Heap, level, __VA_ARGS__)
#define DEBUG_LOG_FILEIO(level, ...) DEBUG_LOG_IF(FileIO, level, __VA_ARGS__)
#define DEBUG_LOG_PM4(level, ...) DEBUG_LOG_IF(PM4, level, __VA_ARGS__)

} // namespace DebugVerbosity

