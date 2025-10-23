#pragma once
#include <vector>
#include <functional>
#include <string>

/**
 * Centralized Initialization Manager
 * 
 * This class provides a safe, controlled way to register initialization callbacks
 * that need to run after the memory subsystem is ready. It solves the static
 * initialization order fiasco by deferring all hook registrations until main().
 * 
 * Usage:
 *   1. In your module, register an initialization callback:
 *      REGISTER_INIT_CALLBACK("MyModule", []() {
 *          g_memory.InsertFunction(0x12345678, MyFunction);
 *      });
 * 
 *   2. In main(), call InitManager::RunAll() after g_memory is initialized
 * 
 * Benefits:
 *   - No static initialization order issues
 *   - Clear dependency management
 *   - Easy to debug (can log all registrations)
 *   - Thread-safe registration
 *   - Graceful error handling
 */
class InitManager
{
public:
    using InitCallback = std::function<void()>;

    struct InitEntry
    {
        std::string name;
        InitCallback callback;
        int priority;  // Lower numbers run first (default: 100)
    };

    // Get the singleton instance (thread-safe in C++11+)
    static InitManager& Instance()
    {
        static InitManager instance;
        return instance;
    }

    // Register an initialization callback
    // Priority: Lower numbers run first (default: 100)
    // Common priorities:
    //   0-49:   Critical system initialization (memory, heap)
    //   50-99:  Core subsystems (file system, kernel)
    //   100-149: Game hooks and patches (default)
    //   150-199: Optional features
    void Register(const char* name, InitCallback callback, int priority = 100)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (has_run_) {
            fprintf(stderr, "[INIT-MGR] WARNING: Registering '%s' after initialization has already run!\n", name);
            fprintf(stderr, "[INIT-MGR]          Running callback immediately...\n");
            fflush(stderr);
            
            try {
                callback();
                fprintf(stderr, "[INIT-MGR] ✓ '%s' (late registration)\n", name);
            } catch (const std::exception& e) {
                fprintf(stderr, "[INIT-MGR] ✗ '%s' FAILED: %s\n", name, e.what());
            }
            fflush(stderr);
            return;
        }

        entries_.push_back({name, callback, priority});
        fprintf(stderr, "[INIT-MGR] Registered: '%s' (priority: %d)\n", name, priority);
        fflush(stderr);
    }

    // Run all registered callbacks in priority order
    void RunAll()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (has_run_) {
            fprintf(stderr, "[INIT-MGR] WARNING: RunAll() called multiple times! Ignoring...\n");
            fflush(stderr);
            return;
        }

        fprintf(stderr, "[INIT-MGR] ========================================\n");
        fprintf(stderr, "[INIT-MGR] Running %zu initialization callbacks...\n", entries_.size());
        fprintf(stderr, "[INIT-MGR] ========================================\n");
        fflush(stderr);

        // Sort by priority (lower numbers first)
        std::sort(entries_.begin(), entries_.end(), 
            [](const InitEntry& a, const InitEntry& b) {
                return a.priority < b.priority;
            });

        size_t succeeded = 0;
        size_t failed = 0;

        for (const auto& entry : entries_) {
            fprintf(stderr, "[INIT-MGR] Running: '%s' (priority: %d)...\n", 
                    entry.name.c_str(), entry.priority);
            fflush(stderr);

            try {
                entry.callback();
                succeeded++;
                fprintf(stderr, "[INIT-MGR] ✓ '%s' completed successfully\n", entry.name.c_str());
            } catch (const std::exception& e) {
                failed++;
                fprintf(stderr, "[INIT-MGR] ✗ '%s' FAILED: %s\n", entry.name.c_str(), e.what());
            } catch (...) {
                failed++;
                fprintf(stderr, "[INIT-MGR] ✗ '%s' FAILED: Unknown exception\n", entry.name.c_str());
            }
            fflush(stderr);
        }

        fprintf(stderr, "[INIT-MGR] ========================================\n");
        fprintf(stderr, "[INIT-MGR] Initialization complete: %zu succeeded, %zu failed\n", 
                succeeded, failed);
        fprintf(stderr, "[INIT-MGR] ========================================\n");
        fflush(stderr);

        has_run_ = true;
    }

    // Check if initialization has run
    bool HasRun() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return has_run_;
    }

    // Get count of registered callbacks
    size_t Count() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

private:
    InitManager() = default;
    ~InitManager() = default;
    
    // Prevent copying
    InitManager(const InitManager&) = delete;
    InitManager& operator=(const InitManager&) = delete;

    std::vector<InitEntry> entries_;
    mutable std::mutex mutex_;
    bool has_run_ = false;
};

// Convenience macro for registering initialization callbacks
#define REGISTER_INIT_CALLBACK(name, callback) \
    static struct InitRegistrar_##__LINE__ { \
        InitRegistrar_##__LINE__() { \
            InitManager::Instance().Register(name, callback); \
        } \
    } init_registrar_##__LINE__;

// Convenience macro with priority
#define REGISTER_INIT_CALLBACK_PRIORITY(name, priority, callback) \
    static struct InitRegistrar_##__LINE__ { \
        InitRegistrar_##__LINE__() { \
            InitManager::Instance().Register(name, callback, priority); \
        } \
    } init_registrar_##__LINE__;

