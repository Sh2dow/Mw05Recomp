#pragma once

#include <string>
#include <vector>
#include <atomic>

// Debug Console - Runtime control of debug settings
// Press ` (backtick) or F1 to toggle console
// 
// Commands:
//   debug.graphics 0|1|2|3    - Set graphics verbosity (0=off, 1=minimal, 2=normal, 3=verbose)
//   debug.pm4 0|1|2|3         - Set PM4 verbosity
//   debug.kernel 0|1|2|3      - Set kernel verbosity
//   debug.thread 0|1|2|3      - Set thread verbosity
//   debug.heap 0|1|2|3        - Set heap verbosity
//   debug.fileio 0|1|2|3      - Set file I/O verbosity
//   trace.start [file]        - Start trace logging
//   trace.stop                - Stop trace logging
//   trace.vdswap on|off       - Enable/disable VdSwap tracing
//   pm4.dump [count]          - Dump PM4 ring buffer (last N packets, default 100)
//   pm4.stats                 - Show PM4 statistics (total packets, draws, etc.)
//   pm4.opcodes               - Show PM4 opcode histogram
//   heap.stats                - Show heap statistics (user + physical)
//   thread.list               - List all threads with status
//   vdswap.break              - Break into debugger on next VdSwap call
//   vdswap.log                - Log next 10 VdSwap calls with full context
//   break <address>           - Break into debugger at address (hex)
//   watch <address>           - Watch memory address for changes
//   help                      - Show all commands
//   clear                     - Clear console output

namespace DebugConsole {

// Initialize debug console (call once at startup)
void Init();

// Render debug console (call every frame)
void Render();

// Toggle console visibility
void Toggle();

// Check if console is visible
bool IsVisible();

// Execute a command (for programmatic use)
void ExecuteCommand(const char* cmd);

// Runtime debug settings (replaces environment variables)
struct Settings {
    // Verbosity levels (0=off, 1=minimal, 2=normal, 3=verbose)
    std::atomic<int> graphics_verbosity{1};
    std::atomic<int> pm4_verbosity{1};
    std::atomic<int> kernel_verbosity{1};
    std::atomic<int> thread_verbosity{1};
    std::atomic<int> heap_verbosity{1};
    std::atomic<int> fileio_verbosity{1};
    
    // Trace control
    std::atomic<bool> trace_imports{false};
    std::atomic<bool> trace_hostops{false};
    std::atomic<bool> trace_vdswap{false};
    std::atomic<bool> trace_pm4{false};
    
    // PM4 control
    std::atomic<bool> pm4_scan_all{true};
    std::atomic<bool> pm4_apply_state{true};
    std::atomic<bool> pm4_emit_draws{true};
    
    // File I/O control
    std::atomic<bool> stream_bridge{true};
    
    // Initialize from environment variables (for backward compatibility)
    void InitFromEnvironment();
    
    // Load/save profiles
    void LoadProfile(const char* name);  // "minimal", "normal", "verbose", "pm4", "fileio"
};

// Global settings instance
extern Settings g_settings;

// Get verbosity level (for use in DEBUG_LOG_* macros)
inline int GetGraphicsVerbosity() { return g_settings.graphics_verbosity.load(std::memory_order_relaxed); }
inline int GetPM4Verbosity() { return g_settings.pm4_verbosity.load(std::memory_order_relaxed); }
inline int GetKernelVerbosity() { return g_settings.kernel_verbosity.load(std::memory_order_relaxed); }
inline int GetThreadVerbosity() { return g_settings.thread_verbosity.load(std::memory_order_relaxed); }
inline int GetHeapVerbosity() { return g_settings.heap_verbosity.load(std::memory_order_relaxed); }
inline int GetFileIOVerbosity() { return g_settings.fileio_verbosity.load(std::memory_order_relaxed); }

} // namespace DebugConsole

