#include "debug_console.h"
#include <imgui.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>

// Forward declarations for debugging functions
// TODO: Implement these functions in their respective modules
// namespace PM4 {
//     void DumpRingBuffer(int count);
//     void ShowStats();
//     void ShowOpcodeHistogram();
// }
//
// namespace Heap {
//     void ShowStats();
// }
//
// namespace Thread {
//     void ListThreads();
// }
//
// namespace VdSwap {
//     void EnableBreakOnNext();
//     void EnableLogging(int count);
// }

namespace DebugConsole {

// Global settings instance
Settings g_settings;

// Console state
static bool s_isVisible = false;
static char s_inputBuffer[256] = "";
static std::vector<std::string> s_output;
static std::vector<std::string> s_history;
static int s_historyIndex = -1;
static bool s_scrollToBottom = false;
static bool s_reclaimFocus = false;

// Initialize settings from environment variables (backward compatibility)
void Settings::InitFromEnvironment() {
    // Verbosity levels
    if (const char* v = std::getenv("MW05_DEBUG_GRAPHICS")) {
        graphics_verbosity.store(std::atoi(v), std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_DEBUG_PM4")) {
        pm4_verbosity.store(std::atoi(v), std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_DEBUG_KERNEL")) {
        kernel_verbosity.store(std::atoi(v), std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_DEBUG_THREAD")) {
        thread_verbosity.store(std::atoi(v), std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_DEBUG_HEAP")) {
        heap_verbosity.store(std::atoi(v), std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_DEBUG_FILEIO")) {
        fileio_verbosity.store(std::atoi(v), std::memory_order_relaxed);
    }
    
    // Trace control
    if (const char* v = std::getenv("MW05_HOST_TRACE_IMPORTS")) {
        trace_imports.store(v[0] != '0', std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_HOST_TRACE_HOSTOPS")) {
        trace_hostops.store(v[0] != '0', std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_PM4_TRACE")) {
        trace_pm4.store(v[0] != '0', std::memory_order_relaxed);
    }
    
    // PM4 control
    if (const char* v = std::getenv("MW05_PM4_SCAN_ALL")) {
        pm4_scan_all.store(v[0] != '0', std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_PM4_APPLY_STATE")) {
        pm4_apply_state.store(v[0] != '0', std::memory_order_relaxed);
    }
    if (const char* v = std::getenv("MW05_PM4_EMIT_DRAWS")) {
        pm4_emit_draws.store(v[0] != '0', std::memory_order_relaxed);
    }
    
    // File I/O control
    if (const char* v = std::getenv("MW05_STREAM_BRIDGE")) {
        stream_bridge.store(v[0] != '0', std::memory_order_relaxed);
    }
}

// Load a debug profile
void Settings::LoadProfile(const char* name) {
    if (strcmp(name, "minimal") == 0) {
        graphics_verbosity.store(0, std::memory_order_relaxed);
        pm4_verbosity.store(0, std::memory_order_relaxed);
        kernel_verbosity.store(0, std::memory_order_relaxed);
        thread_verbosity.store(0, std::memory_order_relaxed);
        heap_verbosity.store(0, std::memory_order_relaxed);
        fileio_verbosity.store(0, std::memory_order_relaxed);
        trace_imports.store(false, std::memory_order_relaxed);
        trace_hostops.store(false, std::memory_order_relaxed);
        trace_pm4.store(false, std::memory_order_relaxed);
    } else if (strcmp(name, "normal") == 0) {
        graphics_verbosity.store(1, std::memory_order_relaxed);
        pm4_verbosity.store(1, std::memory_order_relaxed);
        kernel_verbosity.store(1, std::memory_order_relaxed);
        thread_verbosity.store(1, std::memory_order_relaxed);
        heap_verbosity.store(1, std::memory_order_relaxed);
        fileio_verbosity.store(1, std::memory_order_relaxed);
        trace_imports.store(false, std::memory_order_relaxed);
        trace_hostops.store(false, std::memory_order_relaxed);
        trace_pm4.store(false, std::memory_order_relaxed);
    } else if (strcmp(name, "verbose") == 0) {
        graphics_verbosity.store(3, std::memory_order_relaxed);
        pm4_verbosity.store(3, std::memory_order_relaxed);
        kernel_verbosity.store(3, std::memory_order_relaxed);
        thread_verbosity.store(3, std::memory_order_relaxed);
        heap_verbosity.store(3, std::memory_order_relaxed);
        fileio_verbosity.store(3, std::memory_order_relaxed);
        trace_imports.store(true, std::memory_order_relaxed);
        trace_hostops.store(true, std::memory_order_relaxed);
        trace_pm4.store(true, std::memory_order_relaxed);
    } else if (strcmp(name, "pm4") == 0) {
        graphics_verbosity.store(1, std::memory_order_relaxed);
        pm4_verbosity.store(3, std::memory_order_relaxed);
        kernel_verbosity.store(1, std::memory_order_relaxed);
        thread_verbosity.store(1, std::memory_order_relaxed);
        heap_verbosity.store(1, std::memory_order_relaxed);
        fileio_verbosity.store(1, std::memory_order_relaxed);
        trace_pm4.store(true, std::memory_order_relaxed);
    } else if (strcmp(name, "fileio") == 0) {
        graphics_verbosity.store(1, std::memory_order_relaxed);
        pm4_verbosity.store(1, std::memory_order_relaxed);
        kernel_verbosity.store(1, std::memory_order_relaxed);
        thread_verbosity.store(1, std::memory_order_relaxed);
        heap_verbosity.store(1, std::memory_order_relaxed);
        fileio_verbosity.store(3, std::memory_order_relaxed);
        trace_hostops.store(true, std::memory_order_relaxed);
    }
}

// Helper to add output line
static void AddOutput(const char* text) {
    s_output.push_back(text);
    s_scrollToBottom = true;
    
    // Limit output buffer to 1000 lines
    if (s_output.size() > 1000) {
        s_output.erase(s_output.begin());
    }
}

// Helper to parse integer argument
static bool ParseInt(const char* str, int& out) {
    char* end;
    long val = std::strtol(str, &end, 10);
    if (end == str || *end != '\0') {
        return false;
    }
    out = static_cast<int>(val);
    return true;
}

// Execute a command
void ExecuteCommand(const char* cmd) {
    // Add to history
    if (cmd[0] != '\0') {
        s_history.push_back(cmd);
        s_historyIndex = -1;
    }
    
    // Echo command
    char buf[512];
    snprintf(buf, sizeof(buf), "> %s", cmd);
    AddOutput(buf);
    
    // Parse command
    char cmdCopy[256];
    strncpy(cmdCopy, cmd, sizeof(cmdCopy) - 1);
    cmdCopy[sizeof(cmdCopy) - 1] = '\0';
    
    char* token = strtok(cmdCopy, " ");
    if (!token) {
        return;
    }
    
    // Handle commands
    if (strcmp(token, "help") == 0) {
        AddOutput("Available commands:");
        AddOutput("  debug.graphics 0|1|2|3  - Set graphics verbosity");
        AddOutput("  debug.pm4 0|1|2|3       - Set PM4 verbosity");
        AddOutput("  debug.kernel 0|1|2|3    - Set kernel verbosity");
        AddOutput("  debug.thread 0|1|2|3    - Set thread verbosity");
        AddOutput("  debug.heap 0|1|2|3      - Set heap verbosity");
        AddOutput("  debug.fileio 0|1|2|3    - Set file I/O verbosity");
        AddOutput("  profile minimal|normal|verbose|pm4|fileio - Load debug profile");
        AddOutput("  trace.vdswap on|off     - Enable/disable VdSwap tracing");
        AddOutput("  trace.pm4 on|off        - Enable/disable PM4 tracing");
        AddOutput("  pm4.dump [count]        - Dump PM4 ring buffer (last N packets)");
        AddOutput("  pm4.stats               - Show PM4 statistics");
        AddOutput("  pm4.opcodes             - Show PM4 opcode histogram");
        AddOutput("  heap.stats              - Show heap statistics");
        AddOutput("  thread.list             - List all threads");
        AddOutput("  vdswap.break            - Break into debugger on next VdSwap");
        AddOutput("  vdswap.log              - Log next 10 VdSwap calls");
        AddOutput("  status                  - Show current settings");
        AddOutput("  clear                   - Clear console output");
        AddOutput("  help                    - Show this help");
    } else if (strcmp(token, "clear") == 0) {
        s_output.clear();
    } else if (strcmp(token, "status") == 0) {
        snprintf(buf, sizeof(buf), "Graphics verbosity: %d", g_settings.graphics_verbosity.load());
        AddOutput(buf);
        snprintf(buf, sizeof(buf), "PM4 verbosity: %d", g_settings.pm4_verbosity.load());
        AddOutput(buf);
        snprintf(buf, sizeof(buf), "Kernel verbosity: %d", g_settings.kernel_verbosity.load());
        AddOutput(buf);
        snprintf(buf, sizeof(buf), "Thread verbosity: %d", g_settings.thread_verbosity.load());
        AddOutput(buf);
        snprintf(buf, sizeof(buf), "Heap verbosity: %d", g_settings.heap_verbosity.load());
        AddOutput(buf);
        snprintf(buf, sizeof(buf), "File I/O verbosity: %d", g_settings.fileio_verbosity.load());
        AddOutput(buf);
        snprintf(buf, sizeof(buf), "VdSwap tracing: %s", g_settings.trace_vdswap.load() ? "ON" : "OFF");
        AddOutput(buf);
        snprintf(buf, sizeof(buf), "PM4 tracing: %s", g_settings.trace_pm4.load() ? "ON" : "OFF");
        AddOutput(buf);
    } else if (strcmp(token, "profile") == 0) {
        char* profile = strtok(nullptr, " ");
        if (!profile) {
            AddOutput("Error: profile name required (minimal|normal|verbose|pm4|fileio)");
        } else {
            g_settings.LoadProfile(profile);
            snprintf(buf, sizeof(buf), "Loaded profile: %s", profile);
            AddOutput(buf);
        }
    } else if (strncmp(token, "debug.", 6) == 0) {
        const char* subsystem = token + 6;
        char* value = strtok(nullptr, " ");
        if (!value) {
            AddOutput("Error: verbosity level required (0|1|2|3)");
            return;
        }
        
        int level;
        if (!ParseInt(value, level) || level < 0 || level > 3) {
            AddOutput("Error: verbosity level must be 0, 1, 2, or 3");
            return;
        }
        
        if (strcmp(subsystem, "graphics") == 0) {
            g_settings.graphics_verbosity.store(level, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "Graphics verbosity set to %d", level);
            AddOutput(buf);
        } else if (strcmp(subsystem, "pm4") == 0) {
            g_settings.pm4_verbosity.store(level, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "PM4 verbosity set to %d", level);
            AddOutput(buf);
        } else if (strcmp(subsystem, "kernel") == 0) {
            g_settings.kernel_verbosity.store(level, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "Kernel verbosity set to %d", level);
            AddOutput(buf);
        } else if (strcmp(subsystem, "thread") == 0) {
            g_settings.thread_verbosity.store(level, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "Thread verbosity set to %d", level);
            AddOutput(buf);
        } else if (strcmp(subsystem, "heap") == 0) {
            g_settings.heap_verbosity.store(level, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "Heap verbosity set to %d", level);
            AddOutput(buf);
        } else if (strcmp(subsystem, "fileio") == 0) {
            g_settings.fileio_verbosity.store(level, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "File I/O verbosity set to %d", level);
            AddOutput(buf);
        } else {
            snprintf(buf, sizeof(buf), "Error: unknown subsystem '%s'", subsystem);
            AddOutput(buf);
        }
    } else if (strncmp(token, "trace.", 6) == 0) {
        const char* subsystem = token + 6;
        char* value = strtok(nullptr, " ");
        if (!value) {
            AddOutput("Error: value required (on|off)");
            return;
        }
        
        bool enable = (strcmp(value, "on") == 0 || strcmp(value, "1") == 0);
        
        if (strcmp(subsystem, "vdswap") == 0) {
            g_settings.trace_vdswap.store(enable, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "VdSwap tracing %s", enable ? "enabled" : "disabled");
            AddOutput(buf);
        } else if (strcmp(subsystem, "pm4") == 0) {
            g_settings.trace_pm4.store(enable, std::memory_order_relaxed);
            snprintf(buf, sizeof(buf), "PM4 tracing %s", enable ? "enabled" : "disabled");
            AddOutput(buf);
        } else {
            snprintf(buf, sizeof(buf), "Error: unknown trace subsystem '%s'", subsystem);
            AddOutput(buf);
        }
    } else if (strncmp(token, "pm4.", 4) == 0) {
        // TODO: Implement PM4 debugging functions
        AddOutput("PM4 commands not yet implemented");
    } else if (strncmp(token, "heap.", 5) == 0) {
        // TODO: Implement heap debugging functions
        AddOutput("Heap commands not yet implemented");
    } else if (strncmp(token, "thread.", 7) == 0) {
        // TODO: Implement thread debugging functions
        AddOutput("Thread commands not yet implemented");
    } else if (strncmp(token, "vdswap.", 7) == 0) {
        // TODO: Implement VdSwap debugging functions
        AddOutput("VdSwap commands not yet implemented");
    } else {
        snprintf(buf, sizeof(buf), "Error: unknown command '%s' (type 'help' for list)", token);
        AddOutput(buf);
    }
}

void Init() {
    // Initialize settings from environment variables
    g_settings.InitFromEnvironment();
    
    // Add welcome message
    AddOutput("MW05 Debug Console");
    AddOutput("Type 'help' for list of commands");
    AddOutput("Press ` or F1 to toggle console");
    AddOutput("");
}

void Toggle() {
    s_isVisible = !s_isVisible;
    if (s_isVisible) {
        s_reclaimFocus = true;
    }
}

bool IsVisible() {
    return s_isVisible;
}

void Render() {
    if (!s_isVisible) {
        return;
    }
    
    // Set window size and position
    ImGui::SetNextWindowSize(ImVec2(800, 400), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
    
    if (!ImGui::Begin("Debug Console", &s_isVisible, ImGuiWindowFlags_NoCollapse)) {
        ImGui::End();
        return;
    }
    
    // Output area
    const float footer_height = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height), false, ImGuiWindowFlags_HorizontalScrollbar);
    
    for (const auto& line : s_output) {
        ImGui::TextUnformatted(line.c_str());
    }
    
    if (s_scrollToBottom) {
        ImGui::SetScrollHereY(1.0f);
        s_scrollToBottom = false;
    }
    
    ImGui::EndChild();
    
    // Input area
    ImGui::Separator();
    
    bool reclaim_focus = false;
    ImGuiInputTextFlags input_flags = ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory;
    
    auto input_callback = [](ImGuiInputTextCallbackData* data) -> int {
        if (data->EventFlag == ImGuiInputTextFlags_CallbackHistory) {
            const int prev_history_index = s_historyIndex;
            if (data->EventKey == ImGuiKey_UpArrow) {
                if (s_historyIndex == -1) {
                    s_historyIndex = static_cast<int>(s_history.size()) - 1;
                } else if (s_historyIndex > 0) {
                    s_historyIndex--;
                }
            } else if (data->EventKey == ImGuiKey_DownArrow) {
                if (s_historyIndex != -1) {
                    s_historyIndex++;
                    if (s_historyIndex >= static_cast<int>(s_history.size())) {
                        s_historyIndex = -1;
                    }
                }
            }
            
            if (prev_history_index != s_historyIndex) {
                const char* history_str = (s_historyIndex >= 0) ? s_history[s_historyIndex].c_str() : "";
                data->DeleteChars(0, data->BufTextLen);
                data->InsertChars(0, history_str);
            }
        }
        return 0;
    };
    
    if (ImGui::InputText("Input", s_inputBuffer, sizeof(s_inputBuffer), input_flags, input_callback)) {
        ExecuteCommand(s_inputBuffer);
        s_inputBuffer[0] = '\0';
        reclaim_focus = true;
    }
    
    ImGui::SetItemDefaultFocus();
    if (reclaim_focus || s_reclaimFocus) {
        ImGui::SetKeyboardFocusHere(-1);
        s_reclaimFocus = false;
    }
    
    ImGui::End();
}

} // namespace DebugConsole

