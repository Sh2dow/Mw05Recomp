// PM4 packet parser for MW05 ring buffer commands
// This intercepts ring buffer writes and logs PM4 draw commands

#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cstdint>
#include <atomic>
#include <cstdlib>

// PM4 packet types (Xbox 360 GPU)
enum PM4Type {
    PM4_TYPE0 = 0,  // Register write
    PM4_TYPE1 = 1,  // Reserved
    PM4_TYPE2 = 2,  // Reserved  
    PM4_TYPE3 = 3   // Command packet
};

// PM4 Type-3 opcodes (common draw commands)
enum PM4Opcode {
    PM4_ME_INIT = 0x48,
    PM4_NOP = 0x10,
    PM4_INDIRECT_BUFFER = 0x3F,
    PM4_WAIT_REG_MEM = 0x3C,
    PM4_REG_RMW = 0x21,
    PM4_COND_WRITE = 0x45,
    PM4_EVENT_WRITE = 0x46,
    PM4_EVENT_WRITE_SHD = 0x58,
    PM4_EVENT_WRITE_CFL = 0x59,
    PM4_EVENT_WRITE_EXT = 0x5A,
    PM4_DRAW_INDX = 0x22,           // Draw indexed primitives
    PM4_DRAW_INDX_2 = 0x36,         // Draw indexed primitives (variant)
    PM4_VIZ_QUERY = 0x23,
    PM4_SET_STATE = 0x25,
    PM4_SET_CONSTANT = 0x2D,
    PM4_LOAD_ALU_CONSTANT = 0x2F,
    PM4_SET_SHADER_CONSTANTS = 0x32,
    PM4_IM_LOAD = 0x27,
    PM4_IM_LOAD_IMMEDIATE = 0x2B,
    PM4_INVALIDATE_STATE = 0x3B,
    PM4_SET_BIN_MASK = 0x50,
    PM4_SET_BIN_SELECT = 0x51,
};

// Ring buffer state
static std::atomic<uint32_t> g_rbBase{0};
static std::atomic<uint32_t> g_rbSize{0};
static std::atomic<uint32_t> g_rbWritePtr{0};

// Statistics
static std::atomic<uint64_t> g_pm4DrawCount{0};
static std::atomic<uint64_t> g_pm4PacketCount{0};

static inline bool IsPM4TracingEnabled() {
    static const bool enabled = []() {
        const char* env = std::getenv("MW05_PM4_TRACE");
        return env && *env && *env != '0';
    }();
    return enabled;
}

void PM4_SetRingBuffer(uint32_t base, uint32_t size_log2) {
    g_rbBase.store(base, std::memory_order_release);
    const uint32_t size = (size_log2 < 32) ? (1u << size_log2) : 0;
    g_rbSize.store(size, std::memory_order_release);
    g_rbWritePtr.store(0, std::memory_order_release);
    
    if (IsPM4TracingEnabled()) {
        KernelTraceHostOpF("HOST.PM4.SetRingBuffer base=%08X size_log2=%u size=%08X", 
                          base, size_log2, size);
    }
}

// Parse a single PM4 packet at the given address
static uint32_t ParsePM4Packet(uint32_t addr) {
    uint32_t* ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(addr));
    if (!ptr) return 4;
    
    uint32_t header = __builtin_bswap32(*ptr);  // Big-endian
    uint32_t type = (header >> 30) & 0x3;
    
    g_pm4PacketCount.fetch_add(1, std::memory_order_relaxed);
    
    if (type == PM4_TYPE3) {
        uint32_t opcode = (header >> 8) & 0x7F;
        uint32_t count = (header >> 16) & 0x3FFF;
        uint32_t size = (count + 2) * 4;  // +1 for header, +1 for count encoding
        
        // Log draw commands
        if (opcode == PM4_DRAW_INDX || opcode == PM4_DRAW_INDX_2) {
            g_pm4DrawCount.fetch_add(1, std::memory_order_relaxed);
            
            if (IsPM4TracingEnabled()) {
                // Read draw parameters
                uint32_t* params = ptr + 1;
                uint32_t p0 = params[0] ? __builtin_bswap32(params[0]) : 0;
                uint32_t p1 = (count >= 1 && params[1]) ? __builtin_bswap32(params[1]) : 0;
                uint32_t p2 = (count >= 2 && params[2]) ? __builtin_bswap32(params[2]) : 0;
                
                KernelTraceHostOpF("HOST.PM4.DRAW_%s addr=%08X count=%u p0=%08X p1=%08X p2=%08X total_draws=%llu",
                                  (opcode == PM4_DRAW_INDX) ? "INDX" : "INDX_2",
                                  addr, count, p0, p1, p2,
                                  (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
            }
        }
        else if (IsPM4TracingEnabled()) {
            // Log other interesting commands
            const char* opname = nullptr;
            switch (opcode) {
                case PM4_SET_CONSTANT: opname = "SET_CONSTANT"; break;
                case PM4_SET_SHADER_CONSTANTS: opname = "SET_SHADER_CONSTANTS"; break;
                case PM4_EVENT_WRITE: opname = "EVENT_WRITE"; break;
                case PM4_WAIT_REG_MEM: opname = "WAIT_REG_MEM"; break;
                case PM4_INDIRECT_BUFFER: opname = "INDIRECT_BUFFER"; break;
                default: break;
            }
            
            if (opname) {
                KernelTraceHostOpF("HOST.PM4.%s addr=%08X count=%u", opname, addr, count);
            }
        }
        
        return size;
    }
    else if (type == PM4_TYPE0) {
        // Register write: count+1 register writes
        uint32_t count = (header >> 16) & 0x3FFF;
        return (count + 2) * 4;
    }
    
    return 4;  // Unknown, skip one dword
}

// Scan ring buffer for PM4 packets when a write is detected
void PM4_ScanRingBuffer(uint32_t writeAddr, size_t writeSize) {
    if (!IsPM4TracingEnabled()) return;

    uint32_t base = g_rbBase.load(std::memory_order_acquire);
    uint32_t size = g_rbSize.load(std::memory_order_acquire);

    if (!base || !size) return;

    // Check if write is within ring buffer
    if (writeAddr < base || writeAddr >= (base + size)) return;

    // Calculate write offset
    uint32_t writeOffset = writeAddr - base;
    uint32_t prevWrite = g_rbWritePtr.exchange(writeOffset, std::memory_order_acq_rel);

    // Only scan if we've moved forward significantly (avoid scanning every tiny write)
    uint32_t delta = (writeOffset >= prevWrite) ? (writeOffset - prevWrite) : (size - prevWrite + writeOffset);
    if (delta < 16) return;  // Skip small writes (less than 4 dwords)

    // Parse packets between prevWrite and writeOffset
    uint32_t offset = prevWrite;
    uint32_t scanned = 0;
    const uint32_t maxScan = 2048;  // Limit scan to prevent infinite loops

    KernelTraceHostOpF("HOST.PM4.Scan.start prev=%04X cur=%04X delta=%u", prevWrite, writeOffset, delta);

    while (offset != writeOffset && scanned < maxScan) {
        uint32_t addr = base + offset;
        uint32_t packetSize = ParsePM4Packet(addr);

        offset = (offset + packetSize) & (size - 1);
        scanned++;
    }

    if (scanned > 0) {
        KernelTraceHostOpF("HOST.PM4.Scan.end prev=%04X cur=%04X scanned=%u draws=%llu",
                          prevWrite, writeOffset, scanned,
                          (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
    }
}

// Hook for ring buffer write pointer updates (called from VdSwap)
void PM4_OnRingBufferWrite(uint32_t writeOffset) {
    if (!IsPM4TracingEnabled()) return;

    uint32_t base = g_rbBase.load(std::memory_order_acquire);
    if (!base) return;

    PM4_ScanRingBuffer(base + writeOffset, 4);
}

// Hook for ring buffer writes (called from TraceRbWrite)
void PM4_OnRingBufferWriteAddr(uint32_t writeAddr, size_t writeSize) {
    PM4_ScanRingBuffer(writeAddr, writeSize);
}

// Get statistics
uint64_t PM4_GetDrawCount() {
    return g_pm4DrawCount.load(std::memory_order_relaxed);
}

uint64_t PM4_GetPacketCount() {
    return g_pm4PacketCount.load(std::memory_order_relaxed);
}

void PM4_ResetStats() {
    g_pm4DrawCount.store(0, std::memory_order_relaxed);
    g_pm4PacketCount.store(0, std::memory_order_relaxed);
}

