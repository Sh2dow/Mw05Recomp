#pragma once

#include <cstdint>

// PM4 packet parser for MW05 ring buffer commands
// Intercepts ring buffer writes and logs PM4 draw commands

// Initialize PM4 parser with ring buffer info
void PM4_SetRingBuffer(uint32_t base, uint32_t size_log2);

// Called when ring buffer write pointer is updated (from VdSwap)
void PM4_OnRingBufferWrite(uint32_t writePtr);

// Called when ring buffer write is detected (from TraceRbWrite)
void PM4_OnRingBufferWriteAddr(uint32_t writeAddr, size_t writeSize);

// Optional: debug scan of entire ring when normal triggers are missing (env-gated)
void PM4_DebugScanAll();

// Force debug scan regardless of env gating (used for auto-diagnosis)
void PM4_DebugScanAll_Force();

// Scan a linear buffer for PM4 packets (used to inspect system command buffer)
void PM4_ScanLinear(uint32_t addr, uint32_t bytes);

// Get statistics
uint64_t PM4_GetDrawCount();
uint64_t PM4_GetPacketCount();
void PM4_ResetStats();



// Debug: dump histogram of observed PM4 TYPE3 opcodes
void PM4_DumpOpcodeHistogram();
