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

// Get statistics
uint64_t PM4_GetDrawCount();
uint64_t PM4_GetPacketCount();
void PM4_ResetStats();

