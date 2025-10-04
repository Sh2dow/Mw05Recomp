#pragma once
#include <cstdint>

// Minimal MW05 micro-IB interpreter entrypoint. The format begins with 'MW05' (BE) and
// is followed by a small prelude. This function will evolve to translate micro ops
// into host RenderCommands. For now it ensures a visible frame and structured logging.
extern "C" void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size);

