#pragma once

// Check if there are pending APCs for the current thread
bool ApcPendingForCurrentThread();

// Process pending APCs for the current thread
// Returns true if any APCs were processed
bool ProcessPendingApcs();
