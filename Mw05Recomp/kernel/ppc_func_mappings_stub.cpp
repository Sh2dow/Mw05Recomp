// Builds only when Unleashed is disabled to satisfy references.
#ifndef MW05_ENABLE_UNLEASHED
struct PPCFuncMapping { unsigned int guest; void* host; };
extern "C" PPCFuncMapping* PPCFuncMappings = nullptr;
#endif
