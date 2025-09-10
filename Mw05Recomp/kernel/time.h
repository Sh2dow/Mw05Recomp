// KeQuerySystemTime fills a 64-bit 100ns tick count since 1601
// 1) Correct KeQuerySystemTime signature + body
// time.h: void KeQuerySystemTime(be<int64_t>* out_time);
void KeQuerySystemTime(be<int64_t>* out_time) {
    using namespace std::chrono;
    // Windows "system time": 100-ns ticks since 1601-01-01
    constexpr int64_t kFileTimeEpochDiff100ns = 116444736000000000LL; // 1601->1970
    const auto now      = system_clock::now().time_since_epoch();
    const auto now100ns = duration_cast<duration<int64_t, std::ratio<1, 10000000>>>(now).count();
    *out_time = now100ns + kFileTimeEpochDiff100ns;
}

// kernel/time.h  (or near top of imports.cpp)
static inline uint32_t GuestTimeoutToMilliseconds(const be<int64_t>* t)
{
    // NT semantics on 100-ns ticks:
    //   nullptr -> INFINITE
    //   < 0     -> relative delay
    //   = 0     -> zero timeout (poll)
    //   > 0     -> absolute time (ms calculated; caller decides how to interpret)
    if (!t) return INFINITE;

    const int64_t ticks = *t;
    if (ticks == 0) return 0;

    const bool is_relative = ticks < 0;
    uint64_t abs_ticks = is_relative ? (uint64_t)(-ticks) : (uint64_t)ticks;

    // Convert 100-ns to ms, rounding up if non-zero.
    uint32_t ms = (uint32_t)((abs_ticks + 9'999) / 10'000);
    if (ms == 0 && abs_ticks) ms = 1;

    return ms; // (relative vs absolute handled by caller if needed)
}
