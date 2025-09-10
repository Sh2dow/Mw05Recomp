// KeQuerySystemTime fills a 64-bit 100ns tick count since 1601
// 1) Correct KeQuerySystemTime signature + body
void KeQuerySystemTime(be<int64_t>* out_time)
{
    using namespace std::chrono;
    // system_clock is Unix epoch (1970). Convert to 1601 epoch.
    constexpr int64_t EPOCH_DIFF_100NS = 11644473600LL * 10000000LL; // seconds * 10^7
    const int64_t unix_100ns =
        duration_cast<duration<int64_t, std::ratio<1, 10000000>>>(
            system_clock::now().time_since_epoch()).count();
    *out_time = be<int64_t>(unix_100ns + EPOCH_DIFF_100NS);
}

// 100ns -> ms with NT semantics (round up if non-zero)
static inline uint32_t GuestTimeoutToMilliseconds(const be<int64_t>* t)
{
    if (!t) return INFINITE;            // wait forever
    const int64_t ticks = *t;           // 100-ns units
    if (ticks == 0) return 0;           // yield/poll
    const bool is_relative = ticks < 0; // negative = relative delay
    uint64_t abs_ticks = is_relative ? (uint64_t)(-ticks) : (uint64_t)ticks;
    uint32_t ms = (uint32_t)((abs_ticks + 9'999) / 10'000);
    if (ms == 0 && abs_ticks) ms = 1;
    return ms;                          // caller interprets rel vs abs
}

// 100ns ticks since Jan 1, 1601 (FILETIME epoch)
static inline int64_t KeQuerySystemTime100ns() {
    using namespace std::chrono;
    constexpr int64_t SEC_TO_100NS = 10'000'000;
    constexpr int64_t WIN_UNIX_DIFF_SEC = 11644473600LL; // 1601->1970
    const auto now = system_clock::now().time_since_epoch();
    const int64_t unix_100ns = duration_cast<nanoseconds>(now).count() / 100;
    return unix_100ns + WIN_UNIX_DIFF_SEC * SEC_TO_100NS;
}

static inline void host_sleep_ms(int32_t ms) {
    if (ms <= 0) {
        // avoid tight spin if we rounded to 0
        std::this_thread::yield();
    } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
}

static inline int64_t query_system_time_100ns() {
    using namespace std::chrono;
    // Windows system time epoch is Jan 1, 1601
    constexpr int64_t SEC_TO_100NS = 10'000'000;
    constexpr int64_t WIN_UNIX_DIFF_SEC = 11644473600LL;
    const int64_t unix_100ns =
        duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count() / 100;
    return unix_100ns + WIN_UNIX_DIFF_SEC * SEC_TO_100NS;
}

static inline int ceil_ms_from_100ns(int64_t t100ns) {
    // ceil(t / 10'000)
    return (int)((t100ns + 9'999) / 10'000);
}
