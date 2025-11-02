#include <stdafx.h>
#include "xam.h"
#include "xdm.h"
#include <hid/hid.h>
#include <ui/game_window.h>
#include <cpu/guest_thread.h>
#include <ranges>
#include <unordered_set>
#include "xxHashMap.h"
#include <user/paths.h>
#include <SDL3/SDL.h>
#include <os/logger.h>

#include <cstdlib>
#include <chrono>

// Forward decl from kernel/imports.cpp
extern "C" bool KeSetEvent(XKEVENT* pEvent, uint32_t Increment, bool Wait);

// XamUser signin states
enum XUserSigninState {
    eXUserSigninState_NotSignedIn = 0,
    eXUserSigninState_SignedInLocally = 1,
    eXUserSigninState_SignedInToLive = 2,
};

// Fake user data for testing
static const uint64_t g_fakeXUID = 0xE000000000000001ULL;  // Offline XUID
static const char* g_fakeUserName = "Player1";


struct XamListener : KernelObject
{
    uint32_t id{};
    uint64_t areas{};
    std::vector<std::tuple<uint32_t, uint32_t>> notifications;

    XamListener(const XamListener&) = delete;
    XamListener& operator=(const XamListener&) = delete;

    XamListener();
    ~XamListener();
};

struct XamEnumeratorBase : KernelObject
{
    virtual uint32_t Next(void* buffer)
    {
        return -1;
    }
};

template<typename TIterator = std::vector<XHOSTCONTENT_DATA>::iterator>
struct XamEnumerator : XamEnumeratorBase
{
    uint32_t fetch;
    size_t size;
    TIterator position;
    TIterator begin;
    TIterator end;

    XamEnumerator() = default;
    XamEnumerator(uint32_t fetch, size_t size, TIterator begin, TIterator end) : fetch(fetch), size(size), position(begin), begin(begin), end(end)
    {

    }

    uint32_t Next(void* buffer) override
    {
        if (position == end)
        {
            return -1;
        }

        if (buffer == nullptr)
        {
            for (size_t i = 0; i < fetch; i++)
            {
                if (position == end)
                {
                    return i == 0 ? -1 : i;
                }

                ++position;
            }
        }

        for (size_t i = 0; i < fetch; i++)
        {
            if (position == end)
            {
                return i == 0 ? -1 : i;
            }

            memcpy(buffer, &*position, size);

            ++position;
            buffer = (void*)((size_t)buffer + size);
        }

        return fetch;
    }
};

std::array<xxHashMap<XHOSTCONTENT_DATA>, 3> gContentRegistry{};
std::unordered_set<XamListener*> gListeners{};
std::mutex gListenersMutex{};  // CRITICAL: Protect gListeners from race conditions
xxHashMap<std::string> gRootMap;

std::string_view XamGetRootPath(const std::string_view& root)
{
    const auto result = gRootMap.find(StringHash(root));

    if (result == gRootMap.end())
        return "";

    return result->second;
}

void XamRootCreate(const std::string_view& root, const std::string_view& path)
{
    LOGFN("XamRootCreate: '{}' -> '{}'", root, path);
    KernelTraceHostOpF("HOST.XamRootCreate root='%.*s' path='%.*s'",
                       (int)root.size(), root.data(), (int)path.size(), path.data());
    gRootMap.emplace(StringHash(root), path);
}

XamListener::XamListener()
{
    std::lock_guard<std::mutex> lock(gListenersMutex);
    gListeners.insert(this);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.XamListener.constructor this=%p gListeners.size=%u", this, (unsigned int)gListeners.size());
    fprintf(stderr, "[XAM] XamListener.constructor this=%p gListeners.size=%u\n", this, (unsigned int)gListeners.size());
    fflush(stderr);
}

XamListener::~XamListener()
{
    std::lock_guard<std::mutex> lock(gListenersMutex);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.XamListener.destructor this=%p gListeners.size=%u BEFORE erase", this, (unsigned int)gListeners.size());
    fprintf(stderr, "[XAM] XamListener.destructor this=%p gListeners.size=%u BEFORE erase\n", this, (unsigned int)gListeners.size());
    fflush(stderr);
    gListeners.erase(this);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.XamListener.destructor this=%p gListeners.size=%u AFTER erase", this, (unsigned int)gListeners.size());
    fprintf(stderr, "[XAM] XamListener.destructor this=%p gListeners.size=%u AFTER erase\n", this, (unsigned int)gListeners.size());
    fflush(stderr);
}

XCONTENT_DATA XamMakeContent(uint32_t type, const std::string_view& name)
{
    XCONTENT_DATA data{ 1, type };

    strncpy(data.szFileName, name.data(), sizeof(data.szFileName));

    return data;
}

void XamRegisterContent(const XCONTENT_DATA& data, const std::string_view& root)
{
    const auto idx_raw = data.dwContentType - 1;
    if (idx_raw >= gContentRegistry.size())
    {
        LOGFN_ERROR("XamRegisterContent: invalid content type {} for {}", (uint32_t)data.dwContentType, data.szFileName);
        return;
    }
    const size_t idx = static_cast<size_t>(idx_raw);

    fprintf(stderr, "[XAM-CONTENT] XamRegisterContent: content='%s' type=%u root='%.*s' hash=%016llX\n",
            data.szFileName, (uint32_t)data.dwContentType, (int)root.size(), root.data(),
            (unsigned long long)StringHash(data.szFileName));
    fflush(stderr);

    gContentRegistry[idx].emplace(StringHash(data.szFileName), XHOSTCONTENT_DATA{ data }).first->second.szRoot = root;
}

void XamRegisterContent(uint32_t type, const std::string_view name, const std::string_view& root)
{
    XCONTENT_DATA data{ 1, type, {}, "" };

    strncpy(data.szFileName, name.data(), sizeof(data.szFileName));

    XamRegisterContent(data, root);
}

uint32_t XamNotifyCreateListener(uint64_t qwAreas)
{
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.XamNotifyCreateListener BEFORE CreateKernelObject areas=%016llX gListeners.size=%u",
    //                   (unsigned long long)qwAreas, (unsigned int)gListeners.size());
    fprintf(stderr, "[XAM] XamNotifyCreateListener BEFORE CreateKernelObject areas=%016llX gListeners.size=%u\n",
            (unsigned long long)qwAreas, (unsigned int)gListeners.size());
    fflush(stderr);

    auto* listener = CreateKernelObject<XamListener>();

    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.XamNotifyCreateListener AFTER CreateKernelObject listener=%p gListeners.size=%u",
    //                   listener, (unsigned int)gListeners.size());
    fprintf(stderr, "[XAM] XamNotifyCreateListener AFTER CreateKernelObject listener=%p gListeners.size=%u\n",
            listener, (unsigned int)gListeners.size());
    fflush(stderr);

    listener->areas = qwAreas;

    fprintf(stderr, "[XAM] XamNotifyCreateListener areas=%016llX handle=%08X\n",
            (unsigned long long)qwAreas, GetKernelHandle(listener));
    fflush(stderr);

    // CRITICAL FIX (2025-10-31): Send XN_SYS_SIGNINCHANGED notification when GAME creates listener
    // The game creates listener with areas=0x2F (listening to areas 0,1,2,3,5)
    // We need to send the notification to THIS listener, not the auto-created one
    // Check if this is the game's listener (areas=0x2F) and send notification immediately
    if (qwAreas == 0x2F) {
        const uint32_t XN_SYS_SIGNINCHANGED = 0x11;  // area=0, message=17
        fprintf(stderr, "[XAM] XamNotifyCreateListener: Game listener detected (areas=0x2F), sending XN_SYS_SIGNINCHANGED\n");
        fflush(stderr);

        // Send notification to THIS listener (param=1 for user 0 signed in)
        listener->notifications.emplace_back(XN_SYS_SIGNINCHANGED, 1);

        fprintf(stderr, "[XAM] XamNotifyCreateListener: Notification queued directly to listener (queue_size=%zu)\n",
                listener->notifications.size());
        fflush(stderr);
    }

    return GetKernelHandle(listener);
}

void XamNotifyEnqueueEvent(uint32_t dwId, uint32_t dwParam)
{
    std::lock_guard<std::mutex> lock(gListenersMutex);
    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.XamNotifyEnqueueEvent id=%08X param=%08X area=%u msg=%u listeners=%zu",
    //                   dwId, dwParam, MSG_AREA(dwId), MSG_NUMBER(dwId), gListeners.size());
    fprintf(stderr, "[XAM] XamNotifyEnqueueEvent id=%08X param=%08X area=%u msg=%u listeners=%zu\n",
            dwId, dwParam, MSG_AREA(dwId), MSG_NUMBER(dwId), gListeners.size());
    fflush(stderr);

    int delivered_count = 0;
    for (const auto& listener : gListeners)
    {
        uint32_t area_bit = 1 << MSG_AREA(dwId);
        bool matches = (area_bit & listener->areas) != 0;

        // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
        // KernelTraceHostOpF("  listener areas=%016llX area_bit=%08X matches=%d",
        //                   (unsigned long long)listener->areas, area_bit, matches);
        fprintf(stderr, "[XAM]   listener areas=%016llX area_bit=%08X matches=%d\n",
                (unsigned long long)listener->areas, area_bit, matches);
        fflush(stderr);

        if (!matches)
            continue;

        listener->notifications.emplace_back(dwId, dwParam);
        delivered_count++;

        // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
        // KernelTraceHostOpF("  -> delivered to listener (queue_size now %zu)", listener->notifications.size());
        fprintf(stderr, "[XAM]   -> delivered to listener (queue_size now %zu)\n", listener->notifications.size());
        fflush(stderr);
    }

    // CRITICAL FIX: KernelTraceHostOpF hangs in natural path! Skip it.
    // KernelTraceHostOpF("HOST.XamNotifyEnqueueEvent delivered to %d listeners", delivered_count);
    fprintf(stderr, "[XAM] XamNotifyEnqueueEvent delivered to %d listeners\n", delivered_count);
    fflush(stderr);
}

bool XNotifyGetNext(uint32_t hNotification, uint32_t dwMsgFilter, be<uint32_t>* pdwId, be<uint32_t>* pParam)
{
    auto& listener = *GetKernelObject<XamListener>(hNotification);

    static int call_count = 0;
    static int last_log_count = 0;
    static bool dummy_notification_sent = false;
    static int empty_queue_count = 0;
    static int no_match_count = 0;  // NEW: Track consecutive calls with no matching notification
    call_count++;

    // MW05_FIX: After 10 consecutive polling attempts with empty queue, send a dummy notification to unblock the thread
    // The notification polling thread (sub_82849D40) gets stuck waiting for notifications that never arrive
    // Xenia doesn't create this thread at all, so we need to unblock it to let the game progress
    // The game is polling for notification ID 0x00000011, so we send that specific notification
    if (listener.notifications.empty()) {
        empty_queue_count++;
    } else {
        empty_queue_count = 0;  // Reset counter if queue is not empty
    }

    // Log the first 30 calls to debug the notification logic
    if (call_count <= 30) {
        fprintf(stderr, "[MW05_DEBUG] XNotifyGetNext call=%d empty_count=%d no_match_count=%d queue_size=%zu filter=%08X dummy_sent=%d\n",
                call_count, empty_queue_count, no_match_count, listener.notifications.size(), dwMsgFilter, dummy_notification_sent);
        fflush(stderr);

        // Log queued notifications
        for (size_t i = 0; i < listener.notifications.size() && i < 3; i++) {
            uint32_t id = std::get<0>(listener.notifications[i]);
            uint32_t param = std::get<1>(listener.notifications[i]);
            fprintf(stderr, "[MW05_DEBUG]   [%zu] id=%08X param=%08X\n", i, id, param);
            fflush(stderr);
        }
    }

    if (!dummy_notification_sent && empty_queue_count >= 10 && dwMsgFilter == 0x00000011) {
        fprintf(stderr, "[MW05_FIX] XNotifyGetNext: Sending XN_SYS_SIGNINCHANGED notification id=0x%08X param=1 (user 0 signed in) to unblock polling thread (call_count=%d, empty_queue_count=%d)\n", dwMsgFilter, call_count, empty_queue_count);
        fflush(stderr);

        // CRITICAL FIX (2025-10-30): Send the notification the game is waiting for (id=0x00000011, param=1)
        // Parameter MUST be 1 (user slot mask for user 0 signed in), NOT 0!
        // param=0 means no users signed in, which is incorrect
        // param=1 means user 0 is signed in (bit 0 set)
        listener.notifications.push_back(std::make_tuple(dwMsgFilter, 1));  // param=1 for user 0 signed in
        dummy_notification_sent = true;
        empty_queue_count = 0;  // Reset counter after sending

        KernelTraceHostOpF("HOST.XNotifyGetNext DUMMY_NOTIFICATION_SENT id=%08X param=%08X (user 0 signed in)",
                          dwMsgFilter, 1);
    }

    // MW05_FIX: If the game keeps polling for a specific notification but the queue has non-matching notifications,
    // send the requested notification after 5 consecutive no-match attempts
    if (dwMsgFilter != 0 && !listener.notifications.empty()) {
        bool has_match = false;
        for (size_t i = 0; i < listener.notifications.size(); i++) {
            if (std::get<0>(listener.notifications[i]) == dwMsgFilter) {
                has_match = true;
                break;
            }
        }

        if (!has_match) {
            no_match_count++;
            if (no_match_count >= 5 && dwMsgFilter == 0x00000011) {
                fprintf(stderr, "[MW05_FIX] XNotifyGetNext: Queue has %zu notifications but none match filter=0x%08X. Sending requested notification after %d attempts.\n",
                        listener.notifications.size(), dwMsgFilter, no_match_count);

                // Log what's actually in the queue
                fprintf(stderr, "[MW05_FIX] Notifications in queue:\n");
                for (size_t i = 0; i < listener.notifications.size() && i < 5; i++) {
                    uint32_t id = std::get<0>(listener.notifications[i]);
                    uint32_t param = std::get<1>(listener.notifications[i]);
                    fprintf(stderr, "[MW05_FIX]   [%zu] id=0x%08X param=0x%08X (matches filter: %s)\n",
                            i, id, param, (id == dwMsgFilter) ? "YES" : "NO");
                }
                fflush(stderr);

                // Send the notification the game is waiting for
                // CRITICAL FIX: Parameter is user slot mask! For user 0 signed in, param = (1 << 0) = 1
                listener.notifications.push_back(std::make_tuple(dwMsgFilter, 1));
                no_match_count = 0;  // Reset counter

                KernelTraceHostOpF("HOST.XNotifyGetNext NO_MATCH_FIX id=%08X param=%08X",
                                  dwMsgFilter, 1);
            }
        } else {
            no_match_count = 0;  // Reset if we found a match
        }
    } else {
        no_match_count = 0;  // Reset if queue is empty or no filter
    }

    // Log first 10 calls and every 100th call
    bool should_log = (call_count <= 10) || (call_count % 100 == 0);

    if (should_log) {
        KernelTraceHostOpF("HOST.XNotifyGetNext count=%d filter=%08X queue_size=%zu",
                          call_count, dwMsgFilter, listener.notifications.size());

        // Log queued notifications
        for (size_t i = 0; i < listener.notifications.size() && i < 5; i++) {
            uint32_t id = std::get<0>(listener.notifications[i]);
            uint32_t param = std::get<1>(listener.notifications[i]);
            KernelTraceHostOpF("  [%zu] id=%08X param=%08X area=%u msg=%u",
                              i, id, param, MSG_AREA(id), MSG_NUMBER(id));
        }
    }

    if (dwMsgFilter)
    {
        for (size_t i = 0; i < listener.notifications.size(); i++)
        {
            if (std::get<0>(listener.notifications[i]) == dwMsgFilter)
            {
                if (pdwId)
                    *pdwId = std::get<0>(listener.notifications[i]);

                if (pParam)
                    *pParam = std::get<1>(listener.notifications[i]);

                listener.notifications.erase(listener.notifications.begin() + i);

                KernelTraceHostOpF("HOST.XNotifyGetNext FOUND filter=%08X -> id=%08X param=%08X",
                                  dwMsgFilter, pdwId ? (uint32_t)*pdwId : 0, pParam ? (uint32_t)*pParam : 0);

                return true;
            }
        }

        if (should_log && listener.notifications.size() > 0) {
            KernelTraceHostOpF("HOST.XNotifyGetNext NOT_FOUND filter=%08X (queue has %zu items but none match)",
                              dwMsgFilter, listener.notifications.size());
        }
    }
    else
    {
        if (listener.notifications.empty())
            return false;

        if (pdwId)
            *pdwId = std::get<0>(listener.notifications[0]);

        if (pParam)
            *pParam = std::get<1>(listener.notifications[0]);

        listener.notifications.erase(listener.notifications.begin());

        KernelTraceHostOpF("HOST.XNotifyGetNext NO_FILTER -> id=%08X param=%08X",
                          pdwId ? (uint32_t)*pdwId : 0, pParam ? (uint32_t)*pParam : 0);

        return true;
    }

    return false;
}

uint32_t XamShowMessageBoxUI(uint32_t dwUserIndex, be<uint16_t>* wszTitle, be<uint16_t>* wszText, uint32_t cButtons,
    xpointer<be<uint16_t>>* pwszButtons, uint32_t dwFocusButton, uint32_t dwFlags, be<uint32_t>* pResult, XXOVERLAPPED* pOverlapped)
{
    *pResult = cButtons ? cButtons - 1 : 0;

#if _DEBUG
    assert("XamShowMessageBoxUI encountered!" && false);
#elif _WIN32
    // This code is Win32-only as it'll most likely crash, misbehave or
    // cause corruption due to using a different type of memory than what
    // wchar_t is on Linux. Windows uses 2 bytes while Linux uses 4 bytes.
    std::vector<std::wstring> texts{};

    texts.emplace_back(reinterpret_cast<wchar_t*>(wszTitle));
    texts.emplace_back(reinterpret_cast<wchar_t*>(wszText));

    for (size_t i = 0; i < cButtons; i++)
        texts.emplace_back(reinterpret_cast<wchar_t*>(pwszButtons[i].get()));

    for (auto& text : texts)
    {
        for (size_t i = 0; i < text.size(); i++)
            ByteSwapInplace(text[i]);
    }

    wprintf(L"[XamShowMessageBoxUI] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    wprintf(L"[XamShowMessageBoxUI] If you are encountering this message and the game has ceased functioning,\n");
    wprintf(L"[XamShowMessageBoxUI] please create an issue at https://github.com/sh2dow/Mw05Recomp/issues.\n");
    wprintf(L"[XamShowMessageBoxUI] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    wprintf(L"[XamShowMessageBoxUI] %ls\n", texts[0].c_str());
    wprintf(L"[XamShowMessageBoxUI] %ls\n", texts[1].c_str());
    wprintf(L"[XamShowMessageBoxUI] ");

    for (size_t i = 0; i < cButtons; i++)
    {
        wprintf(L"%ls", texts[2 + i].c_str());

        if (i != cButtons - 1)
            wprintf(L" | ");
    }

    wprintf(L"\n");
    wprintf(L"[XamShowMessageBoxUI] Defaulted to button: %d\n", pResult->get());
    wprintf(L"[XamShowMessageBoxUI] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
#endif

    if (pOverlapped)
    {
        pOverlapped->dwCompletionContext = GuestThread::GetCurrentThreadId();
        pOverlapped->Error = 0;
        pOverlapped->Length = -1;
        // If caller provided an event, signal it to emulate immediate completion.
        if (pOverlapped->hEvent)
        {
            if (auto* ev = reinterpret_cast<XKEVENT*>(g_memory.Translate(pOverlapped->hEvent)))
            {
                KeSetEvent(ev, 0, false);
                KernelTraceHostOpF("HOST.XamShowMessageBoxUI.signal hEvent=%08X", (uint32_t)pOverlapped->hEvent);
            }
        }
    }

    XamNotifyEnqueueEvent(9, 0);

    KernelTraceHostOpF("HOST.XamShowMessageBoxUI.complete cButtons=%u", cButtons);
    return 0;
}

uint32_t XamContentCreateEnumerator(uint32_t dwUserIndex, uint32_t DeviceID, uint32_t dwContentType,
    uint32_t dwContentFlags, uint32_t cItem, be<uint32_t>* pcbBuffer, be<uint32_t>* phEnum)
{
    LOGFN("XamContentCreateEnumerator: userIndex={} deviceID={} contentType={} flags={:X} cItem={}",
          dwUserIndex, DeviceID, dwContentType, dwContentFlags, cItem);
    KernelTraceHostOpF("HOST.XamContentCreateEnumerator userIndex=%u deviceID=%u contentType=%u flags=%08X cItem=%u",
                       dwUserIndex, DeviceID, dwContentType, dwContentFlags, cItem);

    if (dwUserIndex != 0)
    {
        GuestThread::SetLastError(ERROR_NO_SUCH_USER);
        LOGFN_ERROR("XamContentCreateEnumerator: invalid user index {}", dwUserIndex);
        return 0xFFFFFFFF;
    }

    // Validate content type to avoid out-of-range array access
    if (dwContentType < 1 || dwContentType > gContentRegistry.size())
    {
        LOGFN_ERROR("XamContentCreateEnumerator: invalid content type {}", dwContentType);
        return ERROR_INVALID_PARAMETER;
    }
    const auto& registry = gContentRegistry[dwContentType - 1];
    const auto& values = registry | std::views::values;
    auto* enumerator = CreateKernelObject<XamEnumerator<decltype(values.begin())>>(cItem, sizeof(_XCONTENT_DATA), values.begin(), values.end());

    if (pcbBuffer)
        *pcbBuffer = sizeof(_XCONTENT_DATA) * cItem;

    *phEnum = GetKernelHandle(enumerator);

    LOGFN("XamContentCreateEnumerator: created enumerator handle={:X} with {} items", (uint32_t)*phEnum, registry.size());
    KernelTraceHostOpF("HOST.XamContentCreateEnumerator.result handle=%08X items=%u", (uint32_t)*phEnum, (unsigned int)registry.size());

    return 0;
}

uint32_t XamEnumerate(uint32_t hEnum, uint32_t dwFlags, void* pvBuffer, uint32_t cbBuffer, be<uint32_t>* pcItemsReturned, XXOVERLAPPED* pOverlapped)
{
    auto* enumerator = GetKernelObject<XamEnumeratorBase>(hEnum);
    const auto count = enumerator->Next(pvBuffer);

    if (count == -1)
        return ERROR_NO_MORE_FILES;

    if (pcItemsReturned)
        *pcItemsReturned = count;

    return ERROR_SUCCESS;
}

uint32_t XamContentCreateEx(uint32_t dwUserIndex, const char* szRootName, const XCONTENT_DATA* pContentData,
    uint32_t dwContentFlags, be<uint32_t>* pdwDisposition, be<uint32_t>* pdwLicenseMask,
    uint32_t dwFileCacheSize, uint64_t uliContentSize, PXXOVERLAPPED pOverlapped)
{
    LOGFN("XamContentCreateEx: root='{}' content='{}' type={} flags={:X}",
          szRootName, pContentData->szFileName, (uint32_t)pContentData->dwContentType, dwContentFlags);
    KernelTraceHostOpF("HOST.XamContentCreateEx root='%s' content='%s' type=%u flags=%08X",
                       szRootName, pContentData->szFileName, (uint32_t)pContentData->dwContentType, dwContentFlags);

    uint32_t contentType = static_cast<uint32_t>(pContentData->dwContentType);
    if (contentType < 1 || contentType > gContentRegistry.size())
    {
        // Be permissive for early boot: treat unknown types as RESERVED to avoid crashing.
        LOGFN_ERROR("XamContentCreateEx: invalid content type {} for {} — treating as RESERVED", contentType, pContentData->szFileName);
        contentType = XCONTENTTYPE_RESERVED;
    }
    const auto& registry = gContentRegistry[contentType - 1];
    const auto exists = registry.contains(StringHash(pContentData->szFileName));
    const auto mode = dwContentFlags & 0xF;

    if (mode == CREATE_ALWAYS)
    {
        if (pdwDisposition)
            *pdwDisposition = XCONTENT_NEW;

        if (!exists)
        {
            std::filesystem::path rootPath;

            if (pContentData->dwContentType == XCONTENTTYPE_SAVEDATA)
            {
                rootPath = GetSavePath(true);
            }
            else if (pContentData->dwContentType == XCONTENTTYPE_DLC)
            {
                rootPath = GetGamePath() / "dlc";
            }
            else
            {
                rootPath = GetGamePath();
            }

            const std::string root = (const char*)rootPath.u8string().c_str();
            XamRegisterContent(*pContentData, root);

            std::error_code ec;
            std::filesystem::create_directory(rootPath, ec);

            XamRootCreate(szRootName, root);
        }
        else
        {
            XamRootCreate(szRootName, registry.find(StringHash(pContentData->szFileName))->second.szRoot);
        }

        return ERROR_SUCCESS;
    }

    if (mode == OPEN_EXISTING)
    {
        if (exists)
        {
            if (pdwDisposition)
                *pdwDisposition = XCONTENT_EXISTING;

            const std::string& rootPath = registry.find(StringHash(pContentData->szFileName))->second.szRoot;
            fprintf(stderr, "[XAM-CONTENT] XamContentCreateEx OPEN_EXISTING: root='%s' content='%s' rootPath='%s'\n",
                    szRootName, pContentData->szFileName, rootPath.c_str());
            fflush(stderr);

            XamRootCreate(szRootName, rootPath);

            return ERROR_SUCCESS;
        }
        else
        {
            fprintf(stderr, "[XAM-CONTENT] XamContentCreateEx OPEN_EXISTING FAILED: root='%s' content='%s' NOT FOUND in registry\n",
                    szRootName, pContentData->szFileName);
            fflush(stderr);

            if (pdwDisposition)
                *pdwDisposition = XCONTENT_NEW;

            return ERROR_PATH_NOT_FOUND;
        }
    }

    return ERROR_PATH_NOT_FOUND;
}

uint32_t XamContentClose(const char* szRootName, XXOVERLAPPED* pOverlapped)
{
    gRootMap.erase(StringHash(szRootName));
    return 0;
}

uint32_t XamContentGetDeviceData(uint32_t DeviceID, XDEVICE_DATA* pDeviceData)
{
    pDeviceData->DeviceID = DeviceID;
    pDeviceData->DeviceType = XCONTENTDEVICETYPE_HDD;
    pDeviceData->ulDeviceBytes = 0x10000000;
    pDeviceData->ulDeviceFreeBytes = 0x10000000;
    pDeviceData->wszName[0] = 'S';
    pDeviceData->wszName[1] = 'p';
    pDeviceData->wszName[2] = 'e';
    pDeviceData->wszName[3] = 'e';
    pDeviceData->wszName[4] = 'd';
    pDeviceData->wszName[5] = '\0';

    return 0;
}

uint32_t XamInputGetCapabilities(uint32_t unk, uint32_t userIndex, uint32_t flags, XAMINPUT_CAPABILITIES* caps)
{
    uint32_t result = hid::GetCapabilities(userIndex, caps);

    if (result == ERROR_SUCCESS)
    {
        ByteSwapInplace(caps->Flags);
        ByteSwapInplace(caps->Gamepad.wButtons);
        ByteSwapInplace(caps->Gamepad.sThumbLX);
        ByteSwapInplace(caps->Gamepad.sThumbLY);
        ByteSwapInplace(caps->Gamepad.sThumbRX);
        ByteSwapInplace(caps->Gamepad.sThumbRY);
        ByteSwapInplace(caps->Vibration.wLeftMotorSpeed);
        ByteSwapInplace(caps->Vibration.wRightMotorSpeed);
    }

    return result;
}

uint32_t XamInputGetState(uint32_t userIndex, uint32_t flags, XAMINPUT_STATE* state)
{
    static bool s_loggedOnce = false;
    if (!s_loggedOnce) { s_loggedOnce = true; KernelTraceHostOpF("HOST.XamInputGetState.first_call"); }

    memset(state, 0, sizeof(*state));

    if (hid::IsInputAllowed())
        hid::GetState(userIndex, state);

    // AUTO-PRESS START BUTTON: Simulate START button press to get past title screen
    // This allows the game to progress from the title screen to the main menu/gameplay
    static auto s_startTime = std::chrono::steady_clock::now();
    static bool s_autoStartPressed = false;
    static bool s_autoStartLoggedOnce = false;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - s_startTime).count();

    // Press START button after 10-15 seconds
    bool autoStart = (elapsed >= 10 && elapsed < 15);
    if (autoStart && !s_autoStartLoggedOnce) {
        s_autoStartLoggedOnce = true;
        fprintf(stderr, "[XAM-INPUT] Auto-pressing START button at %lld seconds\n", (long long)elapsed);
        fflush(stderr);
    }
    if (autoStart) {
        s_autoStartPressed = true;
    }

    auto keyboardState = SDL_GetKeyboardState(NULL);

    if (GameWindow::s_isFocused && !keyboardState[SDL_SCANCODE_LALT])
    {
        if (keyboardState[Config::Key_LeftStickUp])
            state->Gamepad.sThumbLY = 32767;
        if (keyboardState[Config::Key_LeftStickDown])
            state->Gamepad.sThumbLY = -32768;
        if (keyboardState[Config::Key_LeftStickLeft])
            state->Gamepad.sThumbLX = -32768;
        if (keyboardState[Config::Key_LeftStickRight])
            state->Gamepad.sThumbLX = 32767;

        if (keyboardState[Config::Key_RightStickUp])
            state->Gamepad.sThumbRY = 32767;
        if (keyboardState[Config::Key_RightStickDown])
            state->Gamepad.sThumbRY = -32768;
        if (keyboardState[Config::Key_RightStickLeft])
            state->Gamepad.sThumbRX = -32768;
        if (keyboardState[Config::Key_RightStickRight])
            state->Gamepad.sThumbRX = 32767;

        if (keyboardState[Config::Key_LeftTrigger])
            state->Gamepad.bLeftTrigger = 0xFF;
        if (keyboardState[Config::Key_RightTrigger])
            state->Gamepad.bRightTrigger = 0xFF;

        if (keyboardState[Config::Key_DPadUp])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_DPAD_UP;
        if (keyboardState[Config::Key_DPadDown])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_DPAD_DOWN;
        if (keyboardState[Config::Key_DPadLeft])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_DPAD_LEFT;
        if (keyboardState[Config::Key_DPadRight])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_DPAD_RIGHT;

        if (keyboardState[Config::Key_Start] || s_autoStartPressed)
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_START;
        if (keyboardState[Config::Key_Back])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_BACK;

        if (keyboardState[Config::Key_LeftBumper])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_LEFT_SHOULDER;
        if (keyboardState[Config::Key_RightBumper])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_RIGHT_SHOULDER;

        if (keyboardState[Config::Key_A])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_A;
        if (keyboardState[Config::Key_B])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_B;
        if (keyboardState[Config::Key_X])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_X;
        if (keyboardState[Config::Key_Y])
            state->Gamepad.wButtons |= XAMINPUT_GAMEPAD_Y;
    }

    state->Gamepad.wButtons &= ~hid::g_prohibitedButtons;

    if (hid::g_isLeftStickProhibited)
    {
        state->Gamepad.sThumbLX = 0;
        state->Gamepad.sThumbLY = 0;
    }

    if (hid::g_isRightStickProhibited)
    {
        state->Gamepad.sThumbRX = 0;
        state->Gamepad.sThumbRY = 0;
    }

    ByteSwapInplace(state->Gamepad.wButtons);
    ByteSwapInplace(state->Gamepad.sThumbLX);
    ByteSwapInplace(state->Gamepad.sThumbLY);
    ByteSwapInplace(state->Gamepad.sThumbRX);
    ByteSwapInplace(state->Gamepad.sThumbRY);

    return ERROR_SUCCESS;
}

uint32_t XamInputSetState(uint32_t userIndex, uint32_t flags, XAMINPUT_VIBRATION* vibration)
{
    if (!hid::IsInputDeviceController() || !Config::Vibration)
        return ERROR_SUCCESS;

    ByteSwapInplace(vibration->wLeftMotorSpeed);
    ByteSwapInplace(vibration->wRightMotorSpeed);

    return hid::SetState(userIndex, vibration);
}

// XamUser functions - needed to unblock game initialization
PPC_FUNC_IMPL(XamUserGetSigninState);
PPC_FUNC(XamUserGetSigninState)
{
    uint32_t userIndex = ctx.r3.u32;

    // Return SignedInLocally for user 0, NotSignedIn for others
    uint32_t state = (userIndex == 0) ? eXUserSigninState_SignedInLocally : eXUserSigninState_NotSignedIn;

    fprintf(stderr, "[HOST.XamUserGetSigninState] userIndex=%u -> state=%u\n", userIndex, state);
    fflush(stderr);

    ctx.r3.u32 = state;
}

// XamContent functions - needed for content device management
PPC_FUNC_IMPL(XamContentGetDeviceState);
PPC_FUNC(XamContentGetDeviceState)
{
    uint32_t deviceId = ctx.r3.u32;
    uint32_t overlappedPtr = ctx.r4.u32;

    fprintf(stderr, "[HOST.XamContentGetDeviceState] deviceId=%u overlappedPtr=%08X\n", deviceId, overlappedPtr);
    fflush(stderr);

    // Device IDs (from Xenia):
    // 1 = HDD (Hard Disk Drive)
    // 2 = ODD (Optical Disc Drive)

    // Return success for HDD and ODD, error for others
    uint32_t result;
    if (deviceId == 1 || deviceId == 2) {
        // Device is connected and ready
        if (overlappedPtr != 0) {
            // Async mode - complete immediately with success
            // TODO: Implement overlapped completion if needed
            result = 0x3E6; // X_ERROR_IO_PENDING
        } else {
            // Sync mode - return success
            result = 0; // X_ERROR_SUCCESS
        }
    } else {
        // Unknown device
        if (overlappedPtr != 0) {
            // Async mode - complete immediately with error
            result = 0x3E6; // X_ERROR_IO_PENDING
        } else {
            // Sync mode - return error
            result = 0x48F; // X_ERROR_DEVICE_NOT_CONNECTED
        }
    }

    fprintf(stderr, "[HOST.XamContentGetDeviceState] -> result=%08X\n", result);
    fflush(stderr);

    ctx.r3.u32 = result;
}

PPC_FUNC_IMPL(XamUserGetXUID);
PPC_FUNC(XamUserGetXUID)
{
    uint32_t userIndex = ctx.r3.u32;
    uint32_t xuidPtr_ea = ctx.r4.u32;

    // Return fake XUID for user 0
    if (userIndex == 0 && xuidPtr_ea != 0) {
        be<uint64_t>* xuidPtr = static_cast<be<uint64_t>*>(g_memory.Translate(xuidPtr_ea));
        if (xuidPtr) {
            *xuidPtr = g_fakeXUID;
            fprintf(stderr, "[HOST.XamUserGetXUID] userIndex=%u -> XUID=%016llX\n", userIndex, g_fakeXUID);
            fflush(stderr);
            ctx.r3.u32 = ERROR_SUCCESS;
            return;
        }
    }

    fprintf(stderr, "[HOST.XamUserGetXUID] userIndex=%u -> ERROR (not signed in)\n", userIndex);
    fflush(stderr);
    ctx.r3.u32 = ERROR_NOT_LOGGED_ON;
}

PPC_FUNC_IMPL(XamUserGetName);
PPC_FUNC(XamUserGetName)
{
    uint32_t userIndex = ctx.r3.u32;
    uint32_t nameBuffer_ea = ctx.r4.u32;
    uint32_t bufferSize = ctx.r5.u32;

    // Return fake username for user 0
    if (userIndex == 0 && nameBuffer_ea != 0 && bufferSize > 0) {
        char* nameBuffer = static_cast<char*>(g_memory.Translate(nameBuffer_ea));
        if (nameBuffer) {
            size_t copyLen = std::min((size_t)bufferSize - 1, strlen(g_fakeUserName));
            memcpy(nameBuffer, g_fakeUserName, copyLen);
            nameBuffer[copyLen] = '\0';

            fprintf(stderr, "[HOST.XamUserGetName] userIndex=%u -> name='%s'\n", userIndex, g_fakeUserName);
            fflush(stderr);
            ctx.r3.u32 = ERROR_SUCCESS;
            return;
        }
    }

    fprintf(stderr, "[HOST.XamUserGetName] userIndex=%u -> ERROR (not signed in)\n", userIndex);
    fflush(stderr);
    ctx.r3.u32 = ERROR_NOT_LOGGED_ON;
}

PPC_FUNC_IMPL(XamUserCheckPrivilege);
PPC_FUNC(XamUserCheckPrivilege)
{
    uint32_t userIndex = ctx.r3.u32;
    uint32_t privilege = ctx.r4.u32;
    uint32_t resultPtr_ea = ctx.r5.u32;

    // Always grant all privileges for user 0
    if (userIndex == 0 && resultPtr_ea != 0) {
        be<uint32_t>* resultPtr = static_cast<be<uint32_t>*>(g_memory.Translate(resultPtr_ea));
        if (resultPtr) {
            *resultPtr = 1;  // Privilege granted
            fprintf(stderr, "[HOST.XamUserCheckPrivilege] userIndex=%u privilege=%u -> GRANTED\n", userIndex, privilege);
            fflush(stderr);
            ctx.r3.u32 = ERROR_SUCCESS;
            return;
        }
    }

    fprintf(stderr, "[HOST.XamUserCheckPrivilege] userIndex=%u privilege=%u -> ERROR\n", userIndex, privilege);
    fflush(stderr);
    ctx.r3.u32 = ERROR_NOT_LOGGED_ON;
}

PPC_FUNC_IMPL(XamUserAreUsersFriends);
PPC_FUNC(XamUserAreUsersFriends)
{
    uint32_t userIndex = ctx.r3.u32;
    uint32_t count = ctx.r5.u32;

    // Stub: no friends
    fprintf(stderr, "[HOST.XamUserAreUsersFriends] userIndex=%u count=%u -> no friends (stub)\n", userIndex, count);
    fflush(stderr);

    ctx.r3.u32 = ERROR_SUCCESS;
}

PPC_FUNC_IMPL(XamUserCreateStatsEnumerator);
PPC_FUNC(XamUserCreateStatsEnumerator)
{
    uint32_t titleId = ctx.r3.u32;
    uint32_t userIndex = ctx.r4.u32;

    // Stub: return empty enumerator
    fprintf(stderr, "[HOST.XamUserCreateStatsEnumerator] titleId=%08X userIndex=%u -> stub\n", titleId, userIndex);
    fflush(stderr);

    ctx.r3.u32 = ERROR_SUCCESS;
}

PPC_FUNC_IMPL(XamUserCreateAchievementEnumerator);
PPC_FUNC(XamUserCreateAchievementEnumerator)
{
    uint32_t titleId = ctx.r3.u32;
    uint32_t userIndex = ctx.r4.u32;

    // Stub: return empty enumerator
    fprintf(stderr, "[HOST.XamUserCreateAchievementEnumerator] titleId=%08X userIndex=%u -> stub\n", titleId, userIndex);
    fflush(stderr);

    ctx.r3.u32 = ERROR_SUCCESS;
}

PPC_FUNC_IMPL(XamUserCreatePlayerEnumerator);
PPC_FUNC(XamUserCreatePlayerEnumerator)
{
    uint32_t userIndex = ctx.r3.u32;

    // Stub: return empty enumerator
    fprintf(stderr, "[HOST.XamUserCreatePlayerEnumerator] userIndex=%u -> stub\n", userIndex);
    fflush(stderr);

    ctx.r3.u32 = ERROR_SUCCESS;
}
