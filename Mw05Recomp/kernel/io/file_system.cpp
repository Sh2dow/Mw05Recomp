#include "file_system.h"
#include <cpu/guest_thread.h>
#include <kernel/xam.h>
#include <kernel/xdm.h>
#include <kernel/function.h>
#if MW05_ENABLE_UNLEASHED
#include <mod/mod_loader.h>
#endif
#include <os/logger.h>
#include <cctype>
#include <cstdlib>
#include <kernel/trace.h>
#include <user/config.h>
#include <stdafx.h>
#include <atomic>

uint32_t NtCreateFile(be<uint32_t>* FileHandle, uint32_t DesiredAccess, XOBJECT_ATTRIBUTES* Attributes, XIO_STATUS_BLOCK* IoStatusBlock, uint64_t* AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions);
uint32_t NtOpenFile(be<uint32_t>* FileHandle, uint32_t DesiredAccess, XOBJECT_ATTRIBUTES* Attributes, XIO_STATUS_BLOCK* IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions);
uint32_t NtClose(uint32_t handle);
uint32_t NtReadFile(uint32_t handleId, uint32_t Event, uint32_t ApcRoutine, uint32_t ApcContext, XIO_STATUS_BLOCK* IoStatusBlock, void* Buffer, uint32_t Length, be<int64_t>* ByteOffset, be<uint32_t>* Key);
uint32_t NtWriteFile(uint32_t handleId, uint32_t Event, uint32_t ApcRoutine, uint32_t ApcContext, XIO_STATUS_BLOCK* IoStatusBlock, const void* Buffer, uint32_t Length, be<int64_t>* ByteOffset, be<uint32_t>* Key);
static std::atomic<int> g_fileTraceEnabled{-1};
static std::atomic<int> g_fileTraceAnnounced{0};
static bool FileTraceEnabled()
{
    auto toLower = [](unsigned char c) { return static_cast<char>(std::tolower(c)); };
    auto equalsIgnoreCase = [&](const char* lhs, const char* rhs) {
        while (*lhs && *rhs) {
            if (toLower(*lhs++) != toLower(*rhs++)) {
                return false;
            }
        }
        return *lhs == 0 && *rhs == 0;
    };

    int s = g_fileTraceEnabled.load(std::memory_order_relaxed);
    if (s < 0) {
        const char* envValue = std::getenv("MW05_FILE_LOG");
        const bool sawEnv = envValue != nullptr;
        int enabled = 0;
        if (envValue) {
            if (!(envValue[0] == '0' && envValue[1] == '\0') && !equalsIgnoreCase(envValue, "false") && !equalsIgnoreCase(envValue, "off") && !equalsIgnoreCase(envValue, "no")) {
                enabled = 1;
            }
        }
        s = enabled;
        g_fileTraceEnabled.store(s, std::memory_order_relaxed);
        if (sawEnv) {
            const int state = enabled ? 1 : 2;
            if (g_fileTraceAnnounced.exchange(state, std::memory_order_relaxed) != state) {
                KernelTraceHostOpF("HOST.FileSystem.trace %s env=MW05_FILE_LOG value=\"%s\"",
                    enabled ? "enabled" : "disabled", envValue ? envValue : "<null>");
            }
        }
    }
    return s != 0;
}

static const bool g_fileTraceInit = []() noexcept {
    (void)FileTraceEnabled();
    return true;
}();

struct FileHandle : KernelObject
{
    std::fstream stream;
    std::filesystem::path path;
    std::string guestPath;
};

struct FindHandle : KernelObject
{
    std::error_code ec;
    ankerl::unordered_dense::map<std::u8string, std::pair<size_t, bool>> searchResult; // Relative path, file size, is directory
    decltype(searchResult)::iterator iterator;

    FindHandle(const std::string_view& path)
    {
        auto addDirectory = [&](const std::filesystem::path& directory)
            {
                for (auto& entry : std::filesystem::directory_iterator(directory, ec))
                {
                    std::u8string relativePath = entry.path().lexically_relative(directory).u8string();
                    searchResult.emplace(relativePath, std::make_pair(entry.is_directory(ec) ? 0 : entry.file_size(ec), entry.is_directory(ec)));
                }
            };

        std::string_view pathNoPrefix = path;
        size_t index = pathNoPrefix.find(":\\");
        if (index != std::string_view::npos)
            pathNoPrefix.remove_prefix(index + 2);

        // Force add a work folder to let the game see the files in mods,
        // if by some rare chance the user has no DLC or update files.
        if (pathNoPrefix.empty())
            searchResult.emplace(u8"work", std::make_pair(0, true));

        // Look for only work folder in mod folders, AR files cause issues.
        if (pathNoPrefix.starts_with("work"))
        {
            std::string pathStr(pathNoPrefix);
            std::replace(pathStr.begin(), pathStr.end(), '\\', '/');

            for (size_t i = 0; ; i++)
            {
            #if MW05_ENABLE_UNLEASHED
                auto* includeDirs = ModLoader::GetIncludeDirectories(i);
                if (includeDirs == nullptr)
                    break;

                for (auto& includeDir : *includeDirs)
                    addDirectory(includeDir / pathStr);
            #else
                (void)i; // mods disabled
                break;
            #endif
            }
        }

        addDirectory(FileSystem::ResolvePath(path, false));

        iterator = searchResult.begin();
    }

    void fillFindData(WIN32_FIND_DATAA* lpFindFileData)
    {
        if (iterator->second.second)
            lpFindFileData->dwFileAttributes = ByteSwap(FILE_ATTRIBUTE_DIRECTORY);
        else
            lpFindFileData->dwFileAttributes = ByteSwap(FILE_ATTRIBUTE_NORMAL);

        strncpy(lpFindFileData->cFileName, (const char *)(iterator->first.c_str()), sizeof(lpFindFileData->cFileName));
        lpFindFileData->nFileSizeLow = ByteSwap(uint32_t(iterator->second.first >> 32U));
        lpFindFileData->nFileSizeHigh = ByteSwap(uint32_t(iterator->second.first));
        lpFindFileData->ftCreationTime = {};
        lpFindFileData->ftLastAccessTime = {};
        lpFindFileData->ftLastWriteTime = {};
    }
};

namespace
{
    void SetInvalidHandleError()
    {
#ifdef _WIN32
        GuestThread::SetLastError(ERROR_INVALID_HANDLE);
#else
        GuestThread::SetLastError(6); // ERROR_INVALID_HANDLE
#endif
    }

    bool EnsureLiveFileHandle(FileHandle* handle)
    {
        if (!IsKernelObjectAlive(handle))
        {
            SetInvalidHandleError();
            return false;
        }

        if (!handle->stream.is_open())
        {
            SetInvalidHandleError();
            return false;
        }

        return true;
    }

    bool EnsureLiveFindHandle(FindHandle* handle)
    {
        if (!IsKernelObjectAlive(handle))
        {
            SetInvalidHandleError();
            return false;
        }

        return true;
    }
}

FileHandle* XCreateFileA
(
    const char* lpFileName,
    uint32_t dwDesiredAccess,
    uint32_t dwShareMode,
    void* lpSecurityAttributes,
    uint32_t dwCreationDisposition,
    uint32_t dwFlagsAndAttributes
)
{
    if (FileTraceEnabled()) {
        KernelTraceHostOpF("HOST.FileSystem.XCreateFileA.enter guest=\"%s\"", lpFileName ? lpFileName : "<null>");
    }

    assert(((dwDesiredAccess & ~(GENERIC_READ | GENERIC_WRITE | FILE_READ_DATA)) == 0) && "Unknown desired access bits.");
    assert(((dwShareMode & ~(FILE_SHARE_READ | FILE_SHARE_WRITE)) == 0) && "Unknown share mode bits.");
    assert(((dwCreationDisposition & ~(CREATE_NEW | CREATE_ALWAYS | OPEN_ALWAYS | OPEN_EXISTING | TRUNCATE_EXISTING)) == 0) && "Unknown creation disposition bits.");

    std::filesystem::path filePath = FileSystem::ResolvePath(lpFileName, true);

    // If this is a directory open (common for NtCreateFile with FILE_DIRECTORY_FILE),
    // don't try to open a stream; just succeed and return a handle that carries the path.
    const bool isDir = std::filesystem::is_directory(filePath);
    if (isDir) {
        if (FileTraceEnabled()) {
            auto hostPathU8 = filePath.u8string();
            std::string hostPath(hostPathU8.begin(), hostPathU8.end());
            KernelTraceHostOpF("HOST.FileSystem.ResolvePath.open.dir guest=\"%s\" host=\"%s\"", lpFileName ? lpFileName : "<null>", hostPath.c_str());
        }
        FileHandle* dirHandle = CreateKernelObject<FileHandle>();
        // Leave stream closed for directories; we never read/write them as files.
        dirHandle->path = std::move(filePath);
        dirHandle->guestPath = lpFileName ? lpFileName : "";
        return dirHandle;
    }

    std::fstream fileStream;
    std::ios::openmode fileOpenMode = std::ios::binary;
    if (dwDesiredAccess & (GENERIC_READ | FILE_READ_DATA))
    {
        fileOpenMode |= std::ios::in;
    }

    if (dwDesiredAccess & GENERIC_WRITE)
    {
        fileOpenMode |= std::ios::out;
    }

    fileStream.open(filePath, fileOpenMode);
    if (!fileStream.is_open())
    {
        if (FileTraceEnabled()) {
            auto hostPathU8 = filePath.u8string();
            std::string hostPath(hostPathU8.begin(), hostPathU8.end());
            KernelTraceHostOpF("HOST.FileSystem.ResolvePath.fail guest=\"%s\" host=\"%s\"", lpFileName ? lpFileName : "<null>", hostPath.c_str());
        }
#ifdef _WIN32
        GuestThread::SetLastError(GetLastError());
#endif
        return GetInvalidKernelObject<FileHandle>();
    }

    if (FileTraceEnabled()) {
        auto hostPathU8 = filePath.u8string();
        std::string hostPath(hostPathU8.begin(), hostPathU8.end());
        KernelTraceHostOpF("HOST.FileSystem.ResolvePath.open guest=\"%s\" host=\"%s\"", lpFileName ? lpFileName : "<null>", hostPath.c_str());
    }

    FileHandle *fileHandle = CreateKernelObject<FileHandle>();
    fileHandle->stream = std::move(fileStream);
    fileHandle->path = std::move(filePath);
    fileHandle->guestPath = lpFileName ? lpFileName : "";
    return fileHandle;
}

static uint32_t XGetFileSizeA(FileHandle* hFile, be<uint32_t>* lpFileSizeHigh)
{
    if (!EnsureLiveFileHandle(hFile))
    {
        if (lpFileSizeHigh != nullptr)
        {
            *lpFileSizeHigh = 0;
        }

        return INVALID_FILE_SIZE;
    }

    std::error_code ec;
    auto fileSize = std::filesystem::file_size(hFile->path, ec);
    if (!ec)
    {
        if (lpFileSizeHigh != nullptr)
        {
            *lpFileSizeHigh = uint32_t(fileSize >> 32U);
        }

        return static_cast<uint32_t>(fileSize);
    }

    GuestThread::SetLastError(ec.value());
    return INVALID_FILE_SIZE;
}

uint32_t XGetFileSizeExA(FileHandle* hFile, LARGE_INTEGER* lpFileSize)
{
    if (!EnsureLiveFileHandle(hFile))
    {
        if (lpFileSize != nullptr)
        {
            lpFileSize->QuadPart = 0;
        }

        return FALSE;
    }

    std::error_code ec;
    auto fileSize = std::filesystem::file_size(hFile->path, ec);
    if (!ec)
    {
        if (lpFileSize != nullptr)
        {
            lpFileSize->QuadPart = ByteSwap(fileSize);
        }

        return TRUE;
    }

    GuestThread::SetLastError(ec.value());
    return FALSE;
}

uint32_t XReadFile
(
    FileHandle* hFile,
    void* lpBuffer,
    uint32_t nNumberOfBytesToRead,
    be<uint32_t>* lpNumberOfBytesRead,
    XOVERLAPPED* lpOverlapped
)
{
    if (!EnsureLiveFileHandle(hFile))
    {
        if (lpNumberOfBytesRead != nullptr)
        {
            *lpNumberOfBytesRead = 0;
        }

        return FALSE;
    }

    uint32_t result = FALSE;
    if (lpOverlapped != nullptr)
    {
        std::streamoff streamOffset = lpOverlapped->Offset + (std::streamoff(lpOverlapped->OffsetHigh.get()) << 32U);
        hFile->stream.clear();
        hFile->stream.seekg(streamOffset, std::ios::beg);
        if (hFile->stream.bad())
        {
            return FALSE;
        }
    }

    uint32_t numberOfBytesRead;
    hFile->stream.read((char *)(lpBuffer), nNumberOfBytesToRead);
    if (!hFile->stream.bad())
    {
        numberOfBytesRead = uint32_t(hFile->stream.gcount());
        result = TRUE;
    }

    if (result)
    {
        if (lpOverlapped != nullptr)
        {
            lpOverlapped->Internal = 0;
            lpOverlapped->InternalHigh = numberOfBytesRead;
        }
        else if (lpNumberOfBytesRead != nullptr)
        {
            *lpNumberOfBytesRead = numberOfBytesRead;
        }
    }

    return result;
}

uint32_t XSetFilePointer(FileHandle* hFile, int32_t lDistanceToMove, be<int32_t>* lpDistanceToMoveHigh, uint32_t dwMoveMethod)
{
    if (!EnsureLiveFileHandle(hFile))
    {
        if (lpDistanceToMoveHigh != nullptr)
        {
            *lpDistanceToMoveHigh = 0;
        }

        return INVALID_SET_FILE_POINTER;
    }

    int32_t distanceToMoveHigh = lpDistanceToMoveHigh ? lpDistanceToMoveHigh->get() : 0;
    std::streamoff streamOffset = lDistanceToMove + (std::streamoff(distanceToMoveHigh) << 32U);
    std::fstream::seekdir streamSeekDir = {};
    switch (dwMoveMethod)
    {
    case FILE_BEGIN:
        streamSeekDir = std::ios::beg;
        break;
    case FILE_CURRENT:
        streamSeekDir = std::ios::cur;
        break;
    case FILE_END:
        streamSeekDir = std::ios::end;
        break;
    default:
        assert(false && "Unknown move method.");
        break;
    }

    hFile->stream.clear();
    hFile->stream.seekg(streamOffset, streamSeekDir);
    if (hFile->stream.bad())
    {
        return INVALID_SET_FILE_POINTER;
    }

    std::streampos streamPos = hFile->stream.tellg();
    if (lpDistanceToMoveHigh != nullptr)
        *lpDistanceToMoveHigh = int32_t(streamPos >> 32U);

    return uint32_t(streamPos);
}

uint32_t XSetFilePointerEx(FileHandle* hFile, int32_t lDistanceToMove, LARGE_INTEGER* lpNewFilePointer, uint32_t dwMoveMethod)
{
    if (!EnsureLiveFileHandle(hFile))
    {
        if (lpNewFilePointer != nullptr)
        {
            lpNewFilePointer->QuadPart = 0;
        }

        return FALSE;
    }

    std::fstream::seekdir streamSeekDir = {};
    switch (dwMoveMethod)
    {
    case FILE_BEGIN:
        streamSeekDir = std::ios::beg;
        break;
    case FILE_CURRENT:
        streamSeekDir = std::ios::cur;
        break;
    case FILE_END:
        streamSeekDir = std::ios::end;
        break;
    default:
        assert(false && "Unknown move method.");
        break;
    }

    hFile->stream.clear();
    hFile->stream.seekg(lDistanceToMove, streamSeekDir);
    if (hFile->stream.bad())
    {
        return FALSE;
    }

    if (lpNewFilePointer != nullptr)
    {
        lpNewFilePointer->QuadPart = ByteSwap(int64_t(hFile->stream.tellg()));
    }

    return TRUE;
}

FindHandle* XFindFirstFileA(const char* lpFileName, WIN32_FIND_DATAA* lpFindFileData)
{
    std::string_view path = lpFileName;
    if (path.find("\\*") == (path.size() - 2) || path.find("/*") == (path.size() - 2))
    {
        path.remove_suffix(1);
    }
    else if (path.find("\\*.*") == (path.size() - 4) || path.find("/*.*") == (path.size() - 4))
    {
        path.remove_suffix(3);
    }
    else
    {
        assert(!std::filesystem::path(path).has_extension() && "Unknown search pattern.");
    }

    FindHandle findHandle(path);

    if (findHandle.searchResult.empty())
        return GetInvalidKernelObject<FindHandle>();

    findHandle.fillFindData(lpFindFileData);

    return CreateKernelObject<FindHandle>(std::move(findHandle));
}

uint32_t XFindNextFileA(FindHandle* Handle, WIN32_FIND_DATAA* lpFindFileData)
{
    if (!EnsureLiveFindHandle(Handle))
    {
        return FALSE;
    }

    Handle->iterator++;

    if (Handle->iterator == Handle->searchResult.end())
    {
        return FALSE;
    }
    else
    {
        Handle->fillFindData(lpFindFileData);
        return TRUE;
    }
}

uint32_t XReadFileEx(FileHandle* hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, XOVERLAPPED* lpOverlapped, uint32_t lpCompletionRoutine)
{
    if (!EnsureLiveFileHandle(hFile))
    {
        return FALSE;
    }

    uint32_t result = FALSE;
    uint32_t numberOfBytesRead;
    std::streamoff streamOffset = lpOverlapped->Offset + (std::streamoff(lpOverlapped->OffsetHigh.get()) << 32U);
    hFile->stream.clear();
    hFile->stream.seekg(streamOffset, std::ios::beg);
    if (hFile->stream.bad())
        return FALSE;

    hFile->stream.read((char *)(lpBuffer), nNumberOfBytesToRead);
    if (!hFile->stream.bad())
    {
        numberOfBytesRead = uint32_t(hFile->stream.gcount());
        result = TRUE;
    }

    if (result)
    {
        lpOverlapped->Internal = 0;
        lpOverlapped->InternalHigh = numberOfBytesRead;
    }

    return result;
}

uint32_t XGetFileAttributesA(const char* lpFileName)
{
    std::filesystem::path filePath = FileSystem::ResolvePath(lpFileName, true);
    if (std::filesystem::is_directory(filePath))
        return FILE_ATTRIBUTE_DIRECTORY;
    else if (std::filesystem::is_regular_file(filePath))
        return FILE_ATTRIBUTE_NORMAL;
    else
        return INVALID_FILE_ATTRIBUTES;
}

uint32_t XWriteFile(FileHandle* hFile, const void* lpBuffer, uint32_t nNumberOfBytesToWrite, be<uint32_t>* lpNumberOfBytesWritten, void* lpOverlapped)
{
    if (!EnsureLiveFileHandle(hFile))
    {
        if (lpNumberOfBytesWritten != nullptr)
        {
            *lpNumberOfBytesWritten = 0;
        }

        return FALSE;
    }

    assert(lpOverlapped == nullptr && "Overlapped not implemented.");

    hFile->stream.write((const char *)(lpBuffer), nNumberOfBytesToWrite);
    if (hFile->stream.bad())
        return FALSE;

    if (lpNumberOfBytesWritten != nullptr)
        *lpNumberOfBytesWritten = uint32_t(hFile->stream.gcount());

    return TRUE;
}


std::filesystem::path FileSystem::ResolvePath(const std::string_view& path, bool checkForMods)
{
    if (checkForMods)
    {
#if MW05_ENABLE_UNLEASHED
        std::filesystem::path resolvedPath = ModLoader::ResolvePath(path);
        if (!resolvedPath.empty())
        {
            if (FileTraceEnabled()) {
                auto hostU8 = resolvedPath.u8string();
                std::string hostPath(hostU8.begin(), hostU8.end());
                std::string guestPath(path);
                KernelTraceHostOpF("HOST.FileSystem.ResolvePath.map guest=\"%s\" host=\"%s\" source=mod", guestPath.c_str(), hostPath.c_str());
            }
            if (ModLoader::s_isLogTypeConsole)
                LOGF_IMPL(Utility, "Mod Loader", "Loading file: \"{}\"", reinterpret_cast<const char*>(resolvedPath.u8string().c_str()));
            return resolvedPath;
        }
#endif
    }

    thread_local std::string builtPath;
    builtPath.clear();

    // Special-case: MW05 FS service requests for ZDIR (e.g., "FS\\ZD", "FS\\ZDBIN").
    // These are service tokens, not real subfolders; locate an actual ZDIR file under the game root.
    {
        auto starts_with_ci = [](std::string_view s, std::string_view p){
            if (s.size() < p.size()) return false;
            for (size_t i = 0; i < p.size(); ++i) {
                char a = (char)std::tolower((unsigned char)s[i]);
                char b = (char)std::tolower((unsigned char)p[i]);
                if (a != b) return false;
            }
            return true;
        };
        if (starts_with_ci(path, "FS\\")) {
            std::string_view rest = path.substr(3);
            if (starts_with_ci(rest, "ZD")) {
                static std::string s_cachedZdir;
                if (s_cachedZdir.empty()) {
                    const std::string gameRoot = std::string(XamGetRootPath("game"));
                    if (!gameRoot.empty()) {
                        const char* candidates[] = {
                            "/ZDIR.BIN", "/ZDIR.bin", "/ZDIR", "/GLOBAL/ZDIR.BIN", "/GLOBAL/ZDIR.bin", "/GLOBAL/ZDIR"
                        };
                        for (const char* c : candidates) {
                            std::string tryPath = gameRoot; tryPath += c;
                            if (std::filesystem::exists(tryPath)) { s_cachedZdir = std::move(tryPath); break; }
                        }
                        if (s_cachedZdir.empty()) {
                            std::error_code ec;
                            for (auto it = std::filesystem::recursive_directory_iterator(gameRoot, ec);
                                 !ec && it != std::filesystem::recursive_directory_iterator(); ++it) {
                                if (!it->is_regular_file(ec)) continue;
                                auto name = it->path().filename().string();
                                if (name.size() >= 4) {
                                    bool zdir = (std::tolower((unsigned char)name[0])=='z' &&
                                                 std::tolower((unsigned char)name[1])=='d' &&
                                                 std::tolower((unsigned char)name[2])=='i' &&
                                                 std::tolower((unsigned char)name[3])=='r');
                                    if (zdir) { s_cachedZdir = it->path().string(); break; }
                                }
                            }
                        }
                    }
                }
                if (!s_cachedZdir.empty()) {
                    if (FileTraceEnabled()) {
                        KernelTraceHostOpF("HOST.FileSystem.ResolvePath.fs_zdir.map guest=\"%s\" host=\"%s\"", std::string(path).c_str(), s_cachedZdir.c_str());
                    }
                    return std::u8string_view((const char8_t*)s_cachedZdir.c_str());
                }
            }
        }
    }

    size_t index = path.find(":\\");
    if (index != std::string::npos)
    {
        // rooted folder, handle direction
        std::string_view root = path.substr(0, index);

        // HACK: The game tries to load work folder from the "game" root path for
        // Application and shader archives, which does not work in Recomp because
        // we don't support stacking the update and game files on top of each other.
        //
        // We can fix it by redirecting it to update instead as we know the original
        // game files don't have a work folder.
        if (path.starts_with("game:\\work\\"))
            root = "update";

        const auto newRoot = XamGetRootPath(root);

        if (!newRoot.empty())
        {
            builtPath += newRoot;
            builtPath += '/';
        }

        builtPath += path.substr(index + 2);
    }
    else
    {
        // Treat leading backslash paths (e.g. "\GLOBAL") as rooted under the default game mount,
        // mirroring the canonicalization used for NT-style kernel paths in imports.cpp.
        if (!path.empty() && (path.front() == '\\' || path.front() == '/'))
        {
            const auto newRoot = XamGetRootPath("game");
            if (!newRoot.empty())
            {
                builtPath += newRoot;
    // Special-case: MW05 FS service requests for ZDIR (e.g., "FS\\ZD", "FS\\ZDBIN").
    // These are service tokens, not real subfolders; locate an actual ZDIR file under the game root.
    {
        auto starts_with_ci = [](std::string_view s, std::string_view p){
            if (s.size() < p.size()) return false;
            for (size_t i = 0; i < p.size(); ++i) {
                char a = (char)std::tolower((unsigned char)s[i]);
                char b = (char)std::tolower((unsigned char)p[i]);
                if (a != b) return false;
            }
            return true;
        };
        if (starts_with_ci(path, "FS\\")) {
            std::string_view rest = path.substr(3);
            if (starts_with_ci(rest, "ZD")) {
                static std::string s_cachedZdir;
                if (s_cachedZdir.empty()) {
                    const std::string gameRoot = std::string(XamGetRootPath("game"));
                    if (!gameRoot.empty()) {
                        const char* candidates[] = {
                            "/ZDIR.BIN", "/ZDIR.bin", "/ZDIR", "/GLOBAL/ZDIR.BIN", "/GLOBAL/ZDIR.bin", "/GLOBAL/ZDIR"
                        };
                        for (const char* c : candidates) {
                            std::string tryPath = gameRoot; tryPath += c;
                            if (std::filesystem::exists(tryPath)) { s_cachedZdir = std::move(tryPath); break; }
                        }
                        if (s_cachedZdir.empty()) {
                            std::error_code ec;
                            for (auto it = std::filesystem::recursive_directory_iterator(gameRoot, ec);
                                 !ec && it != std::filesystem::recursive_directory_iterator(); ++it) {
                                if (!it->is_regular_file(ec)) continue;
                                auto name = it->path().filename().string();
                                if (name.size() >= 4) {
                                    bool zdir = (std::tolower((unsigned char)name[0])=='z' &&
                                                 std::tolower((unsigned char)name[1])=='d' &&
                                                 std::tolower((unsigned char)name[2])=='i' &&
                                                 std::tolower((unsigned char)name[3])=='r');
                                    if (zdir) { s_cachedZdir = it->path().string(); break; }
                                }
                            }
                        }
                    }
                }
                if (!s_cachedZdir.empty()) {
                    if (FileTraceEnabled()) {
                        KernelTraceHostOpF("HOST.FileSystem.ResolvePath.fs_zdir.map guest=\"%s\" host=\"%s\"", std::string(path).c_str(), s_cachedZdir.c_str());
                    }
                    return std::u8string_view((const char8_t*)s_cachedZdir.c_str());
                }
            }
        }
    }

                builtPath += '/';
            }
            builtPath += path.substr(1);
        }
        else
        {
            // No device root and no leading slash — treat as relative to the game root.
            const auto newRoot = XamGetRootPath("game");
            if (!newRoot.empty())
            {
                builtPath += newRoot;
                builtPath += '/';
            }
            builtPath += path;
        }
    }

    std::replace(builtPath.begin(), builtPath.end(), '\\', '/');

    if (FileTraceEnabled()) {
        std::string guestPath(path);

        KernelTraceHostOpF("HOST.FileSystem.ResolvePath.map guest=\"%s\" host=\"%s\" source=default", guestPath.c_str(), builtPath.c_str());
    }

    return std::u8string_view((const char8_t*)builtPath.c_str());
}

#if 1
// Hook direct recompiled X* file APIs as well, regardless of Unleashed mode.
// Many titles call these directly rather than going through Nt* imports.
GUEST_FUNCTION_HOOK(sub_82BD4668, XCreateFileA);
GUEST_FUNCTION_HOOK(sub_82BD4600, XGetFileSizeA);
GUEST_FUNCTION_HOOK(sub_82BD5608, XGetFileSizeExA);
GUEST_FUNCTION_HOOK(sub_82BD4478, XReadFile);
GUEST_FUNCTION_HOOK(sub_831CD3E8, XSetFilePointer);
GUEST_FUNCTION_HOOK(sub_831CE888, XSetFilePointerEx);
GUEST_FUNCTION_HOOK(sub_831CDC58, XFindFirstFileA);
GUEST_FUNCTION_HOOK(sub_831CDC00, XFindNextFileA);
GUEST_FUNCTION_HOOK(sub_831CDF40, XReadFileEx);
GUEST_FUNCTION_HOOK(sub_831CD6E8, XGetFileAttributesA);
GUEST_FUNCTION_HOOK(sub_831CE3F8, XCreateFileA);
GUEST_FUNCTION_HOOK(sub_82BD4860, XWriteFile);
#endif

#if 1
GUEST_FUNCTION_HOOK(__imp__NtCreateFile, NtCreateFile);
GUEST_FUNCTION_HOOK(__imp__NtOpenFile, NtOpenFile);
GUEST_FUNCTION_HOOK(__imp__NtClose, NtClose);
GUEST_FUNCTION_HOOK(__imp__NtReadFile, NtReadFile);
GUEST_FUNCTION_HOOK(__imp__NtWriteFile, NtWriteFile);
#endif

// Register X* file API hooks (direct recompiled functions)
// Note: Nt* imports are automatically registered by ProcessImportTable()
static void RegisterFileSystemHooks() {
    KernelTraceHostOp("HOST.FileSystem.RegisterXFileHooks");

    // Register X* file API hooks at their known addresses
    if (&sub_82BD4668) g_memory.InsertFunction(0x82BD4668, sub_82BD4668); // XCreateFileA
    if (&sub_82BD4600) g_memory.InsertFunction(0x82BD4600, sub_82BD4600); // XGetFileSizeA
    if (&sub_82BD5608) g_memory.InsertFunction(0x82BD5608, sub_82BD5608); // XGetFileSizeExA
    if (&sub_82BD4478) g_memory.InsertFunction(0x82BD4478, sub_82BD4478); // XReadFile
    if (&sub_831CD3E8) g_memory.InsertFunction(0x831CD3E8, sub_831CD3E8); // XSetFilePointer
    if (&sub_831CE888) g_memory.InsertFunction(0x831CE888, sub_831CE888); // XSetFilePointerEx
    if (&sub_831CDC58) g_memory.InsertFunction(0x831CDC58, sub_831CDC58); // XFindFirstFileA
    if (&sub_831CDC00) g_memory.InsertFunction(0x831CDC00, sub_831CDC00); // XFindNextFileA
    if (&sub_831CDF40) g_memory.InsertFunction(0x831CDF40, sub_831CDF40); // XReadFileEx
    if (&sub_831CD6E8) g_memory.InsertFunction(0x831CD6E8, sub_831CD6E8); // XGetFileAttributesA
    if (&sub_831CE3F8) g_memory.InsertFunction(0x831CE3F8, sub_831CE3F8); // XCreateFileA (duplicate)
    if (&sub_82BD4860) g_memory.InsertFunction(0x82BD4860, sub_82BD4860); // XWriteFile

    KernelTraceHostOp("HOST.FileSystem.RegisterXFileHooks.done");
}

// Use static constructor to register hooks early
#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl file_system_hooks_ctor();
    __declspec(allocate(".CRT$XCU")) void (__cdecl*file_system_hooks_ctor_)(void) = file_system_hooks_ctor;
    static void __cdecl file_system_hooks_ctor() { RegisterFileSystemHooks(); }
#else
    __attribute__((constructor)) static void file_system_hooks_ctor() { RegisterFileSystemHooks(); }
#endif
