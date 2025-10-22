#pragma once
#include <filesystem>
#include <string_view>
#include <xbox.h>

struct FileSystem {
    static std::filesystem::path ResolvePath(const std::string_view& path, bool checkForMods);
};

// Forward decls so we can declare the I/O functions here:
struct FileHandle;
// struct XOVERLAPPED;
template<typename T> struct be;

uint32_t XReadFile
(
    FileHandle* hFile,
    void* lpBuffer,
    uint32_t nNumberOfBytesToRead,
    be<uint32_t>* lpNumberOfBytesRead,
    XOVERLAPPED* lpOverlapped
);
uint32_t XWriteFile
(
    FileHandle* hFile, 
    const void* lpBuffer, 
    uint32_t nNumberOfBytesToWrite, 
    be<uint32_t>* lpNumberOfBytesWritten, 
    void* lpOverlapped
);
FileHandle* XCreateFileA
(
    const char* lpFileName,
    uint32_t dwDesiredAccess,
    uint32_t dwShareMode,
    void* lpSecurityAttributes,
    uint32_t dwCreationDisposition,
    uint32_t dwFlagsAndAttributes
);

// Register file system hooks (must be called after g_memory is initialized)
void RegisterFileSystemHooks();
