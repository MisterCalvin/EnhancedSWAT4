#include "stdafx.h"
#include "common.hpp"
#include "feature.hpp"

// When a package is found in the download cache, appFindPackageFile refreshes the file's
// timestamp by opening it for writing. That fails while the package is loaded, and the file
// manager answers a failed write with a "Failed to write" message box. Rejoining a server
// that is running a downloaded map, as happens whenever the server reloads it, raises the
// box on every lookup and the client never gets past "Connecting".
//
// A package that is in use does not need its timestamp refreshed, so the failure is harmless
// and only the message box has to go.
namespace
{
    SafetyHookInline shUpdateFileModTime{};

    int* suppressWriteErrorMessage{};

    int __cdecl UpdateFileModTime(wchar_t* filename)
    {
        auto previous = *suppressWriteErrorMessage;
        *suppressWriteErrorMessage = 1;

        auto result = shUpdateFileModTime.ccall<int>(filename);

        *suppressWriteErrorMessage = previous;
        return result;
    }
}

FEATURE(Core, CacheWriteError)
{
    auto core = GetModuleHandleW(L"Core");

    auto updateFileModTime = GetProcAddress(core, "?appUpdateFileModTime@@YAHPAG@Z");
    suppressWriteErrorMessage = reinterpret_cast<int*>(GetProcAddress(core, "?GSuppressWriteErrorMessage@@3HA"));

    if (!updateFileModTime || !suppressWriteErrorMessage)
    {
        spdlog::error("CacheWriteError: appUpdateFileModTime or GSuppressWriteErrorMessage not found");
        return;
    }

    shUpdateFileModTime = safetyhook::create_inline(updateFileModTime, UpdateFileModTime);
    spdlog::info("CacheWriteError: Downloaded packages in use no longer raise a write error");
}
