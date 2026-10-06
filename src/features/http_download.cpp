#include "stdafx.h"
#include "common.hpp"
#include "feature.hpp"

// Servers can point clients at a web server for content they are missing (RedirectToURL).
// Once UHTTPDownload::Tick reaches the file body it reads 1 KB from the socket, passes it to
// ReceiveData, which repaints the progress screen, and loops without ever returning. That is
// 1 KB per rendered frame, around 60 KB/s on any connection, and the game connection is not
// serviced until the file is done.
//
// Each tick now drains the socket, passes everything to ReceiveData once and returns, so the
// download runs at connection speed, the progress bar moves every frame and the server keeps
// hearing from the client.
namespace
{
    // Stops the drain from holding a frame for too long on a fast connection
    constexpr int32_t MaxBytesPerTick = 0x100000;

    // Offsets from the start of the body loop
    constexpr ptrdiff_t FetchDataCall = 10;     // E8 rel32
    constexpr ptrdiff_t Epilogue      = 0x7C;   // MOV ECX,[EBP-0C] / POP EDI / POP ESI

    // Short jumps back to the top of the loop, which leave the tick instead
    constexpr ptrdiff_t LoopJumps[]   = { 0x1F, 0x5A, 0x70 };

    // Redirect servers can work around the stock 1 KB per frame from their side, at a cost a
    // fixed client should not pay, so it needs to be distinguishable. Same length as the original.
    constexpr wchar_t StockUserAgent[] = L"User-Agent: Unreal";
    constexpr wchar_t FixedUserAgent[] = L"User-Agent: ESWAT4";

    // hook::module_pattern stops at the last executable section, and this lives in .rdata
    void* Find(HMODULE module, const void* data, size_t size)
    {
        auto address = reinterpret_cast<uint8_t*>(module);
        auto header  = reinterpret_cast<IMAGE_NT_HEADERS*>(address + reinterpret_cast<IMAGE_DOS_HEADER*>(module)->e_lfanew);

        for (auto end = address + header->OptionalHeader.SizeOfImage - size; address <= end; ++address)
            if (!memcmp(address, data, size))
                return address;

        return nullptr;
    }
}

FEATURE(IpDrv, HTTPDownload)
{
    auto ipDrv = GetModuleHandleW(L"IpDrv");

    // CMP [ESI+4D8],EDI / JNZ / MOV ECX,ESI / CALL FetchData / CMP EAX,EDI / JZ exit / MOV ECX,[ESI+4D8] / CMP ECX,EDI / JLE loop
    auto bodyLoop = hook::module_pattern(ipDrv,
        "39 BE D8 04 00 00 75 0F 8B CE E8 ? ? ? ? 3B C7 0F 84 ? ? ? ? 8B 8E D8 04 00 00 3B CF 7E DF");

    if (bodyLoop.empty())
    {
        // An IpDrv.dll patched on disk already drains the socket
        if (!hook::module_pattern(ipDrv, "81 BE D8 04 00 00 ? ? ? ? 7D 0B 8B CE E8 ? ? ? ? 85 C0 75 E9").empty())
            spdlog::info("HTTPDownload: IpDrv.dll is already patched");
        else
            spdlog::error("HTTPDownload: pattern not found (bodyLoop)");
        return;
    }

    auto loop = bodyLoop.get_first<uint8_t>(0);

    if (memcmp(loop + Epilogue, "\x8B\x4D\xF4\x5F\x5E", 5))
    {
        spdlog::error("HTTPDownload: function epilogue not found");
        return;
    }

    for (auto jump : LoopJumps)
    {
        if (loop[jump + 1] != static_cast<uint8_t>(-(jump + 2)))
        {
            spdlog::error("HTTPDownload: unexpected jump at {}", static_cast<void*>(loop + jump));
            return;
        }
    }

    // The call moves down four bytes, so its relative target does too
    auto fetchData = *reinterpret_cast<int32_t*>(loop + FetchDataCall + 1) - 4;

    // CMP [ESI+4D8],limit / JGE process / MOV ECX,ESI / CALL FetchData / TEST EAX,EAX / JNZ top
    uint8_t drain[] =
    {
        0x81, 0xBE, 0xD8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7D, 0x0B,
        0x8B, 0xCE,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x85, 0xC0,
        0x75, 0xE9,
    };
    memcpy(drain + 6, &MaxBytesPerTick, sizeof(MaxBytesPerTick));
    memcpy(drain + 15, &fetchData, sizeof(fetchData));

    injector::WriteMemoryRaw(loop, drain, sizeof(drain), true);

    for (auto jump : LoopJumps)
        injector::WriteMemory<uint8_t>(loop + jump + 1, static_cast<uint8_t>(Epilogue - (jump + 2)), true);

    auto size = sizeof(StockUserAgent) - sizeof(wchar_t);

    if (auto userAgent = Find(ipDrv, StockUserAgent, size))
        injector::WriteMemoryRaw(userAgent, const_cast<wchar_t*>(FixedUserAgent), size, true);
    else
        spdlog::warn("HTTPDownload: user agent not found");

    spdlog::info("HTTPDownload: Redirect downloads no longer limited to 1 KB per frame");
}
