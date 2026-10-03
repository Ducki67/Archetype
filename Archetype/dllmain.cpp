#include "pch.h"
#include "iat_entries.h"
#include <cstdio>
#include <cstdarg>
#include <string>

static FILE* g_LogFile = nullptr;
static volatile LONG g_DepSkips = 0;
static volatile LONG g_AvSkips = 0;
static uintptr_t g_ImageBase = 0;
static uintptr_t g_ImageEnd = 0;
static void* g_NullSink = nullptr;

static void Log(const char* fmt, ...)
{
    if (!g_LogFile) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(g_LogFile, fmt, args);
    va_end(args);
    fflush(g_LogFile);
}

static LONG CALLBACK ArchetypeVEH(PEXCEPTION_POINTERS ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    auto info = ep->ExceptionRecord->ExceptionInformation;
    auto ctx = ep->ContextRecord;

    if (code != EXCEPTION_ACCESS_VIOLATION)
    {
        Log("non-AV 0x%08X RIP=0x%llX\n", code, ctx->Rip);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    
    if (info[0] == 8)
    {
        if (InterlockedIncrement(&g_DepSkips) > 50000)
        {
            Log("DEP LIMIT RIP=0x%llX target=0x%llX\n", ctx->Rip, info[1]);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        DWORD64 retAddr = *reinterpret_cast<DWORD64*>(ctx->Rsp);
        Log("DEP #%ld target=0x%llX ret=0x%llX\n", g_DepSkips, info[1], retAddr);
        ctx->Rip = retAddr;
        ctx->Rsp += 8;
        ctx->Rax = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

        if (ctx->Rip >= g_ImageBase && ctx->Rip < g_ImageEnd)
    {
        if (InterlockedIncrement(&g_AvSkips) > 50000)
        {
            Log("AV LIMIT RVA=0x%llX type=%lld fault=0x%llX\n",
                ctx->Rip - g_ImageBase, info[0], info[1]);
            return EXCEPTION_CONTINUE_SEARCH;
        }

                if (info[1] >= 0x10000 && info[1] <= 0x7FFFFFFFFFFF)
        {
            DWORD64 faultPage = info[1] & ~(DWORD64)0xFFF;
            void* alloc = VirtualAlloc((void*)faultPage, 0x1000,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!alloc)
                alloc = VirtualAlloc((void*)faultPage, 0x1000,
                    MEM_COMMIT, PAGE_READWRITE);
            if (alloc)
            {
                Log("AV #%ld ALLOC 0x%llX RVA=0x%llX type=%lld fault=0x%llX\n",
                    g_AvSkips, faultPage, ctx->Rip - g_ImageBase, info[0], info[1]);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

                if (info[1] < 0x10000)
        {
            Log("AV #%ld NULLSKIP RVA=0x%llX type=%lld fault=0x%llX\n",
                g_AvSkips, ctx->Rip - g_ImageBase, info[0], info[1]);
            goto do_unwind;
        }

        // Alloc failed, address allocatable but VirtualAlloc denied — redirect bad registers to null sink
        if (g_NullSink)
        {
            DWORD64 sink = (DWORD64)g_NullSink;
            DWORD64* regs[] = {
                &ctx->Rax, &ctx->Rbx, &ctx->Rcx, &ctx->Rdx,
                &ctx->Rsi, &ctx->Rdi, &ctx->R8, &ctx->R9,
                &ctx->R10, &ctx->R11, &ctx->R12, &ctx->R13,
                &ctx->R14, &ctx->R15, &ctx->Rbp
            };
            int fixed = 0;
            for (auto reg : regs)
            {
                if (*reg < 0x10000 || *reg > 0x7FFFFFFFFFFF)
                {
                    *reg = sink;
                    fixed++;
                }
            }
            if (fixed > 0)
            {
                Log("AV #%ld SINK RVA=0x%llX type=%lld fault=0x%llX regs=%d\n",
                    g_AvSkips, ctx->Rip - g_ImageBase, info[0], info[1], fixed);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        
        do_unwind:
        DWORD64 faultRip = ctx->Rip;
        DWORD64 imageBase = 0;
        auto funcEntry = RtlLookupFunctionEntry(ctx->Rip, &imageBase, NULL);
        if (funcEntry)
        {
            PVOID handlerData = nullptr;
            DWORD64 frame = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, ctx->Rip,
                funcEntry, ctx, &handlerData, &frame, NULL);
            ctx->Rax = 0;
        }
        else
        {
            ctx->Rip = *reinterpret_cast<DWORD64*>(ctx->Rsp);
            ctx->Rsp += 8;
            ctx->Rax = 0;
        }

        Log("AV #%ld SKIP RVA=0x%llX type=%lld fault=0x%llX -> RIP=0x%llX\n",
            g_AvSkips, faultRip - g_ImageBase, info[0], info[1], ctx->Rip);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    Log("AV pass RIP=0x%llX type=%lld fault=0x%llX\n",
        ctx->Rip, info[0], info[1]);
    return EXCEPTION_CONTINUE_SEARCH;
}


extern "C" __declspec(dllexport) void run()
{
}

static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER f) { return NULL; }

static BOOL WINAPI Hook_IsDebuggerPresent() { return FALSE; }


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {

#ifdef _DEBUG
        AllocConsole();

        std::string DateTime = std::string(__DATE__) + " " + __TIME__;

        FILE* fptr;
        freopen_s(&fptr, "CONOUT$", "w+", stdout);
        SetConsoleTitleA("Archetype - DLL Built on: " __DATE__ " " __TIME__);


        std::cout << R"(
                   _          _
    /\            | |        | |
   /  \   _ __ ___| |__   ___| |_ _   _ _ __   ___
  / /\ \ | '__/ __| '_ \ / _ \ __| | | | '_ \ / _ \
 / ____ \| | | (__| | | |  __/ |_| |_| | |_) |  __/
/_/    \_\_|  \___|_| |_|\___|\__|\__, | .__/ \___|
                                   __/ | |
                                  |___/|_|
======================================================
*> Archetype - Made by Ducki67 (@ducki67 on discord)
*> Info: Byfron/Hyperion bypass for 21.20 - 22.20 versions.

)" << "\n";
        std::cout << "Dll built on: ", DateTime + "\n\n";
        std::cout << "\n\n";

        //Sleep(20000);
#endif

        fopen_s(&g_LogFile, "archetype_debug.log", "w");

        auto ImageBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));

        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(ImageBase + dos->e_lfanew);

        g_ImageBase = ImageBase;
        g_ImageEnd = ImageBase + nt->OptionalHeader.SizeOfImage;
        g_NullSink = VirtualAlloc((void*)0x200000000ULL, 0x10000,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_NullSink)
            g_NullSink = VirtualAlloc(NULL, 0x10000,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        AddVectoredExceptionHandler(1, ArchetypeVEH);

        Log("Archetype loaded base=0x%llX end=0x%llX size=0x%X sink=0x%llX\n",
            g_ImageBase, g_ImageEnd, nt->OptionalHeader.SizeOfImage,
            (DWORD64)g_NullSink);

        DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;

#if AUTO_VERSION
        const VersionConfig* config = nullptr;
        for (size_t v = 0; v < SUPPORTED_VERSION_COUNT; v++)
        {
            if (SUPPORTED_VERSIONS[v].entry_rva == entryRVA)
            {
                config = &SUPPORTED_VERSIONS[v];
                break;
            }
        }
        if (!config)
            return TRUE;

#ifdef AUTO_VERSION && NDEBUG
#pragma message(__FILE__ "(" _CRT_STRINGIZE(__LINE__) "): warning: Archetype [AUTO_VERSION] define is enabled. This feature is EXPERIMENTAL and may not work perfectly for the time being!")

#endif

#else
        const char* targetVersion =
        #if V21_20
            "21.20";
        #elif V21_30
            "21.30";
        #elif V21_40
            "21.40";
        #elif V21_50
            "21.50";
        #elif V21_51
            "21.51";
        #elif V22_00
            "22.00";
        #elif V22_10
            "22.10";
        #elif V22_20
            "22.20";
        #else+-
            #error "No version defined! Set V21_20 - V22_20 to "true" or AUTO_VERSION in pch.h"
        #endif

        const VersionConfig* config = nullptr;
        for (size_t v = 0; v < SUPPORTED_VERSION_COUNT; v++)
        {
            if (strcmp(SUPPORTED_VERSIONS[v].name, targetVersion) == 0)
            {
                config = &SUPPORTED_VERSIONS[v];
                break;
            }
        }
        if (!config)
            return TRUE;
#endif

        Log("version=%s entries=%zu entryRVA=0x%X\n",
            config->name, config->count, entryRVA);

        for (size_t i = 0; i < config->count; i++)
        {
            const auto& Import = config->entries[i];
            DWORD og;
            VirtualProtect(reinterpret_cast<FARPROC*>(ImageBase + Import.Offset), 8, PAGE_READWRITE, &og);

            HMODULE hMod = LoadLibraryExA(Import.DllName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!hMod)
                hMod = LoadLibraryA(Import.DllName);

            auto addr = GetProcAddress(hMod, Import.ExportName);

            if (strcmp(Import.ExportName, "SetUnhandledExceptionFilter") == 0)
                addr = (FARPROC)&Hook_SetUnhandledExceptionFilter;
            else if (strcmp(Import.ExportName, "IsDebuggerPresent") == 0)
                addr = (FARPROC)&Hook_IsDebuggerPresent;

            *reinterpret_cast<FARPROC*>(ImageBase + Import.Offset) = addr;
            VirtualProtect(reinterpret_cast<FARPROC*>(ImageBase + Import.Offset), 8, og, &og);
        }

        Log("IAT filled %zu entries\n", config->count);
        break;
    }
    case DLL_THREAD_ATTACH:
    {

        break;
    }
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        if (g_LogFile) fclose(g_LogFile);
        break;
    }
    return TRUE;
}
