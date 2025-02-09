#include "api.h"

int is_debugger_present() {
    return IsDebuggerPresent();
}

void init_api_redirect() {
    HMODULE hModule = GetModuleHandle("msvcrt.dll");
    uint32_t seed = rand() ^ GetTickCount() ^ GetCurrentProcessId();
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *names = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfNames);
    WORD *ordinals = (WORD*)((DWORD_PTR)hModule + exportDir->AddressOfNameOrdinals);
    DWORD *functions = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfFunctions);
    
    uint32_t target_hash = compute_hash("printf", seed);
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *funcName = (char*)((DWORD_PTR)hModule + names[i]);
        if (compute_hash(funcName, seed) == target_hash) {
            api.real_printf = (void (*)(const char *, ...))((DWORD_PTR)hModule + functions[ordinals[i]]);
            break;
        }
    }
    
    if (!api.real_printf) exit(1);
    api.decoy1 = (void (*)(int))GetProcAddress(hModule, "exit");
    api.decoy2 = (void (*)(void*))GetProcAddress(hModule, "malloc");
}
