#include <Windows.h>
#include <thread>

using print_t = void(__cdecl*)(unsigned int, const char*, ...);

void printy()
{
    auto base = (uintptr_t)GetModuleHandleW(NULL);
    auto print = (print_t)(base + 0x1B09F20);

    int sec = 0;
    while (true)
    {
        print(0, "injected %d s", sec++);
        Sleep(1000);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        std::thread(printy).detach(); 
    }
    return TRUE;
}