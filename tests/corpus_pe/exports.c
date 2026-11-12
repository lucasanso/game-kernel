/* Benign DLL with named, ordinal-only and forwarded exports (forwarders come from exports.def). */
#include <windows.h>

__declspec(dllexport) int __cdecl gk_add(int a, int b) { return a + b; }
__declspec(dllexport) int __cdecl gk_mul(int a, int b) { return a * b; }
int __cdecl gk_hidden(int a) { return a ^ 0x5A; }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
