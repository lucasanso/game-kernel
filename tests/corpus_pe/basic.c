/* Benign test program for the PE parser corpus. It is compiled, never executed, by the tests. */
#include <windows.h>
#include <stdio.h>

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved) {
    (void)module; (void)reason; (void)reserved;
}
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK gk_tls_callback = tls_callback;
#else
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK gk_tls_callback = tls_callback;
#endif

int main(int argc, char **argv) {
    (void)argv;
    DWORD ticks = GetTickCount();
    HANDLE h = CreateFileA("gk-corpus.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (argc > 5) MessageBoxA(NULL, "Game Kernel corpus", "corpus", MB_OK);
    printf("%lu\n", (unsigned long)ticks);
    return 0;
}
