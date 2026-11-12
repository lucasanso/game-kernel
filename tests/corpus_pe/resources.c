/* Benign program carrying resources (version info, manifest, embedded PE, high-entropy blob). */
#include <windows.h>
int WINAPI WinMain(HINSTANCE i, HINSTANCE p, LPSTR c, int s) {
    (void)p; (void)c; (void)s;
    HRSRC r = FindResourceA(i, MAKEINTRESOURCEA(100), MAKEINTRESOURCEA(10));
    return r != NULL;
}
