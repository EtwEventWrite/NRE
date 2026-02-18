/*
 * Native test payload: shows a MessageBox so you can verify the stub
 * loads and runs a native PE in memory. Build with build.bat or:
 *   cl /nologo /O2 main.c /Fe:NRE.NativeTestPayload.exe user32.lib
 */
#include <windows.h>

#pragma comment(lib, "user32.lib")

int main(void)
{
    MessageBoxW(NULL,
        L"Success! Native payload ran in memory.",
        L"NRE Native Test Payload",
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
    return 0;
}
