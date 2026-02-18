using System;
using System.Runtime.InteropServices;

namespace NRE.TestPayload
{
    /// <summary>
    /// Test payload: displays "Success!" in a MessageBox after the stub runs all bypasses and loads this assembly.
    /// </summary>
    class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        private const uint MB_OK = 0x00000000;
        private const uint MB_ICONINFORMATION = 0x00000040;
        private const uint MB_TOPMOST = 0x00040000;

        static void Main(string[] args)
        {
            MessageBoxW(IntPtr.Zero, "Success! Payload ran in memory.", "NRE Test Payload", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
        }
    }
}
