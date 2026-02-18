using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// Anti-debug checks: IsDebuggerPresent, NtQueryInformationProcess (DebugPort).
    /// </summary>
    public static class AntiDebug
    {
        [DllImport("kernel32.dll")]
        private static extern int IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        public static bool IsDebugged()
        {
            if (IsDebuggerPresent() != 0)
                return true;
            if (CheckRemoteDebuggerPresent())
                return true;
            return false;
        }

        private static bool CheckRemoteDebuggerPresent()
        {
            var hProcess = GetCurrentProcess();
            bool present = false;
            return CheckRemoteDebuggerPresent(hProcess, ref present) && present;
        }
    }
}
