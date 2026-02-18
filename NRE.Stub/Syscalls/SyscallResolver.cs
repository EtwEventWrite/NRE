using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Syscalls
{
    /// <summary>
    /// Resolves syscall numbers from ntdll by reading the native stub (x64: mov r10, rcx; mov eax, num).
    /// </summary>
    public static class SyscallResolver
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static uint GetSyscallNumber(string functionName)
        {
            IntPtr ntdll = LoadLibrary("ntdll.dll");
            if (ntdll == IntPtr.Zero) return 0;
            IntPtr addr = GetProcAddress(ntdll, functionName);
            if (addr == IntPtr.Zero) return 0;
            return (uint)Marshal.ReadInt32(addr, 4);
        }
    }
}
